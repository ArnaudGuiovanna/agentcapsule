# Native streaming: provider streams, the harness's output stream and SSE events

Accepted on November 20, 2026. The product owner chose D-S1 through D-S6.
The streaming plan records delivery against these contracts. [Streaming plan](../plan-streaming.md).
References: EXT-005 and LLM-009 of the [product spec](../product.md) (§4),
LLM-02, EVT-01 and CAP-01 of the [roadmap](../../ROADMAP.md),
[ADR 011](011-llm-access-and-cost-budgets.md) (calls of unknown outcome),
[ADR 016](016-content-links-capabilities.md) (capabilities, transit
content), [ADR 003](003-restore-rpo.md) and
[ADR 017](017-capacity-queue-and-dead-letter-replay.md) (reruns and replays
under the same identifier), the model
[invocation_completion.qnt](../../spec/invocation_completion.qnt), the
[served API contract](../../openapi/openapi.yaml)
and the [guest platform channel](../guest/capsule-control.md).

## Context

An agent's text reaches its client in one piece, once the work is over, and
the client polls for it. Every hop reads a whole body, decodes it and writes
it again (lines of `321143b`):

| Hop | Code | What blocks a stream |
|---|---|---|
| Gateway → provider | `Gateway.once` reads the whole body (`internal/llmgateway/gateway.go:301`); `forwardFields` refuses `stream` and deletes `stream` and `stream_options` (`forward.go:109-113`) | No stream is ever asked of a provider; usage is read on the whole body (`forwardUsage`, `forward.go:148-177`) |
| Accounting | `LLMService.Call` → `admit` → `execute` → `settle` (`internal/controlplane/llm_service.go:89-174`) | Settlement assumes a whole answer |
| Host → guest | `platformHandler.ServeHTTP` writes one JSON object (`internal/capsuleprotocol/platform.go:121-380`); the server's write deadline is 35 s (`control.go:147`), pushed to 305 s for the two model routes only (`platform.go:145-151`) | No framed answer |
| Relay in the guest | `remotePlatform` calls `PlatformClient`, which reads the whole answer (`platform_local_linux.go:16-51`, `platform.go:430`); local server write deadline 20 s (`local_linux.go:67-97`) | The relay re-frames messages |
| Cost of a call | a new vsock and TLS connection per call (`DisableKeepAlives`, `control.go:308`; HTTP/1.1 only, `credentials.go:239`), a flock per accept (`internal/runtime/firecracker_platform_linux.go:55-94`), `Control` and a hold per call (`internal/worker/platform_linux.go:45-58`), the capability's SQL read (`RequireCapabilityFromVM`, `internal/controlplane/capabilities.go:79-95`) | One call per delta is too dear |
| Exclusive turn | `WithPreparedDelivery` holds the host barrier for the whole delivery (`internal/worker/control_linux.go:85-135`) | A harness can emit nothing before it answers `working` |
| Worker → API | PostgreSQL is the only bus; no `LISTEN` or `NOTIFY` anywhere in the repository; UNLOGGED tables are refused (`internal/controlplane/store.go:134-143`) | No way to push deltas to the API |
| API → client | a 10 s context per request (`internal/api/server.go:223`); read and write deadlines of 15 s (`cmd/agentcapsule-api/main.go:254`) | No SSE, no long answer |
| CLI | an HTTP client with a 30 s `Timeout` that reads whole bodies (`cmd/agentcapsule/http.go:51,139`) | No incremental read |
| capsule-adapter | `ModelEndpoint` replays the whole answer as SSE (`internal/agentadapter/model.go:33-354`); A2A streaming unsupported (`a2a.go:594-604`) | Streaming is only an SDK compatibility |
| Python SDK | `LLM_CALL_TIMEOUT = 130.0` (`sdk/python/agentcapsule_harness.py:59`), below the Go side's 300 and 310 s | Inconsistent |

Facts of the plan that the code contradicts or refines are listed in
[Facts checked](#facts-checked-against-the-code).

## Decision

### 1. The six decisions

| ID | Decision |
|---|---|
| D-S1 | Deltas go from the worker to the API as **sealed chunks in a PostgreSQL table, with a `NOTIFY` that carries only an identifier**. PostgreSQL stays the only bus; a restart of the API is caught up by `Last-Event-ID`; chunks are sealed and checked as results are; several workers per host work. No direct worker → API link, no polling-only table. |
| D-S2 | The platform channel's streams are **NDJSON**: one strict JSON object per line, `Content-Type: application/x-ndjson`. |
| D-S3 | A harness sends its output over **one long full-duplex call per stream**, not one call per batch. The call also carries the platform's control frames to the harness, among them the cancellation. |
| D-S4 | Chunks are kept **10 minutes after the invocation's outcome** (configurable), then deleted. They stay sealed, and are in the PostgreSQL backups for that short life. |
| D-S5 | The CLI prints JSON by default; **`--text`** on `invocation watch` and `agent invoke --watch` prints the deltas' text only, an exception to the JSON-only rule, documented as one. |
| D-S6 | The final result stays bounded at **32 KiB** for a completion. A stream may carry more text than that; the outcome does not change. File results stay EVT-04's. |

### 2. Rules every lot keeps

1. **Deltas are ephemeral and never an outcome.** Only the delivery's answer
   and `POST /v1/invocations/complete` make a result; both stay as they are,
   transactional and exactly once. A client that never subscribes sees what
   it sees in `v0.0.1`. A stream's close frame is not a completion.
2. **One long call per stream, never one call per delta.** Admission, the
   slot and the capability are checked once, at the opening; the stream then
   runs outside the admission lock. The output stream's chunks are each
   checked again in their own transaction (§5.6).
3. **Provider events are relayed untranslated** on `/v1/llm/forward/stream`:
   each event in its own dialect, as `forward` does today ("the body is the
   agent's").
4. **The rights to the stream are the rights to the result**, checked at the
   subscription and again during it (§6.3).
5. **No content in logs, metrics, traces or `NOTIFY` payloads.** A stored
   chunk is sealed as a result is: transit AEAD, bound to the operation, the
   attempt and the requester.
6. **The platform ignores business meaning.** It carries text and steps. A
   harness that must check an answer before showing it emits only steps
   until it has.

### 3. Gateway: provider streams (lot 1)

**Functions.** `internal/llmgateway` gains, in a new file `stream.go`:

```go
// Event is one provider event: its SSE event name (Anthropic) and its data,
// a JSON object, exactly as the provider sent them.
type Event struct {
	Name string          // "" for OpenAI, the `event:` field for Anthropic
	Data json.RawMessage // the `data:` field, a JSON object
}
// StreamResult is a finished stream's usage. FinishReason is set by
// CompleteStream only.
type StreamResult struct {
	Usage        Usage
	FinishReason string
}
func (g *Gateway) ForwardStream(ctx context.Context, route Route, dialect string, body []byte, sink func(Event) error) (StreamResult, error)
func (g *Gateway) CompleteStream(ctx context.Context, route Route, req Request, sink func(text string) error) (StreamResult, error)
```

The names of the arguments follow `Forward` and `Complete`; lot 1 may adapt
them to the existing signatures, not the behaviour below.

- **The request.** Both send `"stream": true`. For `openai_compatible` they
  also set `"stream_options": {"include_usage": true}`, replacing any
  `stream_options` of a forwarded body. `ForwardStream` accepts a body only
  with `"stream": true`; every other check of `forwardFields` stays (`n` > 1,
  output cap, Anthropic `max_tokens`, 960 KiB of request).
- **The parser.** An incremental SSE parser, in `stream.go`: a line is at
  most 64 KiB, an event's data (its lines joined) at most 60 KiB, so that its
  channel frame fits in 64 KiB (§4.2); past either, the stream is cut. Comment lines (`:`) and `retry:` are read and dropped. An
  event whose data is not a JSON object is a cut, except OpenAI's final
  `data: [DONE]`, which ends the stream and is not relayed.
- **What is relayed.** `ForwardStream` calls `sink` once per provider event,
  in order, Anthropic's `ping` included. `CompleteStream` calls `sink` with
  each text fragment: OpenAI `choices[0].delta.content`, Anthropic
  `content_block_delta` of type `text_delta`; other events are read for usage
  and not relayed. A `sink` error cancels the provider call: outcome unknown.
- **Usage**, as `forwardUsage` counts it today:
  - OpenAI: the last chunk's `usage` (`prompt_tokens`, `completion_tokens`),
    which `include_usage` asks for.
  - Anthropic: `message_start.message.usage` gives the input
    (`input_tokens + cache_creation_input_tokens + cache_read_input_tokens`)
    and a first output; each `message_delta.usage` replaces the output
    (`output_tokens`, cumulative), and replaces the input when it carries
    those fields. The stream must end with `message_stop`.
  - A stream that ends without its final usage (no OpenAI usage chunk before
    `[DONE]`, no `message_stop`) has an unknown outcome.
- **The first byte.** It is the provider's answer status and headers. Before
  it, retries are today's: a connection failure, a 429 or a 5xx, at most
  `MaxAttempts` (2) with the same backoff; a 3xx or another 4xx is
  `ErrRejected`. A 2xx whose `Content-Type` is not `text/event-stream` is a
  cut.
- **After the first byte, no retry.** A cut connection, an idle or total
  timeout, a stream past its size bound, a provider `error` event (Anthropic)
  or a stream without final usage is `ErrOutcomeUnknown` (package
  `llmgateway`, `gateway.go:85`). `LLMService` then calls `MarkLLMUnknown`
  (`internal/controlplane/llm_budgets.go:510`): the reservation keeps
  counting and the organization reconciles it (`llm_reconcile.go`,
  `GET /v1/llm/calls/unresolved`). The settlement path is unchanged:
  `settle` on success, `ReleaseLLM` on a refusal before the first byte.
- **Timeouts.** The fixed 140 s per attempt (`internal/worker/llm_linux.go:34`)
  does not apply to the stream functions. They have:
  - up to the first byte, 60 s per attempt (`llm.stream_first_byte_timeout`);
  - between two events, 60 s (`llm.stream_idle_timeout`); any complete event
    or comment line resets it;
  - in total, `capsuleprotocol.LLMCallTimeout` (300 s), the channel's bound.
- **Size.** The bytes read from one stream are bounded by `Config.MaxResponse`
  (4 MiB, `gateway.go:94`). Past it the stream is cut: outcome unknown.
- **Breaker.** Admission is today's (`admit`, one probe half-open). A success
  is recorded at the end of a stream with its usage; a cut, a timeout or a
  stream without usage is a failure; `ErrRejected` before the first byte
  counts as today (a success for the breaker, `gateway.go:266`). The breaker's
  key stays the route's (`tenant/alias` in practice, `llm_service.go:149`).
- **Trace.** The span `llm.call` gains the closed attribute
  `agentcapsule.llm.mode` (`unary`, `stream`), and `agentcapsule.outcome` the
  value `stream_cut` (a cut after the first byte, whose call's outcome is
  `outcome_unknown`). Nothing of an event goes into the span.
- **Metric.** `agentcapsule_llm_stream_first_event_seconds` (histogram, no
  label, buckets 0.1 to 60 s): from the provider request to its first event.
  `agentcapsule_llm_calls_total` counts streams as calls.

**Accounting.** `LLMService` gains `ForwardStreamFromVM` and
`CompleteStreamFromVM` beside `ForwardFromVM` and `CallFromVM`: the same
`admitFromVM` (identity, alias access, budgets, reservation, idempotency key),
then the gateway's stream function, then the same `settle` with
`context.WithoutCancel`. A replay of the request key behaves as today
(`admit`, `llm_service.go:123-127`): a reservation still `reserved` becomes
unknown and answers `outcome_unknown`; any other answers `conflict`
(`ErrLLMAlreadyProcessed`). A key is never sent to the provider twice.

### 4. Platform channel: model streams (lot 2)

#### 4.1 Routes

| Route | Request | Capability |
|---|---|---|
| `POST /v1/llm/forward/stream` | the `forward` request (`platformRequest.forward`, `LLMForward`), whose body must hold `"stream": true` | `llm.invoke` |
| `POST /v1/llm/complete/stream` | the `complete` request (`platformRequest.llm`, `LLMRequest`) | `llm.invoke` |

`capability.ForRoute` maps both to `llm.invoke`. The request is the
channel's usual JSON envelope (`protocol`, `identity`, `idempotency_key`),
read with today's bound (`MaxMessageBytes`); `forward` with `"stream": false`
or without `stream` is `invalid` on the stream route, and `forward` with
`"stream": true` stays `invalid` on `/v1/llm/forward`.

#### 4.2 The answer

A refusal before the first frame is today's JSON answer
(`platformResponse` with `code`) and HTTP status (`platform.go:361-377`):
`unauthorized`, `capability_denied` (403), `invalid`, `dialect` (400),
`quota_exceeded`, `rate_limited` (429), `rejected`, `conflict` (409),
`unavailable` (503, also the 17th concurrent call of the VM),
`outcome_unknown` (409, the replay of a key still reserved). A provider
refusal before its first byte (`rejected`, `rate_limited`, `unavailable`)
also answers this way: no frame has gone out yet.

Otherwise the answer is `200`, `Content-Type: application/x-ndjson`,
`Cache-Control: no-store`, and one frame per line:

```json
{"type":"start","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"agt_…","generation":3,"vm_id":"…"}}
{"type":"event","seq":1,"event":{"name":"message_start","data":{"type":"message_start","message":{…}}}}
{"type":"event","seq":2,"event":{"name":"content_block_delta","data":{…}}}
{"type":"end","seq":9,"outcome":"completed","input_tokens":812,"output_tokens":240,"soft_budget_exceeded":false}
```

| Frame | Fields | Route |
|---|---|---|
| `start` | `protocol`, `identity`: the channel's envelope, which the client checks as it checks any answer (`platform.go:438`) | both, always first |
| `event` | `seq`, `event.name` (Anthropic's `event:`, omitted for OpenAI), `event.data` (the provider's JSON object, unchanged) | forward |
| `text` | `seq`, `text` (a fragment of the answer's text, non-empty) | complete |
| `end` | `seq`, `outcome` (`completed` or `outcome_unknown`); with `completed`: `input_tokens`, `output_tokens`, `soft_budget_exceeded`, and for complete `finish_reason` | both, always last |

- `seq` starts at 1 after `start` and grows by one per frame; `end` takes the
  next. A frame is at most 64 KiB (`capsuleprotocol.MaxStreamFrameBytes`),
  its newline included.
- Once a frame has gone out, every failure is an `end` frame with
  `"outcome":"outcome_unknown"` and nothing else: the reservation is
  unknown; the harness must not repeat the request with the same key.
- A client that reads no `end` (a broken connection) must treat the call as
  `outcome_unknown`.

#### 4.3 The host

`platformHandler` gains a stream branch, in a new file `platform_stream.go`:

- it holds one of the VM's 16 slots (`platform.go:118`) for the whole stream;
- it writes the `200` and `start` only once the provider's first byte has
  come (a 2xx with an event stream), so that every refusal before it keeps
  today's JSON answer;
- it writes each frame then calls `http.NewResponseController(w).Flush()`;
- it pushes the write deadline at each frame: idle 60 s
  (`capsuleprotocol.StreamIdleTimeout`), never past 305 s from the request
  (`LLMCallTimeout` + 5 s);
- the call's context is bounded by `LLMCallTimeout`, as today's model routes.

The worker's platform API implements a new optional interface beside
`LLMForwardAPI`:

```go
type LLMStreamAPI interface {
	ForwardLLMStream(ctx context.Context, key string, in LLMForward, sink func(LLMStreamFrame) error) error
	CompleteLLMStream(ctx context.Context, key string, in LLMRequest, sink func(LLMStreamFrame) error) error
}
```

#### 4.4 The guest

- `remotePlatform` (`platform_local_linux.go`) relays a stream frame by
  frame: it reads one line from the host, checks it (strict JSON, the frame
  types above, at most 64 KiB, `seq` in order), writes it to the local
  client and flushes. It never buffers the whole answer.
- The local server (`local_linux.go`) pushes its write deadline at each
  frame, as the host does; its 16 slots apply.
- `PlatformClient.ForwardLLMStream(ctx, key, in)` and
  `PlatformClient.CompleteLLMStream(ctx, key, in)` return a frame iterator
  (`iter.Seq2[LLMStreamFrame, error]`) and do not use `callWithTimeout`: the
  HTTP client has no total `Timeout`; the context bounds the call to 310 s,
  and once `start` has come, the iterator fails after 65 s without a frame.

### 5. Platform channel: the harness's output stream (lot 3)

#### 5.1 The route

`POST /v1/invocations/stream` on the platform channel, **full duplex**: the
host's handler calls `http.NewResponseController(w).EnableFullDuplex()`
before it reads the body, and so do the guest's local server and its relay to
the host. The channel is HTTP/1.1 only (`credentials.go:239`), where Go needs
`EnableFullDuplex` to write an answer while the body is still being read.

`capability.ForRoute("/v1/invocations/stream")` is `stream.output` (§5.9).
The route holds one of the VM's 16 slots for its whole life.

#### 5.2 Frames from the harness (the request body)

`Content-Type: application/x-ndjson`. Each line is one strict JSON object
(unknown fields refused), at most 64 KiB with its newline.

```json
{"type":"open","protocol":"capsule.v1","identity":{…},"operation_id":"op_…"}
{"type":"delta","seq":1,"text":"The NPV is computed "}
{"type":"step","seq":2,"step":"retrieval","state":"started","label":"Searching the course"}
{"type":"delta","seq":3,"text":"by discounting…"}
{"type":"close"}
```

| Frame | Fields | Rules |
|---|---|---|
| `open` | `protocol`, `identity` (the channel's envelope), `operation_id`, optional `attempt` | first line, and only there, within 5 s of the request's headers |
| `delta` | `seq`, `text` | `text` non-empty UTF-8 without NUL |
| `step` | `seq`, `step`, `state`, optional `label` | `step` matches `^[a-z][a-z0-9_.-]{0,63}$`; `state` is `started`, `done` or `failed`; `label` non-empty UTF-8 without control characters, at most 256 bytes |
| `close` | — | the harness ends the stream; no `seq`, nothing stored |

- **`attempt` is optional.** A first opening names none: the platform binds
  the stream to the invocation's current attempt and says which in `opened`.
  A harness that opens again (after a broken connection) names the attempt
  `opened` gave it; if it is no longer current, the stream closes `reset`.
  See [Changes](#changes-during-implementation), item 1.
- **`seq` is per attempt.** The first frame of an attempt has `seq` 1; each
  next frame has the previous `seq` plus one. A gap or a regression closes
  the stream `invalid`. A harness that opens again continues after the `seq`
  that `opened` gives.

#### 5.3 Frames from the platform (the answer body)

The answer is `200`, `Content-Type: application/x-ndjson`, once the opening
transaction has committed. A refusal of the opening is today's JSON answer
with its code and status, before any frame (§5.4).

```json
{"type":"opened","protocol":"capsule.v1","identity":{…},"attempt":2,"seq":0}
{"type":"ack","seq":3}
{"type":"cancel"}
{"type":"closed","reason":"terminal"}
```

| Frame | Fields | When |
|---|---|---|
| `opened` | `protocol`, `identity`, `attempt`, `seq` | first; `seq` is the last `seq` stored for the attempt, 0 if none: the next frame must carry `seq` + 1 |
| `ack` | `seq` | after each committed chunk: every frame up to `seq` is stored |
| `cancel` | — | the requester canceled the invocation, or its agent is being deleted; `closed` follows |
| `closed` | `reason` | last; the platform then ends the answer |

`closed.reason`:

| Reason | Why |
|---|---|
| `done` | answer to the harness's `close`, after the last `ack` |
| `terminal` | the invocation has its outcome (completed, failed, canceled) |
| `expired` | its `result_due_at` passed |
| `reset` | a rerun or a replay started a newer attempt, or `open` named an attempt no longer current |
| `revoked` | the caller's boot is no longer the agent's current one, or the agent is no longer live |
| `invalid` | a malformed frame, a frame over 64 KiB, an unknown type, a second `open`, a gap or a regression of `seq` |
| `truncated` | the attempt reached its limits (§5.7); nothing more is stored for it |
| `idle` | no frame from the harness for 60 s |
| `unavailable` | the worker is stopping or PostgreSQL failed; the harness may open again |

The harness may open the stream again after `idle`, `unavailable` or a
broken connection. After `terminal`, `expired`, `reset` (for its attempt),
`revoked` or `truncated`, an opening is refused or closes at once.

#### 5.4 The opening

One transaction, in the order and under the locks of
`CompleteInvocationFromVM` (`internal/controlplane/invocation_completion.go:34-115`):

1. `lockAgents` and `authorizeVM` (`internal/controlplane/vm_authorization.go:20-36`):
   the caller is the agent's current boot (host, generation, VM, `RUNNING`,
   not fence-only, store ready). Else `unauthorized`.
2. The instruction and operation rows `FOR UPDATE`, as `CompleteInvocationFromVM`
   reads them (`invocation_completion.go:58-62`), for this agent. Else
   `not_found`.
3. The invocation is working: `working_since IS NOT NULL`, no
   `completion_key`, operation `RUNNING`, `result_due_at` not passed. Else
   `transition` (not working, answered at delivery, canceled) or `expired`
   (failed, or past its due time).
4. `attempt`, if given, is `owner_instructions.attempt`. Else the opening
   succeeds and closes at once `reset` (the harness learns why).
5. The stream's state row (`invocation_streams`, §5.8) exists for this
   attempt, or is created; a truncated attempt opens and closes at once
   `truncated`.

The capability `stream.output` is checked before the transaction, by the
channel's gate (`RequireCapabilityFromVM`), as for every route that needs one:
`capability_denied`, HTTP 403. A slot missing is `unavailable`, 503.

Codes of a refused opening: `unauthorized` (403), `capability_denied` (403),
`not_found` (404), `invalid` (400: the first line is not a valid `open`, or
comes late), `transition` (409), `expired` (409), `unavailable` (503).

#### 5.5 Coalescing and acknowledgments

The worker reads frames, checks each (§5.2), and buffers them. It commits a
chunk when the buffer holds 4 KiB of frames (`output_streams.coalesce_bytes`),
or 150 ms after the oldest buffered frame (`output_streams.coalesce_window`),
or at `close`. It then writes `ack` with the chunk's last `seq`. A frame
alone over 4 KiB is a chunk alone. While a chunk commits, the worker keeps
reading; the buffer is bounded by the attempt's limits.

#### 5.6 A chunk's transaction

Each chunk is one transaction, with the same locks in the same order as the
opening, and checks again what the opening checked:

1. `lockAgents`, `authorizeVM` for the stream's boot: else `revoked`.
2. The instruction and operation rows `FOR UPDATE`: still working, before
   `result_due_at`: else `terminal` or `expired`.
3. `owner_instructions.attempt` is the stream's: else `reset`.
4. The stream's state row: `last_seq` + 1 is the chunk's first `seq` (else
   `invalid`), not truncated, and the attempt's limits hold (else, see §5.7).
5. It seals the chunk's frames (§5.8), inserts the chunk row, updates the
   state row, and commits. The `NOTIFY` follows from a trigger (§5.10).

A refused check commits nothing of the chunk and closes the stream with that
reason. These checks are what the model's broken configurations remove
(`invocationCompletionTrustsTheStream`, `invocationCompletionAnyAttempt`):
the stream lives in the worker's memory, and an outcome's transaction cannot
close it, so the opening's checks alone would let a chunk follow the outcome,
or a stream of an old attempt write into a new one.

The capability is not checked again per chunk: a policy change applies to
the next opening, as a model call's applies to the next call.

#### 5.7 Limits per attempt

At most 2 MiB of stored frames (their encoded size,
`output_streams.max_bytes`) and 4,096 frames (`output_streams.max_frames`) per
attempt. The chunk's transaction that would pass either stores the frames
that fit, sets the state row's `truncated`, commits, and the stream closes
`truncated`. The outcome is not touched: the harness still completes as
usual. The subscribers receive `truncated` (§6.2).

#### 5.8 Storage (migration)

One migration, the next free number (0056 at `321143b`; the corpus plan
claims the same number, and the orchestrator renumbers at integration), named
`invocation-streams`:

```sql
-- The invocation's attempt: 1 at its first delivery, plus one at each rerun
-- of a restore (queueRerun) and each replay of a dead letter.
ALTER TABLE owner_instructions ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1);

-- The output stream of the invocation's current attempt.
CREATE TABLE invocation_streams (
  operation_id text PRIMARY KEY REFERENCES owner_instructions(operation_id),
  attempt integer NOT NULL CHECK (attempt >= 1),
  last_seq bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  frames integer NOT NULL DEFAULT 0 CHECK (frames >= 0),
  bytes bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0),
  truncated boolean NOT NULL DEFAULT false,
  first_delta_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- One sealed chunk of frames.
CREATE TABLE invocation_stream_chunks (
  operation_id text NOT NULL REFERENCES owner_instructions(operation_id),
  attempt integer NOT NULL CHECK (attempt >= 1),
  first_seq bigint NOT NULL CHECK (first_seq >= 1),
  last_seq bigint NOT NULL,
  payload_id text NOT NULL UNIQUE REFERENCES transit_payloads(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id, attempt, first_seq),
  CHECK (last_seq >= first_seq)
);
```

- Both tables join `durableTables` (`store.go:158`); `TestEveryTableIsDurable`
  checks it.
- `transit_payloads.kind` gains `stream_chunk` (its CHECK, `schema.sql:208`,
  and `transitKind`, `transit.go:232-234`). A chunk's `ref_id` is
  `<operation_id>/<attempt>/<first_seq>`: `UNIQUE (kind, ref_id)` holds, and
  the AAD, which binds the reference, binds the operation, the attempt and
  the first `seq` with the requester and the agent (its parties), as a
  result's binds its operation (`transitBinding`, `transit.go:221-226`).
- A chunk's plaintext is a JSON array of its frames, in order, each as the
  harness sent it without `type` changes: `[{"type":"delta","seq":1,"text":"…"},…]`.
  It is sealed with `putOwned` and the result's two parties: the agent and
  the requester. Its `purge_after` is `result_due_at` plus the retention: a
  bound, in case nothing else deletes it.
- The rerun (`queueRerun`, `internal/controlplane/invocation_reruns.go`) and
  the replay of a dead letter (`instruction_replays.go`), in the transaction
  that clears `working_since`, increment `owner_instructions.attempt`, delete
  the previous attempts' chunks and their payloads, and reset the state row
  (`attempt` = the new one, counters 0, `truncated` false).

#### 5.9 The capability `stream.output`

- **Vocabulary.** `internal/capability` gains `StreamOutput = "stream.output"`:
  send the output of a working invocation as a stream
  (`/v1/invocations/stream`). `Known()` lists it; `ForRoute` maps the route.
- **Why a capability, though it answers delivered work.** ADR 016 says
  answering delivered work needs none. This one is asked for so that the
  catalog shows it (`GET /v1/agents/{id}/capabilities`): a client knows from
  it whether the agent's harness streams. It also costs the platform
  PostgreSQL writes, which an organization may refuse.
- **Requested** in `harness.yaml` (`capabilities: [llm.invoke, stream.output]`).
  A manifest without the field requests every capability, so this one too
  (ADR 016, question 2); an organization or agent policy written before it
  does not list it, so it is not effective there until added (question 1
  below).
- **The migration** widens the three CHECKs of migration 0036
  (`harness_releases.capabilities`, `organization_capability_policies.allowed`,
  `agent_capability_policies.allowed`) to the four names. The OpenAPI's
  `Capability` and `TemplateSpec.capabilities` enums gain it.
- An older platform refuses a manifest that requests `stream.output` at
  import (strict parsing), as it refused `capabilities:` before ADR 016.
- **The subscription does not need it.** A client may subscribe to any
  invocation it may read (§6): without `stream.output` it receives `state`
  and `end` only.

#### 5.10 Waking the API

Two channels, both written by triggers of the migration, so that no
transaction that changes a stream or an outcome can forget them:

| Channel | Payload | Trigger |
|---|---|---|
| `agentcapsule_invocation_stream` | the operation ID, nothing else | `AFTER INSERT ON invocation_stream_chunks`; `AFTER UPDATE OF status ON platform_operations` when `kind = 'instruction'` and the status changed; `AFTER UPDATE OF attempt ON owner_instructions`; `AFTER UPDATE OF truncated ON invocation_streams` |
| `agentcapsule_organization_policy` | the organization ID | `AFTER UPDATE OF policy_version ON organizations` |

A notification is sent at commit, and PostgreSQL folds identical ones within
a transaction. Operation and organization IDs are opaque identifiers, never
content.

#### 5.11 Purge

The worker's purge block (`Placements.DispatchPass`,
`internal/worker/dispatch_linux.go:60-80`) gains `PurgeStreamChunks`, after
`transit.PurgeExpired`: it deletes, in bounded batches, the chunks and their
payloads of invocations whose outcome is older than the retention
(`completed_at` + `output_streams.retention`, 10 min by default), and of
agents being deleted. Reruns and replays delete theirs at once (§5.8).

#### 5.12 The worker's interface and telemetry

The worker's platform API implements a new optional interface:

```go
type OutputStreamAPI interface {
	// OpenOutputStream runs the opening (§5.4) and returns the bound stream.
	OpenOutputStream(ctx context.Context, operationID string, attempt int) (OutputStream, error)
}
type OutputStream interface {
	Attempt() int
	LastSeq() int64
	// Append commits one chunk (§5.6) and returns the reason to close, or "".
	Append(ctx context.Context, frames []OutputFrame) (closeReason string, err error)
	// Signals reports a cancellation or an outcome of the invocation.
	Signals() <-chan StreamSignal
	Close()
}
```

`Signals` is fed by the worker's hub (§6.5) on `agentcapsule_invocation_stream`,
which falls back to a one-second poll of the invocation's status while it has
no connection: it is how the stream learns of a cancellation or an
outcome between chunks, to send `cancel` and `closed` without waiting for a
chunk.

Metrics (worker):

| Metric | Type | Labels | What |
|---|---|---|---|
| `agentcapsule_worker_streams_open` | gauge | `kind` (`output`, `llm`) | Streams open on the platform channels of the host's VMs |
| `agentcapsule_worker_stream_frames_total` | counter | `outcome` (`stored`, `refused`, `truncated`) | Frames of output streams: stored in a chunk, refused (invalid, after the outcome, an old attempt or boot), or past the attempt's limits. Every series served from zero |
| `agentcapsule_worker_stream_first_delta_seconds` | histogram | — | From `working_since` to the first stored delta of an attempt, buckets 0.1 to 300 s |

The span `platform.call`'s `agentcapsule.platform.call` gains the three
routes' names; the stream's outcome is its `closed.reason`.

#### 5.13 Configuration (worker)

```json
"llm": {"receipt_key": "…", "stream_first_byte_timeout": "60s", "stream_idle_timeout": "60s"},
"output_streams": {"coalesce_window": "150ms", "coalesce_bytes": 4096, "max_bytes": 2097152,
                   "max_frames": 4096, "retention": "10m", "idle_timeout": "60s"}
```

Every key is optional and takes the default shown. Bounds:
`stream_first_byte_timeout` and `stream_idle_timeout` 5 s to 290 s;
`coalesce_window` 10 ms to 1 s; `coalesce_bytes` 512 to 65,536;
`max_bytes` 64 KiB to 16 MiB; `max_frames` 64 to 65,536; `retention` 1 min
to 24 h; `idle_timeout` 10 s to 300 s. A value out of bounds refuses the
configuration at start (`configuration_invalid`).

### 6. API: SSE events (lot 4)

#### 6.1 The routes

`GET /v1/invocations/{id}/events` and its alias `GET /v1/operations/{id}/events`,
`Accept: text/event-stream`. The routes do not negotiate: a successful answer
is `200`, `Content-Type: text/event-stream; charset=utf-8`,
`Cache-Control: no-store`, `X-Accel-Buffering: no`. Tenant domain only:
delegated JWT, service token and member OIDC on the first; delegated JWT and
service token on the second, as their `/result` routes minus the closed
legacy `bearer`.

Refusals, before the first event, as `application/problem+json`:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_request` | a malformed `Last-Event-ID` |
| 403 | `forbidden` | the credential lacks `agent:content:read` |
| 404 | `not_found` | no such invocation, another organization's, not an invocation, not the caller's, no `read_content`, the agent deleted: one answer for all, no existence leak |
| 429 | `too_many_streams` | the caller already holds 4 subscriptions to this invocation |
| 503 | `stream_capacity` | the process holds `-max-event-streams` subscriptions |

`too_many_streams` and `stream_capacity` join `problemCodes`
(`internal/api/telemetry.go:15`).

#### 6.2 The events

```
event: state
data: {"state":"working","attempt":1}

event: delta
id: 1:12
data: {"seq":12,"text":"…"}

event: step
id: 1:13
data: {"seq":13,"step":"retrieval","state":"done","label":"Searching the course"}

event: reset
id: 2:0
data: {"attempt":2}

event: truncated
data: {"attempt":1}

event: end
data: {"state":"completed","attempt":1,"result":{"content":[…]}}

event: revoked
data: {}

: heartbeat
```

| Event | `data` | `id` | When |
|---|---|---|---|
| `state` | `state` (the `Invocation.state` vocabulary: `scheduled`, `accepted`, `working`, `lost`, …), `attempt` | — | first, and at each change of state |
| `delta` | `seq`, `text` | `<attempt>:<seq>` | a stored delta |
| `step` | `seq`, `step`, `state`, `label` if any | `<attempt>:<seq>` | a stored step |
| `reset` | `attempt` | `<attempt>:0` | the subscriber's attempt is no longer current: the deltas it saw are void, those of the new attempt follow |
| `truncated` | `attempt` | — | after the attempt's last stored frame, once it is truncated |
| `end` | `state` (`completed`, `failed`, `expired`, `canceled`, or `lost` with an `error_code`), `attempt`, `error_code` if any, and `result` or `result_available` | — | last; the server then closes |
| `revoked` | `{}` | — | the rights failed during the subscription; the server then closes |

- A comment line `: heartbeat` goes out every 15 s without another event.
- **`end` and the result.** A `completed` end carries `result` (what
  `/v1/invocations/{id}/result` answers) when its encoded size is at most
  32 KiB, else `"result_available": true` and the client reads `/result`. A
  synchronous answer may reach 512 KiB; a completion is bounded at 32 KiB.
  Reading the result through `end` is a read of the result: it starts its
  retention clock (`Transit.delivered`), as `/result` does.
- **Order.** Each wake of a subscriber reads, in one short read-only
  transaction (`REPEATABLE READ`), the invocation's state and attempt, the
  stream's state row, and the chunks after the subscriber's position, at
  most 64 per read. It writes the chunks' frames in `seq` order, then
  `truncated` if set, then `end` if the state is final. A chunk is never
  committed after the outcome (§5.6), so `end` follows every delta of its
  attempt.

#### 6.3 Rights

The subscription checks what `instructionResultTenant`
(`internal/controlplane/tenant_agents.go:882-938`) checks, except what
concerns an existing result: the scope `agent:content:read`, an invocation
of an agent of the caller's organization, requested by the caller, the
caller's effective `read_content` on the agent, the agent live, the
requesting principal still in the organization. Every failure is `404
not_found`, but the scope's, which is `403 forbidden`, as for `/result`.

During the subscription, the API checks them again, with the credential
rebuilt as a download link rebuilds it (token revocation and expiry
included, ADR 016 §2):

- every 10 s;
- at once when `agentcapsule_organization_policy` names the caller's
  organization: its `policy_version` changed (assignments, members, teams,
  capabilities, service accounts, organization disabled).

`policy_version` is not bumped by every revocation (a delegation token's,
those the authority service replays); the 10 s check is the bound, the
notification only shortens it. On failure: `event: revoked`, then the
server closes.

#### 6.4 `Last-Event-ID`

Format `<attempt>:<seq>`, two decimal integers, `seq` ≥ 0; anything else is
400. On a subscription:

- same attempt as the current one: the frames with a larger `seq`;
- an older attempt, or a newer one: `reset` with the current attempt, then
  all its frames;
- the chunks are gone (past the retention): `state`, then `end`.

Without the header, all the current attempt's frames. A reconnection never
duplicates a frame, and never skips one still retained.

#### 6.5 The hub

A new package, `internal/pgnotify`, holds the hub. The API runs one per
process for its subscribers, the worker one for its output streams' signals
(§5.12), and the corpus plan reuses it for its builds:

- **One dedicated connection**, outside the pool (`pgx.Connect` with the
  process's DSN), runs `LISTEN` on every channel registered at start
  (`agentcapsule_invocation_stream`, `agentcapsule_organization_policy`; the
  corpus work adds its own) and wakes the subscribers registered under
  (channel, payload).
- **Losing it** puts every subscriber on a one-second poll until the hub has
  reconnected (backoff from 1 to 30 s); on reconnection each subscriber reads
  once, so nothing sent meanwhile is missed.
- **No subscriber holds a pool connection.** Each read is a short query on
  the pool, under a 5 s context.

```go
type Hub interface {
	// Subscribe wakes c (buffered, one slot; a wake is never lost, only
	// merged) at each notification of channel with this payload, and every
	// second while the hub has no connection.
	Subscribe(channel, payload string) (c <-chan struct{}, cancel func())
}
```

#### 6.6 Deadlines and the server

Only on the two events routes:

- `ServeHTTP` does not wrap their context in its 10 s timeout
  (`server.go:223`); their handler bounds it to 15 min from the request's
  context, so a client that leaves cancels it at once.
- The handler moves the connection's read deadline to the subscription's
  end, and pushes its write deadline 30 s ahead at each event and heartbeat,
  through `http.NewResponseController` (as `attachments.go:69-71` does).
  Without the read deadline, Go's HTTP/1.1 server would cancel the request
  15 s in (`ReadTimeout`, `cmd/agentcapsule-api/main.go:254`).
- `Flush` goes through `http.NewResponseController(w)`: `statusRecorder`
  does not implement `http.Flusher` but has `Unwrap` (`telemetry.go:93`).
- After 15 min the server closes without an event; the client reconnects
  with `Last-Event-ID`.
- HTTP/2 is on whenever the API serves TLS (always in production): several
  subscriptions share a connection.

#### 6.7 Limits, configuration and telemetry

- At most 4 subscriptions of one principal to one invocation at once, in the
  process (fixed).
- At most `-max-event-streams` subscriptions in the process (a new flag of
  `agentcapsule-api`, default 1,000, 1 to 100,000).
- The routes are left out of `agentcapsule_api_request_duration_seconds`;
  `agentcapsule_api_requests_total` and the `http_request` event count them,
  once, at their end.
- New metric: `agentcapsule_api_streams_active` (gauge, no label): the
  process's open subscriptions.

### 7. SDK, adapter and CLI (lots 5 and 6)

- **Python SDK.** `Platform.forward_llm_stream(...)` and
  `Platform.complete_llm_stream(...)` yield frames; `Harness.output_stream(operation_id)`
  is a context manager with `delta(text)`, `step(name, state, label=None)`
  and `cancelled`; it opens again after `idle`, `unavailable` or a broken
  connection, naming the attempt, and sends again its frames not yet
  acknowledged. `LLM_CALL_TIMEOUT` becomes 310 s, the Go client's.
- **Go.** `PlatformClient.OpenOutputStream(ctx, operationID)` returns a
  writer with the same methods.
- **capsule-adapter.** `ModelEndpoint` relays the real stream when its client
  asks for `stream`; it replays the whole answer, as today, only after a
  refusal before the first frame. The `command` mode reads the command's
  standard output as it comes and sends it as deltas. The A2A `server` mode
  serves `SendStreamingMessage` and `SubscribeToTask`, and its cards say
  `streaming: true`.
- **CLI.** `agentcapsule invocation watch ID [--text]` and
  `agentcapsule agent invoke AGENT --file req.json --watch [--text]`: a
  dedicated HTTP client without a total `Timeout`, failing after 45 s without
  a byte, reconnecting with `Last-Event-ID`. By default one JSON line per
  event, `{"version":1,"event":"delta","data":{…}}`; `--text` prints only the
  deltas' text. Exit codes: 0 for `completed`; 5 for `failed`, `expired`,
  `canceled`, `lost` with an `error_code`, or `revoked`; 130 when
  interrupted; 3 and 4 as for any refusal.

### 8. Limits

| Limit | Default | Where | Setting |
|---|---|---|---|
| Provider's first byte | 60 s per attempt | gateway | `llm.stream_first_byte_timeout` |
| Between two provider events | 60 s | gateway | `llm.stream_idle_timeout` |
| A model stream in total | 300 s | gateway, channel | fixed (`LLMCallTimeout`) |
| Bytes read from a provider stream | 4 MiB | gateway | fixed (`Config.MaxResponse`) |
| A channel frame | 64 KiB with its newline | channel | fixed (`MaxStreamFrameBytes`) |
| Between two frames on the channel | 60 s | channel | `output_streams.idle_timeout`; model streams fixed (`StreamIdleTimeout`) |
| Streams per VM | the VM's 16 slots, shared with every other call | channel | fixed |
| Output per attempt | 2 MiB, 4,096 frames | worker | `output_streams.max_bytes`, `max_frames` |
| Coalescing | 150 ms or 4 KiB | worker | `output_streams.coalesce_window`, `coalesce_bytes` |
| Chunks kept after the outcome | 10 min | worker | `output_streams.retention` |
| Subscriptions per principal and invocation | 4 | API | fixed |
| Subscriptions per API process | 1,000 | API | `-max-event-streams` |
| Rights checked again | every 10 s, and at each `policy_version` change | API | fixed |
| Heartbeat | 15 s | API | fixed |
| One subscription | 15 min, then `Last-Event-ID` | API | fixed |

Lot 7's load tests set the production values; changing a fixed one is a
change of this record.

### 9. Security rules

- **Isolation.** An output stream opens only for the working invocation of
  the calling VM's agent, from its current boot, and binds to its current
  attempt; each chunk checks them again. Only the requester holding
  `read_content` reads it.
- **Content.** Chunks are sealed as results are (transit AEAD, parties agent
  and requester, reference bound to the operation, the attempt and the first
  `seq`) and deleted 10 minutes after the outcome. `NOTIFY` carries
  identifiers only. No log line, metric label, span attribute or problem
  detail holds a delta, a step's label, a provider event or a result. The
  `http_request` event of a subscription has its route pattern, never its
  path's ID.
- **Denial of service.** Bounds per frame, per attempt, per VM (16 slots),
  per subscriber and per API process; coalescing bounds PostgreSQL's writes
  per stream to about seven a second.
- **Cost.** A cut model stream is never billed twice: its reservation stays
  `unknown` until the organization reconciles it, and its key is never sent
  again.
- **The outcome.** Nothing a stream does changes an outcome or a result
  (`deltasNeverAnOutcome`).

### 10. Names this record fixes

| Kind | Names |
|---|---|
| API routes | `GET /v1/invocations/{id}/events`, `GET /v1/operations/{id}/events` |
| Channel routes | `POST /v1/llm/forward/stream`, `POST /v1/llm/complete/stream`, `POST /v1/invocations/stream` |
| Model stream frames | `start`, `event`, `text`, `end` (`outcome`: `completed`, `outcome_unknown`) |
| Output stream frames | harness: `open`, `delta`, `step`, `close`; platform: `opened`, `ack`, `cancel`, `closed` |
| `closed.reason` | `done`, `terminal`, `expired`, `reset`, `revoked`, `invalid`, `truncated`, `idle`, `unavailable` |
| Step states | `started`, `done`, `failed` |
| SSE events | `state`, `delta`, `step`, `reset`, `truncated`, `end`, `revoked`; comment `: heartbeat` |
| Problem codes | `too_many_streams` (429), `stream_capacity` (503) |
| Capability | `stream.output` (`capability.StreamOutput`) |
| Migration | `invocation-streams`: `owner_instructions.attempt`, `invocation_streams`, `invocation_stream_chunks`, transit kind `stream_chunk`, the capability CHECKs, the triggers |
| `NOTIFY` channels | `agentcapsule_invocation_stream`, `agentcapsule_organization_policy` |
| Metrics | `agentcapsule_llm_stream_first_event_seconds`, `agentcapsule_worker_streams_open`, `agentcapsule_worker_stream_frames_total`, `agentcapsule_worker_stream_first_delta_seconds`, `agentcapsule_api_streams_active` |
| Span attributes | `agentcapsule.llm.mode` (`unary`, `stream`); outcome `stream_cut` |
| Worker settings | `llm.stream_first_byte_timeout`, `llm.stream_idle_timeout`, `output_streams.{coalesce_window, coalesce_bytes, max_bytes, max_frames, retention, idle_timeout}` |
| API flag | `-max-event-streams` |
| Go | `llmgateway.Gateway.ForwardStream`, `CompleteStream`; `capsuleprotocol.LLMStreamAPI`, `OutputStreamAPI`, `MaxStreamFrameBytes`, `StreamIdleTimeout`; `PlatformClient.ForwardLLMStream`, `CompleteLLMStream`, `OpenOutputStream`; `LLMService.ForwardStreamFromVM`, `CompleteStreamFromVM`; `Store.PurgeStreamChunks`; `pgnotify.Hub` |
| Python | `Platform.forward_llm_stream`, `Platform.complete_llm_stream`, `Harness.output_stream` |
| CLI | `invocation watch`, `agent invoke --watch`, `--text` |

## The model

[invocation_completion.qnt](../../spec/invocation_completion.qnt) gains the
output stream: `openStream`, `appendDelta`, `resetAttempt`, `closeStream`,
and three invariants:

- `noDeltaAfterOutcome`: no chunk commits once the invocation has its outcome;
- `deltaMatchesCurrentAttempt`: every stored chunk comes from a stream of the
  current attempt;
- `deltasNeverAnOutcome`: no stream action writes the outcome; a result comes
  from the delivery's answer or a completion only.

The existing `atMostOneOutcome`, `resultIffCompleted`, `keyOnlyForAgentOutcome`
and `noLateOrStaleCompletion` are unchanged and hold. The stream is modelled
as the worker holds it: open in memory, closed at any time after the outcome
(`closeStream`), its chunks each checked in their own transaction. Three
broken configurations each violate one invariant:
`invocationCompletionTrustsTheStream` (a chunk's transaction trusts the open
stream: a delta after the outcome, in 4 steps),
`invocationCompletionAnyAttempt` (no attempt check: a delta of the old
attempt in the new one, after a rerun, in 5 steps), and
`invocationCompletionCloseFiles` (the close frame files the text as the
result, in 3 steps). The five runs (`openStreamOnlyWhileWorkingTest`,
`noChunkAfterTheOutcomeTest`, `cancelStopsTheChunksTest`,
`rerunDropsTheOldAttemptTest`, `closingTheStreamIsNotAnOutcomeTest`) are
`pending` in [projections.md](../../spec/projections.md): lot 3 projects them
in PostgreSQL tests named after them.

A rerun after an outcome a restore declared lost, and the replay of a dead
letter, also start an attempt, from an outcome; the single outcome of this
model does not cover them (`restore_authority.qnt` and
`concurrent_protocol.qnt` do). Their stream rule is the same, and the same
checks enforce it.

Checked on November 20, 2026 (evidence in
`quint/results/chantiers/streaming-lot0/`): typecheck of every model; the
five runs (`quint test`); 20,000 simulated executions of 12 steps and 50,000
of 25 keep `safety`, with both witnesses reached; Apalache, every execution
of 10 steps keeps `safety`, and each broken configuration fails within its
bound (`scripts/check-models.py --only '^invocationCompletion'`); TLC, every
reachable state (462, depth 10) keeps `safety`.

## Drafts and where they go

| Draft | Holds | Moves to |
|---|---|---|
| [openapi/openapi.yaml](../../openapi/openapi.yaml) | The public subscriptions, their events, problem codes and capability | Served by the API and exercised by the RBAC matrix |
| [Model streams](../api/llm.md#model-streams-on-the-guest-socket) and [guest platform channel](../guest/capsule-control.md) | The two model routes, the invocation output route, their frames and limits | Implemented in the worker and guest supervisor |

Both drafts passed OpenAPI 3.1 validation before implementation.

## Facts checked against the code

The plan's references hold at `321143b`, with these differences:

1. `capability.ForRoute` is a pure function; the per-call SQL read is
   `RequireCapabilityFromVM` (`internal/controlplane/capabilities.go:79-95`).
2. The 140 s per attempt is the worker's setting (`internal/worker/llm_linux.go:34`);
   the library's default is 60 s (`gateway.go:122-124`).
3. On the forward path the answer's real bound is `MaxForwardBytes`, 960 KiB
   (`forward.go:21`); `MaxResponse`, 4 MiB, is the read bound.
4. The breaker's key is `tenant/alias` (`llm_service.go:149`), not
   `tenant/provider` as `Route.Key`'s comment says (`gateway.go:50`). A
   provider refusal counts as a breaker success (`gateway.go:266`).
5. `authorizeVM` (`vm_authorization.go:20-36`) checks the boot's placement,
   not the invocation; the working state and the deadline are checked by
   `CompleteInvocationFromVM` (`invocation_completion.go:58-87`).
6. An invocation has no attempt counter. A restore's rerun (`queueRerun`,
   `invocation_reruns.go:191-227`) and a dead letter's replay
   (`replayDeadInstruction`,
   `instruction_replays.go:184-274`) reset `working_since` under the same
   operation ID. A rerun may also follow an outcome a restore declared lost.
7. The delivered envelope (`capsuleprotocol.Invocation`, `invoke.go:28-37`)
   has no attempt, and guests decode it strictly (`control.go:64-75`): a new
   field would break every harness built before it.
8. `transit_payloads` has a closed list of kinds (`schema.sql:208`) and
   `UNIQUE (kind, ref_id)` (`schema.sql:220`): one payload per kind and
   operation. The AAD has no attempt (`transit.go:221-226`).
9. Reading a result starts its retention (`Transit.delivered`,
   `transit.go:481-485`); an unread result is never purged (`transit.go:506-513`).
10. `organizations.policy_version` is bumped by assignments, members, teams,
    capabilities, service accounts and disabling (`tenant_agents.go:218`,
    `members.go:132`, `teams.go:152`, `capabilities.go:228`,
    `service_accounts.go:219`, `organizations.go:202`, …), never read for a
    decision, and not bumped by a delegation token's revocation
    (`delegation_authority.go:215`) nor by the revocations the authority
    service replays (`reconciliation.go:395-412`).
11. The 32 KiB bound is a completion's (`MaxMessageContentBytes`,
    `content.go:50`); a synchronous answer may reach 512 KiB
    (`MaxContentBytes`, `control.go:22`).
12. The 16 slots are an unnamed literal (`platform.go:118`), one set per boot
    on the host and one in the guest's local server; the 17th call is refused
    `unavailable` (503) before the capability check (`platform.go:138-143`).
13. The channel is HTTP/1.1 only (`credentials.go:239`); full duplex needs
    `EnableFullDuplex` on each server of the path.
14. HTTP/2 is on for the API only with TLS (Go's default under `ServeTLS`,
    no `NextProtos` set, `internal/operatorconfig/tls_linux.go:126-130`); a
    plain HTTP listener, development only, serves HTTP/1.1.
15. The API's long handlers leave the 10 s context with
    `context.WithoutCancel` (`attachments.go:85`, `refusals.go:140`), which
    also loses the client's departure; and Go's HTTP/1.1 server cancels a
    request whose read deadline passes, so a handler that outlives
    `ReadTimeout` must move it (`attachments.go:69-70` does).
16. The capability names are also in three CHECKs of migration 0036 and in
    two OpenAPI enums (`Capability`, `TemplateSpec.capabilities`).
17. `LLM_CALL_TIMEOUT` is at `sdk/python/agentcapsule_harness.py:59`; it is a
    socket timeout, below the gateway's 140 s per attempt.
18. capsule-adapter's model endpoint server has no write timeout
    (`cmd/capsule-adapter/main.go:111`), and `ModelEndpoint` flushes through
    `w.(http.Flusher)` (`model.go:187-206`).
19. The plan's metric prefix `agentcapsule_invocation_` is no process's:
    metrics are named by the process that serves them (`docs/observability.md`).
20. Migration 0056 is free at `321143b`; the corpus plan claims it too.

## Changes during implementation

Changes this record makes to the plan, each keeping its guarantees:

1. **The opening does not require `attempt`** (plan §3.3 shows it in `open`).
   A harness cannot know its attempt: the envelope has none and cannot gain
   one without breaking older harnesses (fact 7). The opening binds the
   stream to the current attempt and returns it in `opened`; a harness that
   opens again names it. The guarantee (a stream writes only into its own
   attempt) is kept by each chunk's check (§5.6) and checked by the model
   (`deltaMatchesCurrentAttempt`).
2. **Each chunk checks again** the boot, the working state, the deadline and
   the attempt (plan §3: "contrôlées une fois à l'ouverture"). The model
   shows the opening's checks are not enough. The capability and the slot
   stay checked once.
3. **`open` carries `protocol` and `identity`**, and the answer's first frame
   (`opened`, `start`) carries them back: the channel's envelope rule.
4. **`close` has no `seq`**: it is not stored.
5. **More `closed` reasons**: `done`, `reset`, `invalid`, `truncated`, `idle`,
   `unavailable`, beside the plan's `terminal`, `expired` and `revoked`.
6. **`/v1/llm/complete/stream` sends `text` frames**, not provider events:
   `complete` has no dialect; `forward/stream` relays events as the plan says.
7. **`NOTIFY` carries the operation ID only, from triggers** (plan:
   `<operation_id>:<attempt>:<last_seq>` after each chunk). Outcomes,
   reruns and truncations must wake subscribers too, and a trigger cannot
   miss one; the subscriber reads its position anyway.
8. **`agentcapsule_organization_policy`** wakes subscribers when
   `policy_version` changes. It is not a complete signal (fact 10): the
   10 s check stays the bound.
9. **The events routes leave the 10 s context in `ServeHTTP`**, bounded to
   15 min from the request's context (plan: `context.WithoutCancel`), so a
   departed client is seen at once; they also move the read deadline
   (fact 15).
10. **`end` embedding the result starts its retention**, as `/result` does
    (plan: only `/result` does). Otherwise a client of the stream alone would
    leave its result unpurged forever (fact 9). `end` embeds a result only up
    to 32 KiB; a larger synchronous answer gives `result_available` (fact 11).
11. **Metric names**: `agentcapsule_worker_stream_frames_total` and
    `agentcapsule_worker_stream_first_delta_seconds` replace
    `agentcapsule_invocation_stream_frames_total` and
    `agentcapsule_invocation_first_delta_seconds` (fact 19);
    `agentcapsule_worker_streams_open` is added.
12. **`too_many_streams` (429)** names the per-principal refusal the plan
    leaves unnamed.
13. **A dead letter's replay starts an attempt too**, as a rerun does (fact 6).
14. **The state row `invocation_streams`** holds the attempt's `last_seq`,
    counters and truncation beside the plan's chunk table; the chunk payloads
    are a new transit kind `stream_chunk` (fact 8).
15. **A subscription does not need `stream.output`**; the capability gates
    the harness's side only, and the catalog tells the client what to expect.
16. **`LLM_CALL_TIMEOUT` becomes 310 s**, the Go client's, rather than 300 s:
    the client's bound must outlast the channel's 300 s.
Lot 1 (the gateway) adds:

17. **A replay leaves a running call's reservation alone** (§3: "a
    reservation still `reserved` becomes unknown"). A stream runs up to
    300 s, so a harness that lost its connection replays its key while the
    stream still runs. Marking the reservation unknown then let the
    organization release it at once (`resolveLLMOutcome` accepts any
    `unknown` call), before the stream settled: the call's cost was lost.
    `LLMService` now holds each request key in its process from the
    admission to the recorded outcome. A replay meanwhile answers
    `outcome_unknown`, never reaches the provider, and leaves the
    reservation to the running call. A `reserved` key that no call of the
    process holds (its worker died) becomes unknown at its replay, as
    before. Unary calls share the keys, so the rule holds for them too.
18. **`start` goes out with the first relayed frame** (§4.3: "once the
    provider's first byte has come"). The gateway calls `sink` with events
    only. `ForwardStreamFromVM` and `CompleteStreamFromVM` return an error
    only when nothing was relayed, and an `LLMStreamEnd` (`completed` or
    `outcome_unknown`) once something was. A stream cut between the
    provider's first byte and its first event is then the refusal
    `outcome_unknown` (409), not `start` and an `end`: the harness learns
    the same thing, and lot 2 needs no other hook. A stream that completes
    without a relayed frame (no text for `complete`) is `start`, then `end`.
19. **A provider's error event is not relayed** (Anthropic's `error`, an
    OpenAI chunk with `error`): it ends the stream with an unknown outcome,
    since a provider's message never reaches the guest on the other routes.
    Anthropic's `message_stop` is relayed only once the usage is complete
    (`message_start`, and a `message_delta` with `output_tokens`), so that a
    client never takes a stream without usage for a whole answer. A usage
    field above 10^12 tokens, which the accounting refuses, is a cut.
20. **Bounds that keep a frame within 64 KiB.** An event's name is a token
    of at most 64 bytes (`[A-Za-z0-9_.:-]`) and its data valid UTF-8.
    `CompleteStream` gives fragments of at most 8 KiB
    (`llmgateway.MaxStreamText`), split between two characters, so that a
    `text` frame fits even with every character escaped. Lot 2 writes an
    event's data unescaped (an encoder with `SetEscapeHTML(false)`, or the
    bytes as they are): `json.Marshal` escapes `<`, `>` and `&` in six bytes
    and could pass 64 KiB.
21. **A caller that leaves is not the provider's failure.** A `sink` error,
    or a caller whose context ends after the first byte, releases a
    half-open probe without a verdict. A cut, a timeout, a stream past its
    bounds or without its usage counts as a failure, as §3 says.
22. **The setting's error and the metric.** A stream setting out of bounds
    stops the worker with `llm_configuration_invalid`, the code of the
    `llm` section. The worker's `LLMTelemetry` serves
    `agentcapsule_llm_stream_first_event_seconds` through the optional
    `controlplane.LLMStreamObserver`: only with the model bridge on, as the
    other `agentcapsule_llm_*` metrics.

Lot 3 (the output stream) adds these changes.

23. **The worker's stream interface** (lot 3): `OutputStream` gains
    `Closing()`, the reason an opening closes at once (`reset`, `truncated`),
    and closes with `Close(reason, dropped)`, so that the worker counts the
    frames still buffered at the close and ends the stream's span with its
    `closed` reason. `Append` and `Signals` give `canceled` (not a `closed`
    reason) for a cancellation: the host then sends `cancel`, then `closed`
    `terminal`. The worker's settings reach the host through an optional
    `OutputStreamTuning`.
24. **A newer attempt is reported first.** A chunk's transaction checks what
    §5.6 says, but reports `reset` before the working state: a rerun queues
    the invocation again, which is no outcome. The checks are the same.
25. **`opened` after a stale attempt** carries the current attempt and its
    last `seq`, then `closed` `reset`.
26. **Stored frames are re-encoded** as they were checked (compact JSON,
    without HTML escapes), not stored byte for byte: what is stored is what
    was checked. Their encoded size counts against `max_bytes`.
27. **A chunk's payload is dated at once**: `transit_payloads` requires
    `delivered_at` with `purge_after`, so both are set at insert
    (`purge_after` = `result_due_at` + retention). Chunk payloads are
    deleted, never left as tombstones.
28. **The guest's bridge waits 305 s** (`MaxOutputStreamIdle` + 5 s) for a
    frame either way, so that the host's idle bound, which the worker sets,
    decides, and the bridge relays `closed` `idle`. A malformed frame from the
    harness closes the stream `invalid` at the bridge; the host sees the call
    end and stores the frames before it.
29. **The opening reads `open` first**, then checks `stream.output`: the
    frame carries the identity the channel checks before anything. The
    capability is still checked before the opening's transaction.
30. **`AgentCatalog.ReadOutputStream`** reads the chunks of the current
    attempt after a position, for the requester only, with the rights of
    `/result` minus the result (§6.3). The PostgreSQL tests read chunks with
    it; lot 4's subscriber reads can build on it.
31. **An agent being deleted** is, for the purge, one whose phase is
    `QUIESCING`, `DELETING` or `DELETED`.
32. **`pgnotify` is built by lot 3**, minimal: `Listener` (`New`, `Run`,
    `Subscribe`, `Connected`) implements `Hub`, with the one-second poll and
    the reconnection of §6.5. The worker listens on
    `agentcapsule_invocation_stream` only; lot 4 extends it for the API.
33. **The span** names the call `output_stream`; its outcomes gain `done`,
    `terminal`, `reset`, `revoked`, `truncated` and `idle`. A stream that
    ends without a `closed` frame (the harness went away) is `unavailable`.
34. **The Go harness API** is `PlatformClient.OpenOutputStream(ctx,
    operationID)` and `ReopenOutputStream(ctx, operationID, attempt)`; the
    writer's `Close(ctx)` sends `close` and waits for `closed`, so that no
    buffered frame is dropped by the outcome filed after it.

## Consequences

- The guest changes in lots 2, 3 and 5: `internal/capsuleprotocol`,
  `internal/agentadapter`, `cmd/capsule-adapter`, `sdk/python`, and
  `cmd/capsule-echo` for the first demonstration. One integrated guest image
  is needed once lots 2 and 3 are in; KVM runs follow (§Tests).
- A harness built before this record keeps working on the new platform: it
  never opens a stream, its envelope does not change, and its clients' polling
  is unchanged.
- A harness that requests `stream.output` is refused at import by an older
  platform.
- PostgreSQL gains about seven commits a second per active output stream, and
  the API one dedicated connection per process.
- An organization whose capability policy predates `stream.output` gets no
  streaming until it adds it (question 1).

## Tests

Each lot's exit criteria are the plan's (§5). They add, by lot:

- Lot 1 (unit and PG): the parser's bounds; usage for both dialects, cache
  included; a cut, an idle stream, a stream without usage, a stream too big:
  `ErrOutcomeUnknown`, the reservation `unknown` and reconcilable; a 429
  before the first byte retried; the same key never sent twice; live on
  Ollama for both APIs (`llmlive`).
- Lot 2 (unit, PG, KVM): frames in order through the guest's relay; a frame
  over 64 KiB cut; the 17th stream `unavailable`; KVM: the first event before
  the end of generation, a stream of 290 s held by the local server and the
  host.
- Lot 3 (PG, KVM): the five runs' projections (`TestOpenStreamOnlyWhileWorking`,
  `TestNoChunkAfterTheOutcome`, `TestCancelStopsTheChunks`,
  `TestRerunDropsTheOldAttempt`, `TestClosingTheStreamIsNotAnOutcome`); chunks
  unreadable by another principal; the purge at its time; `durableTables`;
  KVM: a cancellation reaches the harness.
- Lot 4 (PG): Bob gets 404; a revocation closes within 10 s; an API restart
  caught up by `Last-Event-ID` without a gap or a duplicate; `end` carries
  what `/result` answers and starts its retention; the convention tests
  (`TestOpenAPIDescribesExactlyTheServedRoutes`, `TestEveryProblemCodeIsDeclared`,
  the RBAC matrix).

## Questions for the product owner

1. **A capability policy written before `stream.output`.** Acme allowed
   `llm.invoke`, `agents.delegate` and `agents.discover` explicitly in
   October; its new harness requests `stream.output`. (a) Streaming stays off
   for Acme until its administrator adds `stream.output`; the catalog shows
   it requested and not effective (the default). (b) The migration adds
   `stream.output` to every existing policy. Recommendation: (a): a policy
   says what an organization allowed, and nothing was allowed that did not
   exist.
2. **Reading the result through `end`.** Alice follows her invocation with
   the CLI and never calls `/result`. (a) `end` carries the result and starts
   its retention, 7 days, as a read of `/result` (the default). (b) `end`
   never carries the result; the client reads `/result`. Recommendation:
   (a): one round trip less, with the same right and the same retention.

## Changes after the v0.1.0 audit

**PERF-3A (P-11).** §5.6 step 1 is now the placement's `FOR SHARE` without
`lockAgents`: a chunk reads its agent's row without a lock. Every end of a
stream already takes a row the chunk takes: a boot that ends updates the
placement; an outcome, a cancellation, an expiry and a rerun update the
invocation's rows, which the chunk takes `FOR UPDATE` (step 2). The agent's
deletion cancels its working invocations before it purges its content, so a
chunk under way either commits first and is purged with the rest, or sees the
cancellation. A chunk thus no longer waits for every other transaction of
its agent (a submit, a delivery, a completion), nor they for it. The model's
`appendDelta` is unchanged: its atomic step is these row locks
([projections](../../spec/projections.md)).

§6.3 is kept with fewer reads: a subscriber checks its rights at its first
read, at each tick of the 10 s interval and at each `policy_version`
notification, and in between reads only the new chunks of its invocation in
one statement, without a transaction (`ReadOutputStreamNews`). That statement
still reads only the requester's own invocation of a live agent of the
organization, and checks each chunk's binding. A revocation thus cuts a
subscriber off within 10 s, at once when it changes the policy, as before.
Corpus build streams keep the full read.

**Lot SEC-1A (finding S-08).** §6.7 bounded subscriptions per principal
and invocation (4) and per process (`-max-event-streams`, 1,000) only: one
organization with 250 invocations and 4 subscriptions to each took every
slot of a process for 15 minutes, and could renew them. Two ceilings now
apply in each API process, under `-max-event-streams`:

| Limit | Default | Flag of `agentcapsule-api` | Refusal, before the first event |
|---|---|---|---|
| Subscriptions of one principal | 32 | `-max-principal-event-streams` (1 to 100,000) | 429 `too_many_principal_streams` |
| Subscriptions of one organization | 200 | `-max-organization-event-streams` (1 to 100,000) | 429 `too_many_organization_streams` |

A subscription is checked against 4 to one invocation (`too_many_streams`),
then its principal's ceiling, its organization's, and the process's
(`stream_capacity`); the first one reached refuses. The corpus build events
route shares the ceilings. `agentcapsule_api_limited_requests_total` counts
each refusal by its limit (`invocation_streams`, `principal_streams`,
`organization_streams`, `process_streams`). Opening a subscription is also
one request of its principal's and its organization's request buckets
([ADR 014](014-operations-capacity-diagnostics-audit.md#changes-after-the-v010-audit)).
As every other count of §6.7, the ceilings are per process: behind a load
balancer, each API process keeps its own. Test:
`TestEventStreamCeilingsPerPrincipalAndOrganization` (unit).
