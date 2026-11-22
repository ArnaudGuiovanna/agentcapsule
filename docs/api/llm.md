# LLM providers and model aliases (LLM-01)

A tenant declares its providers and names the models its agents can reach.
Everything requires `provider:manage` and the roles `org_owner` /
`org_admin`; a service account can act only if both its role and its token
carry this scope.

| Route | Effect |
|---|---|
| `POST /v1/llm/providers` | declares a provider (`openai_compatible` or `anthropic`), https URL (or http to localhost, which the worker refuses to call in production, [ADR 010](../adr/010-transport-security-and-preflight.md)), write-only credential. An https URL that writes an internal address out (an IP address that is not public, `localhost`, a numeric form such as `127.1`) is refused with `provider_address_not_allowed` (below) |
| `GET /v1/llm/providers` | metadata, never the credential |
| `POST /v1/llm/providers/{id}/rotate` | new credential generation, effective on the next call; the previous one's revocation is recorded with the authority service (`revocations`, [README](README.md#revocations-pending-and-confirmed)) |
| `POST /v1/llm/providers/{id}/disable` | permanent: erases the ciphertext, disables the aliases; recorded the same way |
| `POST/GET /v1/llm/aliases`, `POST /v1/llm/aliases/{alias}/disable` | model policy: only an active alias is reachable |
| `POST /v1/llm/aliases/{alias}/prices` | replaces both estimation prices (below) |
| `POST /v1/llm/aliases/{alias}/access` | `organization` or `listed` (below) |
| `POST /v1/llm/aliases/{alias}/request-policy` | the fields and tool types a forwarded request may use beside the plain ones, and the output cap of a call that declares none ([request policy](#request-policy)) |
| `POST/GET /v1/llm/aliases/{alias}/grants`, `POST /v1/llm/aliases/{alias}/grants/{id}/revoke` | the agents and teams that may call a listed alias |

## Access per agent and team

An alias's `access` is `organization` (the default: every agent of the
organization may call it) or `listed`. A listed alias serves only the agents
its active **grants** name:
- a grant names one agent (`{"agent_id":"agt_…"}`) or one team
  (`{"team_id":"team_…"}`);
- a team grant reaches every agent with an active assignment to that team,
  whatever the assignment's permissions, while the team is active.

Any other agent is refused before any reservation, and the provider is never
called. On the VM channel the code is `unauthorized`. Changes apply from the
next reservation; a call already reserved goes on. Revoking the last grant
leaves a listed alias reachable by no agent: only setting its access back to
`organization` opens it to all. A grant on an alias open to the organization
is kept and applies once the alias is listed. A disabled alias takes no change
(409). Creating an alias accepts `"access":"listed"`, so that it is never open
to all. The defaults are those of
[ADR 011](../adr/011-llm-access-and-cost-budgets.md), pending the product owner.

## Guarantees
- The credential is encrypted (AES-256-GCM) with a key derived from the
  installation key by HMAC-SHA256 and a dedicated label; it is bound to the
  organization, the provider and the generation. It appears neither in
  responses, nor in idempotency receipts (only its SHA-256 fingerprint enters
  the comparison), nor in the audit, nor in a VM.
- Decryption exists only in `ResolveLLMRoute`, which the gateway calls with the
  tenant bound to the authenticated channel. Disabled organization, alias or
  provider: `ErrNotFound` from the next request.
- Audit: `llm.provider.created|rotated|disabled`,
  `llm.alias.created|disabled|access_set|prices_set|operations_set|request_policy_set|grant_created|grant_revoked`,
  `llm.budget.created|disabled`, `llm.usage.settled|released`. A grant's event
  targets its agent or team, with the alias as reference; a resolved call's
  targets its agent, with the call as reference.

## Known limits
- The encryption key derives from the installation key: losing it also loses the
  credentials (D-05 stays open for a dedicated secret store and rotation of this
  key).
- The gateway does not check the harness's `llm.invoke` capability yet
  (CAP-01).

## Outbound calls (LLM-02)
`internal/llmgateway` calls the provider resolved by `ResolveLLMRoute`.
- Adapters: `openai_compatible` (`/chat/completions`, `Authorization: Bearer`)
  and `anthropic` (`/v1/messages`, `x-api-key`, `system` role folded into
  `system`).
- Bounded retry (2 attempts by default) only when the provider cannot have
  accepted the work: a failure before any connection exists (a name that does
  not resolve, a refused connection, a failed TLS handshake), 429, 5xx. Once a
  connection exists the request may have been written: any transport error
  after that point (a reset, a close without an answer, a timeout) gives
  `ErrOutcomeUnknown` and is never replayed; the cost must then be treated as
  uncertain (LLM-03). A 4xx other than 429 is a permanent refusal.
- The gateway keeps up to 32 idle connections per provider address
  (`llm.max_idle_conns_per_host`), so that concurrent calls reuse them.
- Per-provider circuit breaker: opens after N consecutive failures, a single
  probe in half-open state.
- Redirects are not followed: a 3xx answer is a permanent refusal, so the
  credential never goes to another address. Environment proxies are ignored.
- Nothing of the content or the credential is logged; there is no promise of
  exactly-once effect for an external call.

### Provider addresses

The worker calls a provider at a public address only, unless the platform
operator allows an internal one. It checks each address when it connects,
after DNS resolution: a public name that resolves to `127.0.0.1` is refused
like `127.0.0.1`.
- Refused unless the operator allows them: loopback, private (RFC 1918,
  RFC 4193), site-local (`fec0::/10`), carrier-grade NAT and the other
  reserved ranges.
- Always refused: unspecified, multicast and link-local addresses, and the
  cloud metadata addresses.
- An IPv6 address that carries an IPv4 address takes its class:
  IPv4-mapped, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo
  (`2001::/32`, the stricter of its server and its client).
- A refused call is a permanent refusal (`rejected` on the VM channel):
  nothing is sent, the reservation is released, the breaker stays closed.

The operator allows a model server on their network or on the host in the
worker's configuration, `"llm": {"allowed_internal_providers": [...]}`, as
`host:port` or CIDR prefixes; there is no default entry
([install.md](../install.md#model-providers-on-internal-addresses)). An
organization cannot widen it. Register such a server by its name, which its
certificate covers: `https://models.corp.example:11434/v1`, not
`https://10.20.0.7:11434/v1`.

### Tests against a real provider

The `TestLive*` tests (`internal/llmgateway/live_test.go` and
`live_stream_test.go`, `internal/controlplane/llm_live_test.go` and
`llm_live_stream_test.go`) are compiled only with the `llmlive` tag, hence
never by the default campaigns. They target a real `openai_compatible`
endpoint, in practice a local Ollama, with no paid credential, and the same
server's Anthropic API (`AGENTCAPSULE_TEST_LLM_ANTHROPIC_BASE_URL`, by default
the OpenAI base URL without its `/v1`, as Ollama serves both):

```bash
python3 scripts/verify-postgres.py ... \
  --llm-base-url http://127.0.0.1:11434/v1 --llm-model tinyllama:latest
```

Against the real provider they verify:
- the usage reported by the provider and the respect of `max_tokens`;
- an unknown model = permanent refusal that does not open the breaker;
- a cut after sending = `ErrOutcomeUnknown`, a single request emitted;
- provider streams ([ADR 022](../adr/022-native-streaming.md) §3), in both
  APIs: events relayed in order with the usage of the unary call, text
  fragments, and a stream cut after its first event, by the network or by a
  client that leaves, = `ErrOutcomeUnknown`, a single request emitted;
- end to end with PostgreSQL:
  - exact settlement at the reported tokens and estimated cost, streams
    included;
  - a key already settled is never sent again;
  - `hard` budget refused with no outbound request, counted by a proxy;
  - reservation released on refusal, and kept `unknown` on a cut, then
    settled or released by the organization.

The content of the responses is not evaluated. Without these options,
`environment.json` records `llm_live: not_run`. A paid provider (HTTPS) goes
through the same phase, with `AGENTCAPSULE_TEST_LLM_SECRET`; this secret is never
recorded. The `anthropic` adapter has been called against Ollama's Anthropic
API, not yet against Anthropic's hosted API.

## Budgets and consumption (LLM-03)
A budget limits the tokens (input + output, `limit_tokens`) or the estimated
cost (`limit_cost_micro`) of an organization, an agent, an alias, or an agent
and an alias, per UTC day or month: exactly one of the two limits. One active
budget per scope, period and unit (409 otherwise): a token budget and a cost
budget may cover the same scope. Budgets require `quota:manage` (roles
`org_owner`/`org_admin`); consumption requires `usage:read` (`org_owner`,
`org_admin`, `auditor`). `GET /v1/llm/budgets` gives each active budget's
`used`: what its current window counts, in its unit.

**Prices.** An alias has two prices, `input_micro_per_mtok` and
`output_micro_per_mtok`: micro-units of the organization's currency (10^-6) per
million tokens, at most 10^12. Anthropic's cached input counts as input. They
are set at the alias's creation, or both replaced with `POST
/v1/llm/aliases/{alias}/prices` (`provider:manage`). The alias is then
`priced`; zero prices set on purpose are a free model. An alias created without
prices is not priced.

Each call goes through `LLMService`: alias resolution, the alias's request
policy (below), access check, **reservation**, call, then a single outcome.
The provider's status and credential are read again in the reservation's
transaction: a provider disabled since the route was resolved refuses the
call, and a credential rotated since then is resolved again, so that a
revoked credential is never used. The reservation counts:
- the **output cap** the provider is held to: the one the request declares,
  else the alias's `max_output_tokens`, else 4,096 tokens on the forward
  routes and 1,024 on `/v1/llm/complete`. The cap is written into the request
  sent to the provider, in the field the alias names (`output_cap_field`),
  whichever field the agent's SDK used, so the answer cannot be longer;
- an **input estimate**: one token per three ASCII bytes of the request and
  one per other byte (text in other scripts has more tokens per byte), plus,
  for each medium the provider fetches itself, 4,096 tokens per image and
  300,000 per document (a PDF of up to 100 pages at about 3,000 tokens each)
  given by URL or by a provider file id. An inline image or document is in
  the request's bytes;
- and their cost at the alias's current prices.

The call keeps these prices until its settlement: a price change applies to
calls reserved after it. Outcomes:
- success: settlement with the usage reported by the provider, priced at the
  reservation's prices; a count the answer leaves out (no `usage`, or only
  part of it) is settled at the reservation's: the input estimate, the output
  cap. It is never settled at zero;
- refusal, 429, 5xx, a failure before any connection (nothing was sent):
  release, the provider billed nothing;
- a transport error once connected, or a timeout after sending: `unknown`,
  the reservation (tokens and cost) **keeps counting** and cannot be
  released as free (below);
- a call reserved under a host admission that then fails never runs: its
  reservation is released at once.

A window counts settled calls at their reported tokens and estimated cost,
calls in flight and of unknown outcome at their reservation, and nothing for
released calls. A `hard` budget refuses before any call (`ErrBudgetExceeded`,
code `quota_exceeded` on the VM channel). A hard **cost** budget also refuses
a call to an alias that is not priced: its cost cannot be known. A `soft`
budget lets the call through and reports the overrun: the answer's
`soft_budget_exceeded`, and the operator's metric and log line. A request key
already used does not count again and never calls the provider again; a
reservation left `reserved` after a shutdown is treated as unknown when its key
comes back.

**What a hard budget guarantees.** The applicable budgets are locked in a
fixed order while a call reserves, so concurrent calls never admit more
**reservations** than the limit: a call is admitted only if every call of
the window, at its settlement or its reservation, plus its own reservation,
fits. The window can still pass the limit when a call settles above its
reservation, by that excess:
- output: never above the cap the provider is held to, if the provider reads
  the alias's `output_cap_field` (Ollama reads `max_tokens` only, OpenAI's
  reasoning models `max_completion_tokens` only); a server that reads neither
  is bounded only by its own limit, so set the alias's `max_output_tokens` to
  the model's maximum;
- input: above the estimate when the text has more tokens per ASCII byte
  than three (single characters split by spaces, for example), when an image
  costs more than 4,096 tokens (some providers report an image as tens of
  thousands of tokens, at a lower price per token), or a document more than
  300,000.

Each budget keeps what each of its windows counts (since the v0.1.0 audit,
P-05): a reservation adds its amounts, a settlement or a release the change
of its call's, in the transaction that changes the call. A reservation reads
that count, never the window's calls, so its cost does not grow with them;
the count is the sum described above, exactly, under any concurrency. A
budget created during a window counts the calls its scope already made in
it. The worker deletes a settled or released call `model_call_retention`
after its reservation (90 days by default, at least 35:
[worker.md](../worker.md), "Finished model
calls"); a request key is idempotent for as long as its call is kept.

Such an excess is settled and counted; the next call is then refused. How
many calls can exceed at once is bounded: an agent has at most 8 model calls
in flight, every route counted (`llm.max_calls_per_agent` in the worker's
configuration, 1 to 64), and the next one is refused before any reservation
with the code `concurrency_limited`. A soft budget guarantees nothing; it
reports.

**Exact amounts.** Costs are integers in micro-units, computed exactly and
rounded up once per call: an estimate never under-reports. A call's cost fits in
64 bits at the bounds (10^12 tokens, 10^12 per million).

`GET /v1/llm/usage?period=day|month` gives, per agent and per alias (the
alias names the model), then for the organization (`totals`): settled tokens,
in-flight tokens and tokens of unknown outcome, and the same three for the
cost (`estimated_cost_micro` for settled calls, `pending_cost_micro`,
`unknown_outcome_cost_micro`). The cost is an **estimate**, never an invoice.

### Calls of unknown outcome

Only the organization can read its provider's account, so it reconciles the
calls the platform cannot settle:
- `GET /v1/llm/calls/unresolved` (`usage:read`): the calls of unknown outcome,
  and the reservations older than 15 minutes (longer than any call: the bridge
  stops at 300 s), whose worker stopped before their outcome. Each item gives
  the agent, the alias, the reserved tokens and cost and the creation time; no
  request key, prompt or answer.
- `POST /v1/llm/calls/{id}/settle` with `{"input_tokens":…,"output_tokens":…}`
  (`quota:manage`): the usage read in the provider's account, priced at the
  call's reservation.
- `POST /v1/llm/calls/{id}/release` (`quota:manage`): the provider billed
  nothing; the reservation stops counting.

A resolved call, or one still possibly running, answers 409. When a resolution
and a late settlement by the worker race, one wins and the other is refused.
Nothing is resolved automatically; an unresolved call counts in the window of
its creation only.

### Metrics and logs

The worker's metrics count, for the whole installation, settled tokens and
estimated cost by provider kind, call outcomes, refusals by reason
(`budget_tokens`, `budget_cost`, `unpriced`, `alias_access`, `unsupported`,
`feature_denied`, `concurrency_limited`), soft budgets
passed by unit, and unresolved calls. A soft budget passed and a refused call
are also logged (`llm_budget_soft_exceeded`, `llm_call_refused`) with the
budget's unit, period and scope. They name no organization, agent, alias or
model ([observability.md](../observability.md)); an organization's own figures
per agent and alias are those of `GET /v1/llm/usage`.

## VM bridge (CAP-01)

A running capsule calls its model through the authenticated platform channel,
`POST /v1/llm/complete` (never through the guest network):

```json
{"alias":"fast","messages":[{"role":"user","content":"..."}],"max_tokens":256,"temperature":0.2}
```

and receives `{"text","finish_reason","input_tokens","output_tokens","soft_budget_exceeded"}`.
The idempotency header (`idempotency_key`, at most 200 characters) is the
ledger's request key. Embeddings, transcription and OCR have their own routes
on the same channel, under the same rules:
[guest/llm-multimodal.md](../guest/llm-multimodal.md).

- **Identity**: organization and agent come from the channel (generation and VM
  of the current boot), never from the payload. A `tenant_id`, `provider_secret`
  or equivalent field is refused (400) before the adapter. An agent of the legacy
  domain has no gateway (403).
- **Policy**: the only name the guest supplies is an alias defined by its
  organization; the alias carries the authorized model. A listed alias serves
  only the agents granted it. The LLM-03 budgets apply. The provider
  credential never enters the VM.
- **Host lock**: placement and reservation happen under host admission; the
  provider call happens **outside** that lock, so that a slow model delays
  neither wake, sleep nor deletion. Accounting survives a cancellation by the
  caller.
- **During an invocation**: an instruction is delivered under an exclusive
  admission turn of the host, and this bridge waits for that turn. An agent that
  must call its model to answer therefore acknowledges "working", calls the
  model, then files its result
  (see [agents-assignments.md](agents-assignments.md#deferred-result-the-working-state)).
- **Timeouts**: 300 s in total (two attempts of 140 s); only the model routes
  extend the server's write deadline.
- **Errors** (enumerated codes, never a provider message): `quota_exceeded` (a
  hard budget in tokens or cost, or a hard cost budget on an alias without
  prices) and `rate_limited` (429), `concurrency_limited` (429: the agent
  already has its limit of model calls in flight; retry when one ends),
  `rejected` (provider 4xx), `outcome_unknown` (a cut or a timeout once the
  request may have been sent: the reservation keeps counting; **do not** retry
  with the same key), `conflict` (key already processed: use a new key),
  `invalid`, `feature_denied` (400, forwarded requests: a field or a tool type
  the alias's request policy does not allow), `unauthorized` (also a listed
  alias not granted to the agent), `unavailable`. An older `capsule-init`
  answers `unavailable` for a code it does not know.
- **Replay**: a settled key is never called again and the text is not kept; the
  guest repeats the request with a new key.
- **Activation**: the worker offers the bridge only if its configuration contains
  `"llm": {"receipt_key": "/absolute/path/key"}`, the same private 32-byte key as
  the API (provider credentials are encrypted under a key derived from it).
  Without it, the bridge answers `unavailable`. The same section's
  `allowed_internal_providers` lists the internal provider addresses the
  operator allows ([provider addresses](#provider-addresses)), and
  `stream_first_byte_timeout` and `stream_idle_timeout` bound a provider
  stream ([ADR 022](../adr/022-native-streaming.md) §3): up to the provider's
  first byte, per attempt, and between two of its events, `"60s"` each by
  default, from `"5s"` to `"290s"`. `max_idle_conns_per_host` is how many
  idle connections the gateway keeps to each provider address (32 by
  default, 2 to 512). `max_calls_per_agent` is how many model calls an agent
  may have in flight at once, every route counted (8 by default, 1 to 64). A
  value out of bounds stops the worker with `llm_configuration_invalid`.

## Native requests from the model endpoint

`POST /v1/llm/forward`, on the same channel, carries a request exactly as the
agent's own SDK wrote it to the model endpoint of
[capsule-adapter](../adapter.md):

```json
{"alias":"gpt-4o","dialect":"openai","body":{"model":"gpt-4o","messages":[...],"tools":[...]}}
```

`dialect` is `openai` (Chat Completions) or `anthropic` (Messages). The answer
is `{"body": <the provider's JSON answer>, "input_tokens", "output_tokens",
"soft_budget_exceeded"}`. Identity, policy, host lock, timeouts and replay are
those of `/v1/llm/complete`. In addition:

- **The body is the agent's.** Messages, client tools, images and plain
  options reach the provider unchanged. The gateway sets `model` to the
  alias's upstream model, adds the credential, and writes the output cap in
  the field the provider reads (the alias's cap when the request declares
  none). What else the body may ask is the alias's
  [request policy](#request-policy).
- **Same API on both sides.** An `openai` body goes only to an
  `openai_compatible` provider, an `anthropic` body only to an `anthropic`
  provider. Otherwise the code is `dialect`, and the reservation is released.
- **Refused before any reservation** (`invalid`):
  - `stream: true` on the unary route (use `forward/stream` for a stream);
  - several choices (`n` > 1);
  - an output cap above 1,000,000 tokens;
  - an Anthropic body without `max_tokens`;
  - a body that is not a JSON object with messages;
  - a body over 960 KiB.
- **Refused before any reservation** (`feature_denied`): a top-level field or
  a tool type the alias's request policy does not allow.
- **Accounting.** The reservation is the input estimate, media by reference
  included, plus the output cap ([budgets](#budgets-and-consumption-llm-03)).
  Settlement uses the provider-reported usage, and the reservation for what
  the answer leaves out; Anthropic's cached input
  (`cache_creation_input_tokens`, `cache_read_input_tokens`) counts as input.
  An answer that cannot be read, or that exceeds 960 KiB, was still produced:
  its outcome is `outcome_unknown`.

### Request policy

A forwarded request's top-level fields pass when they are its API's plain
fields, and its tools when the agent runs them itself:
- OpenAI Chat Completions: `messages`, `max_tokens`, `max_completion_tokens`,
  `n` (1), `stream`, `stream_options`, `temperature`, `top_p`, `stop`, `seed`,
  `frequency_penalty`, `presence_penalty`, `logit_bias`, `logprobs`,
  `top_logprobs`, `response_format`, `tools`, `tool_choice`,
  `parallel_tool_calls`, `functions`, `function_call`, `user`,
  `reasoning_effort`, `verbosity`, `prompt_cache_key`, `safety_identifier`;
  tools of type `function` or `custom`.
- Anthropic Messages: `messages`, `max_tokens`, `system`, `stream`,
  `temperature`, `top_p`, `top_k`, `stop_sequences`, `tools`, `tool_choice`,
  `metadata`, `thinking`, `output_config`; tools without a type or of type
  `custom`.

Anything else is refused before any reservation with `feature_denied`: a tool
the provider runs itself (web search or fetch, code execution, file search,
computer use, an MCP connector, an Anthropic-defined tool such as
`bash_20250124`), and a field that changes the price of a call or keeps data
at the provider (`service_tier`, `store`, `background`, `metadata` on OpenAI,
`audio` and `modalities`, `prediction`, `web_search_options`, `mcp_servers`,
`container`, fallback models, a vendor extension such as `top_k` on OpenAI).
Such a tool also
fetches what the guest names from outside the VM, whose own network stays
closed ([ADR 012](../adr/012-limits-restart-budgets-egress.md) §3). A field
set to `null` is dropped; `store: false` and the default service tier
(`"auto"`, and `"default"` on OpenAI, `"standard_only"` on Anthropic) pass,
since they change nothing.

The organization names what an alias allows, with `provider:manage`:

```json
POST /v1/llm/aliases/research/request-policy
{"allowed_fields":["service_tier"],"allowed_tool_types":["web_search_20250305"],
 "max_output_tokens":16000,"output_cap_field":"max_tokens"}
```

- `allowed_fields` and `allowed_tool_types`: at most 32 names each, of
  lowercase letters, digits and underscores; a field the gateway rules on
  itself (`model`, `messages`, `stream`, `stream_options`, `n`, `max_tokens`,
  `max_completion_tokens`) is refused (400). A provider-executed tool is billed
  by its provider beside the tokens (per search, per container hour): the
  platform does not meter it; the tokens it adds are metered.
- `max_output_tokens` (1 to 1,000,000): the cap of a call that declares none,
  on every chat route; absent, 4,096 on the forward routes and 1,024 on
  `/v1/llm/complete`. Set it to the model's maximum output when agents rely on
  long answers.
- `output_cap_field`: where the cap of every call, declared or not, is
  written for an `openai_compatible` provider: `max_tokens` (the default;
  local servers such as Ollama read only it) or `max_completion_tokens`
  (OpenAI's reasoning models require it). A cap the agent wrote in the other
  field is moved there. An `anthropic` provider reads `max_tokens` only.

The body replaces the whole policy; the alias's answer lists it, and the
creation of an alias takes the same fields. It applies from the next
reservation, is audited (`llm.alias.request_policy_set`), and a disabled alias
answers 409. An agent refused access to a listed alias gets `unauthorized`,
whatever its request asks.

On 2026-11-19, all seven gateway and PostgreSQL live tests passed through
Ollama with local `forteim-ministral3-text-gpu-8k:20261030`. This is the
provider selected for MVP live qualification; it does not qualify Anthropic’s
hosted API. Evidence: `_evidence/pi-ghcr-local-20261119/verification.json`
(the `gateway-gemma` and `metering-gemma` phases; their model is recorded
as the local Ministral profile despite the historical phase names).


## Model streams on the guest socket

Harnesses in any language can POST JSON to the platform Unix socket.
`/v1/llm/forward/stream` takes the identity, key and forward request used by
`/v1/llm/forward`, with `stream: true` inside the native body.
`/v1/llm/complete/stream` accepts the envelope of `/v1/llm/complete`.
Both require `llm.invoke`. Read the HTTP 200 response as incremental
`application/x-ndjson` with at most 64 KiB per line including LF.

The initial `start` echoes the channel protocol and the guest identity.
Subsequent frames have consecutive sequence numbers beginning at one.
Forward frames carry an `event` object with native JSON in `data` and the
optional SSE event `name`. Complete frames carry a `text` fragment.
The last frame has type `end`. A completed end carries exact input and output
tokens and the soft budget flag. A cut after the first event yields
`outcome_unknown`. Losing the channel before seeing the end also leaves the
outcome unknown. A refusal before the stream starts uses the ordinary JSON
platform error. A settled or uncertain key never reruns the provider.
The Go reference harness demonstrates delivery before completion with
`/llm-stream <alias> <prompt>`. It publishes each text fragment when the
`stream.output` capability is available and files the final answer separately.
