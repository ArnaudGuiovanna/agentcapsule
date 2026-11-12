# Running an unmodified agent (capsule-adapter)

A harness normally speaks the private `capsule.v1` protocol, by hand or with the
[Python SDK](../sdk/python/README.md). An agent that already exists cannot do that
without being rewritten. Some examples: a command-line agent, a script built on
the OpenAI or Anthropic SDK, or a framework application.

`capsule-adapter` speaks the protocol on the agent's behalf. The agent is packed
into a harness image unchanged, next to the adapter and a short configuration
file. Three things make it run as it is:

- **Work arrives as a command, or as an A2A message.** Each invocation runs the
  agent's command once, with the text on its standard input (or as its last
  argument); what the command prints is the answer. An agent that is an A2A
  server instead keeps running, and each invocation is a message to it (see
  [Agents that serve A2A](#agents-that-serve-a2a)).
- **The model is where the agent's SDK expects it.** The adapter serves the
  OpenAI Chat Completions and Anthropic Messages APIs on the VM's loopback, and
  sets `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` to that address. Each request
  goes through the platform, which adds the organization's credential, checks
  the alias and meters the budget. The credential never enters the VM, and the
  VM still has no network.
- **Other agents are A2A agents.** The adapter serves the agents of the
  organization as [A2A](https://github.com/a2aproject/A2A/releases/tag/v1.0.1)
  agents on the VM's loopback (`AGENTCAPSULE_A2A_URL`). An agent built with an
  A2A SDK sends them messages as it would to any A2A agent; each message
  becomes a request through the platform, under the organization's consent,
  mandate and quota rules.

```
 invocation ─► capsule-init ─► capsule-adapter ──► agent command (stdin → stdout)
                    ▲               │  ▲                    │
                    │               │  ├─ 127.0.0.1:8411 ◄──┤ OpenAI / Anthropic SDK
                    │               │  │  (model endpoint)  │
                    │               │  └─ 127.0.0.1:8412 ◄──┘ A2A client
                    └── platform ◄──┘     (other agents)
                        channel: the answer, the files, every model call,
                        every request to another agent
```

The adapter runs as the harness: same unprivileged user, same chroot, same
limits. It adds no privilege and no path out of the VM.

## Packaging an agent

1. Build the agent's image as usual: its interpreter, its dependencies, its
   code. It must not need anything at runtime that is not in the image.
2. Write `adapter.json`:

   ```json
   {
     "version": 1,
     "command": ["/usr/local/bin/python3", "-I", "/opt/agent/agent.py"],
     "input": "stdin",
     "timeout_seconds": 900
   }
   ```

3. Write `harness.yaml` with the adapter as its entrypoint:

   ```yaml
   schema: agentcapsule.harness/v1
   name: my-agent
   version: 1.0.0
   protocol: capsule.v1
   architecture: x86_64
   base: agentcapsule-guest/1
   entrypoint: [/agentcapsule/capsule-adapter, /agentcapsule/adapter.json]
   ```

4. Pack the image with the adapter, then publish, sign and import it like any
   other package (see [registry.md](registry.md)):

   ```bash
   dagger call adapt --image=registry.example/acme/agent:1.0 --config=./adapter.json \
     --manifest=./harness.yaml export --path=./build/my-agent
   ```

   `adapt` adds `/agentcapsule/capsule-adapter` (a static binary) and
   `/agentcapsule/adapter.json` to the image's filesystem. Nothing else changes.
   Without Dagger, `scripts/build-adapted-harness.py --context <dir with a
   Dockerfile> --adapter-config ... --manifest ... --output ...` does the same
   with Docker.

[examples/adapted-agent](../examples/adapted-agent) is a complete example. It is
a small tool-using agent written against the official OpenAI SDK. Its image
(`Dockerfile`, pinned dependencies) contains nothing of Agent Capsule:
`dagger call adapted-agent export --path=./build/adapted-agent`.

## Agents with their own model access: the example of Pi

Many agents ship their own access to models: a subscription login, API keys
in environment variables, or a credentials file. None of it works in a
capsule, by design. The VM has no network, and no credential belongs in the
image or the VM. The organization's provider and key, declared once in the
platform, replace them. The agent is configured, not modified, to use the
model endpoint. A personal subscription login has no place here: it needs an
interactive sign-in, would leave a token in the VM, and a personal plan is not
meant for a shared service.

[Pi](https://pi.dev), the coding agent, shows what this takes. It ignores
`ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`, because it passes its own address to
each SDK. Its own `models.json` points a provider at the endpoint, for either API:

```json
{"providers": {
  "capsule-anthropic": {"baseUrl": "http://127.0.0.1:8411", "api": "anthropic-messages", "apiKey": "agentcapsule",
    "models": [{"id": "claude-sonnet", "contextWindow": 200000, "maxTokens": 8192}]},
  "capsule-openai": {"baseUrl": "http://127.0.0.1:8411/v1", "api": "openai-completions", "apiKey": "agentcapsule",
    "models": [{"id": "gpt-4o", "contextWindow": 128000, "maxTokens": 8192}]}}}
```

Use `openai-completions`, not `openai-responses`: the endpoint serves Chat
Completions, not the Responses API.

`adapter.json` then runs Pi once per invocation. Pi's configuration ships in the
image, and its sessions go to the encrypted home so that `--continue` carries
the conversation from one invocation to the next:

```json
{
  "version": 1,
  "command": ["/usr/local/bin/pi", "--print", "--provider", "capsule-anthropic", "--model", "claude-sonnet",
              "--continue", "--session-dir", "/var/lib/agent/pi-sessions"],
  "input": "argument",
  "env": {"PI_CODING_AGENT_DIR": "/opt/pi/agent", "PI_OFFLINE": "1", "PI_SKIP_VERSION_CHECK": "1", "PI_TELEMETRY": "0"}
}
```

The `PI_*` variables stop Pi from reaching the network at startup (model
catalog, version check, telemetry). The organization creates an alias named
`claude-sonnet` (or maps it in `models`) on its Anthropic provider.
`scripts/verify-adapter.py --pi` checks this with Pi 1.5.0, unmodified, through
both APIs:
- Pi reads an attached file with its own `read` tool;
- the next invocation answers from Pi's session alone.

[examples/pi-agent](../examples/pi-agent) packs Pi this way. Pi's configuration
directory must be writable, and the image is read-only. Its `start` script
therefore keeps that directory in the encrypted home, copies the image's
`models.json` into it, and runs Pi unchanged. `scripts/build-pi-harness.py`
builds the image from an installed Pi release and the Node.js it runs on, on a
Debian base, as a test build tied to the local installation. The product KVM
campaign (`verify-product-guest.py --pi-harness`) ran it in a jailed microVM on
a real model, Ollama with `gemma4:cloud`. Pi read an attached file with its own
`read` tool, then answered from its session alone, in the next invocation and
again after sleep and wake. Its model calls were metered for the agent.

## Configuration (`adapter.json`)

Strict JSON, unknown fields refused, at most 64 KiB.

| Field | Meaning |
|---|---|
| `version` | `1` |
| `command` | Program (absolute path in the image) and arguments, at most 64; or `server` |
| `input` | `stdin` (default): the text on standard input; `argument`: the text as the last argument (not with `server`) |
| `server.command` | The A2A server's program and arguments, instead of `command` |
| `server.a2a_url` | The server's A2A endpoint (JSON-RPC), `http://` on a loopback IP with a port |
| `server.ready_seconds` | How long a job waits for the server to accept connections, 1 to 3600 (default 120) |
| `env` | Variables added to or replacing the defaults below; `AGENTCAPSULE_*` names are reserved |
| `models` | Model names the agent asks for → the organization's aliases |
| `default_model` | Alias used for any name absent from `models` |
| `model_address` | Loopback address of the model endpoint (default `127.0.0.1:8411`) |
| `a2a_address` | Loopback address of the A2A endpoint (default `127.0.0.1:8412`) |
| `timeout_seconds` | Bound of one run, 1 to 86400 (default 3600) |

Without `models` or `default_model`, the model name is the alias itself. The
simplest setup is therefore for the organization to create an alias named after
the model the agent asks for (`gpt-4o`, for example), pointing at the provider
and model it chooses.

## What the agent sees

- **Environment.** `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
  `HOME` and the working directory on the agent's private encrypted volume
  (`/var/lib/agent`), `LANG=C.UTF-8` and `TMPDIR=/tmp`. Model access comes from:
  - `OPENAI_BASE_URL` (and `OPENAI_API_BASE`): `http://127.0.0.1:8411/v1`;
  - `ANTHROPIC_BASE_URL`: `http://127.0.0.1:8411`;
  - `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`: the placeholder `agentcapsule`;
  - `AGENTCAPSULE_MODEL_URL`: the endpoint itself.

  Each run also gets `AGENTCAPSULE_JOB_ID` (the operation or request it answers)
  and, with files, `AGENTCAPSULE_FILES_DIR`. `AGENTCAPSULE_A2A_URL`
  (`http://127.0.0.1:8412`) is where the other agents are (see below).
- **Memory.** Only `HOME` survives sleep and wake. An agent that keeps sessions
  or notes under `~` (for example `~/.config`) keeps them across sleep and wake,
  encrypted. The image itself is read-only, and the volume is mounted `noexec`.
- **Files.** The invocation's attachments are written under
  `~/.agentcapsule/files/<operation>/` for the run, and removed afterwards. The
  text ends with an `Attached files:` list of their paths, types and sizes.
- **Answer.** The command's standard output, cut at 30 KiB with a note. Standard
  error is discarded. An exit status other than 0, or a run longer than the
  timeout, makes the invocation `failed`. When a run ends, whatever the program
  left in its process group is stopped.
- **Requests from other agents** (`request` events) run the same command, and
  the output is the reply. The agent sends requests itself through the A2A
  endpoint, while it answers an invocation.

## Other agents (A2A endpoint)

The adapter serves the agents of the organization as A2A agents, on
`127.0.0.1:8412`: A2A 1.0, JSON-RPC binding, the profile pinned in
[interop.md](interop.md). The agent uses an A2A SDK, unchanged.

| Path | What it is |
|---|---|
| `GET /agents?skill=10302` | The Agent Cards of the agents offering any of the OASF skills given (1 to 20 `skill` parameters), from the private Directory: `{"agents": [card, ...]}` |
| `GET /agents/<id>/.well-known/agent-card.json` | Agent `<id>`'s Agent Card (also served by a `GET` on `/agents/<id>`) |
| `POST /agents/<id>` | Agent `<id>`'s A2A endpoint (JSON-RPC) |

With the A2A Go SDK (the version the tests use), for example:

```go
card, _ := agentcard.DefaultResolver.Resolve(ctx, os.Getenv("AGENTCAPSULE_A2A_URL")+"/agents/"+peer)
client, _ := a2aclient.NewFromCard(ctx, card)
result, _ := client.SendMessage(ctx, &a2a.SendMessageRequest{
	Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("Summarize: ...")),
	Config:  &a2a.SendMessageConfig{ReturnImmediately: true}})
task, _ := client.GetTask(ctx, &a2a.GetTaskRequest{ID: result.(*a2a.Task).ID})
```

- **Who is there.** A card exists for an agent the caller may send requests
  to: of its organization, discoverable, live, not itself. Anything else
  answers 404, whether it is missing, hidden or of another organization. The
  card carries what the organization published: the description and the
  OASF skills (as skills `oasf-<id>`). An agent never described has a generic
  card. A card grants no right. A message to an agent without a card is
  refused (`-31403`, permission denied).
- **A message is a request.** `SendMessage` sends the message's text parts to
  the agent through the platform (`/v1/agent-requests`, as any harness does).
  The task's ID is the request's ID. The request is stored before the call
  answers; it then waits for the recipient side's consent, wakes the recipient
  if it sleeps, and is delivered. Between agents of an organization, consent is
  the recipient's inbound policy (`PUT /v1/agents/{id}/inbound`, see
  [agents-assignments.md](api/agents-assignments.md#directory-publication-int-02)):
  `auto` delivers at once; under `manual`, the default, the task stays
  `WORKING` until the request's deadline, since an organization has no
  approval route yet. The task's
  states follow the request's, as listed in
  [interop.md](interop.md#decisions). The request's own state is repeated in
  the task's metadata (`agentcapsule.request_state`).
- **Only while answering an invocation.** Each request spends one of the
  invocation's allowance (its mandate: 1 to 3 requests, until it expires). The
  endpoint therefore refuses a message outside a run, and during a run that
  answers another agent's request: a request carries no mandate, so a reply
  cannot start a new delegation. The refusal is an A2A error
  (`-31403`, permission denied), as is an allowance used up.
- **Waiting for the answer.** By default (`returnImmediately` false), A2A's
  `SendMessage` waits for the outcome. The wait can be long: consent may need a
  person, and the request's deadline is the invocation's. Pass
  `returnImmediately: true` and call `GetTask` to follow the task instead.
  `GetTask` asks the platform where the request stands. The reply arrives as an
  event: the task is `COMPLETED` once it is there, with the reply as the
  artifact `reply`.
- **Tasks outlive the run.** Tasks are kept in the agent's encrypted home.
  `GetTask` answers in a later invocation, and after sleep and wake. A reply
  that arrives after the run ended is kept for the next one.
- **Retries.** The same message (same `messageId`) sent again by the same run
  is the same request; with other content it is refused. A message sent again
  by a run that starts over after a crash or a sleep is a new request.
- **Not supported.** File and data parts, follow-up messages on a task
  (`taskId`), streaming (`SendStreamingMessage`, `SubscribeToTask`; the cards
  say `streaming: false`), push notifications, `ListTasks`, extended cards.
  `CancelTask` answers `TaskNotCancelable`: only the sender's owner can cancel
  a request, through the platform API.

## Agents that serve A2A

Some agents are servers rather than commands: they speak A2A themselves (an A2A
SDK's server, a framework's A2A endpoint). `server` in `adapter.json` replaces
`command`:

```json
{
  "version": 1,
  "server": {
    "command": ["/usr/local/bin/python3", "-I", "/opt/agent/server.py"],
    "a2a_url": "http://127.0.0.1:9000/",
    "ready_seconds": 120
  },
  "timeout_seconds": 900
}
```

- **The server runs with the VM.** The adapter starts `server.command` at boot,
  in the agent's home, with the same environment as a command (model endpoint,
  `AGENTCAPSULE_A2A_URL`), in a process group of its own. If it exits, it is
  started again after 1 s, then up to 30 s between attempts. When the VM goes
  to sleep, the group gets `SIGTERM`, then `SIGKILL` 5 s later.
- **Each job is one message.** An invocation, or a request from another agent,
  becomes one A2A message (`SendMessage`, text, `messageId`
  `agentcapsule-<job>`) to `server.a2a_url`, the configured address, whatever
  the agent's card says. The adapter follows the task with `GetTask` until it
  ends. The answer is the text of the task's artifacts (or of its status
  message, or of a message the server answers directly).
- **Failures.** A task that ends `FAILED`, `REJECTED` or `CANCELED`, a task
  that asks for input (`INPUT_REQUIRED`, `AUTH_REQUIRED`; it is canceled, as
  no one can answer it here), a server that dies during the task (or a job sent
  in the instant it dies, before the adapter notices), and a server that does
  not accept connections within `ready_seconds` all make the run failed. A run interrupted by sleep starts again after the wake, with the same
  `messageId`.
- **Sending to other agents** works as for a command: while the server handles
  an invocation's message, it can send requests through `AGENTCAPSULE_A2A_URL`
  under that invocation's mandate.
- **One job at a time**, as with a command: the adapter sends the next message
  once the previous task has ended.

[examples/a2a-agent](../examples/a2a-agent) is such an agent: a Go program
written with the official A2A Go SDK that answers with the text it receives,
or, for `ask <agent> <question>`, asks that agent through
`AGENTCAPSULE_A2A_URL` and answers with its reply. It needs no base image:
`scripts/build-a2a-harness.py` packs its static binary with the adapter,
without Docker.

## Model endpoint

| Path | API |
|---|---|
| `POST /v1/chat/completions` | OpenAI Chat Completions (also `/chat/completions`) |
| `POST /v1/messages` | Anthropic Messages |
| `GET /v1/models` | The names listed in `models` and `default_model` |

- **Forwarded as written.** The body reaches the provider as the agent wrote it:
  messages, tools and tool choice, images, response formats, temperature, and so
  on. The platform replaces only `model` (the alias's upstream model) and the
  credential (`/v1/llm/forward` on the platform channel, see
  [api/llm.md](api/llm.md#native-requests-from-the-model-endpoint)).
- **Same API on both sides.** An OpenAI request goes only to an
  `openai_compatible` provider, and an Anthropic request only to an `anthropic`
  provider. A mismatch answers 400. There is no translation between the two
  APIs.
- **Streaming.** A client that asks for a stream (`"stream": true`) receives the
  whole answer, replayed in each API's stream format:
  - OpenAI: chunks with indexed tool calls, then the usage when
    `stream_options.include_usage` is set, then `[DONE]`;
  - Anthropic: `message_start`, then each content block (text, tool use,
    thinking with its signature), then `message_delta` and `message_stop`.

  The provider itself is never asked for a stream, so the answer arrives in one
  piece, after the whole generation.
- **Refusals** carry each API's error shape and status:

  | Case | Status |
  |---|---|
  | Unknown alias | 404 |
  | Budget exhausted (`hard`) or provider rate limit | 429 |
  | Provider refusal, or a request with several choices (`n` > 1) | 400 |
  | Anthropic request without `max_tokens` | 400 |
  | Provider timeout after sending | 504 |
  | Platform unavailable | 503 |

  SDKs retry 429 and 5xx answers by themselves; each retry is a new, separately
  metered call.
- **Bounds.** A request and its answer are each limited to 960 KiB (about
  240,000 tokens of context). A call may take up to 300 s: one provider attempt
  of up to 140 s, or two.

## Guarantees and limits

- **Delivery.** It is that of any harness. An invocation is recorded and
  acknowledged `working` at once, in the same transaction, and its answer is
  posted with a key derived from the delivered event. A lost acknowledgment
  never runs the command twice. Jobs run one at a time, in delivery order.
- **Interrupted runs.** A run interrupted by a requested sleep, a crash or a
  forced stop of the VM is not an outcome: it starts again from the beginning
  after the restart, so the agent's side effects can happen twice. Its model calls are separate calls, each metered. A finished
  run is never repeated; its output is kept until the platform takes the answer.
  Idle shutdown never stops an agent while an invocation is `working`.
- **Model calls.** They are metered like any other: reservation from the
  request's size and output cap (4,096 tokens when the request sets none), then
  settlement at the provider-reported usage. Anthropic's cached input counts as
  input. A request that would exceed a `hard` budget is refused before the
  provider is called.
- **Not covered yet:**
  - agents that expose a plain HTTP server rather than A2A;
  - several jobs at once for a server agent;
  - files as results, and files in requests to other agents;
  - logs of the agent's standard error (OPS-02);
  - streaming from the provider;
  - translation between the OpenAI and Anthropic APIs.

## Qualification

| Check | What it shows |
|---|---|
| `go test ./internal/agentadapter` | The protocol side: acknowledgment, order, replay, files, revocation, the real command runner. The endpoint side: forwarding, alias mapping, stream replay, the error shapes of both APIs. The A2A side, driven by the official A2A Go SDK (v2.8.0): cards and discovery, a request followed from consent to its reply, a blocking message, outcomes without a reply, and every refusal. Server agents, built with the SDK's server: answers, failures and requests for input, a real server process supervised through a crash and a restart, and a server agent that asks another agent over A2A while it answers an invocation. |
| `scripts/verify-adapter.py` | The official OpenAI and Anthropic Python SDKs (pinned in `scripts/adapter-sdk-requirements.txt`), with and without streaming, with tools, through the endpoint and the platform's gateway code to a real provider (a local Ollama serves both APIs). Then an unmodified agent answers an invocation from an attached file. With `--pi`, Pi does the same through both APIs and keeps its session across invocations. |
| `scripts/verify-postgres.py` | The platform side of `/v1/llm/forward`: placement, reservation, settlement, budget refusal, API mismatch. The reads behind the A2A endpoint: cards follow the recipient rules, a request's state is its sender's only, and both cross capsule-init's bridge. The inbound policy an organization sets on an agent. The example A2A agent, against the official SDK's client and server. |
| `scripts/verify-product-guest.py --adapted-harness` | The example image, adapted, imported and run in a jailed microVM: its SDK reaches a host model through the loopback endpoint, reads an attached file with a tool call, answers again after sleep and wake, and every call is metered. With `--pi-harness`, Pi does the same on a real model and keeps its session across sleep and wake. With `--a2a-harness`, two example A2A agents in their own microVMs: one asks the other over A2A, refused while the other is hidden, answered once it is discoverable under the `auto` policy, and again after it went to sleep, which the request wakes. |

```bash
python -m venv /tmp/sdk && /tmp/sdk/bin/pip install --require-hashes --only-binary=:all: -r scripts/adapter-sdk-requirements.txt
python3 scripts/verify-adapter.py --model <a local model with tool calling> --python /tmp/sdk/bin/python \
  --output ./evidence/adapter-live
```
