# Running an unmodified agent (capsule-adapter)

A harness normally speaks the private `capsule.v1` protocol, by hand or with the
[Python SDK](../sdk/python/README.md). An agent that already exists cannot do that
without being rewritten. Some examples: a command-line agent, a script built on
the OpenAI or Anthropic SDK, or a framework application.

`capsule-adapter` speaks the protocol on the agent's behalf. The agent is packed
into a harness image unchanged, next to the adapter and a short configuration
file. Two things make it run as it is:

- **Work arrives as a command.** Each invocation runs the agent's command once,
  with the text on its standard input (or as its last argument). What the command
  prints is the answer.
- **The model is where the agent's SDK expects it.** The adapter serves the
  OpenAI Chat Completions and Anthropic Messages APIs on the VM's loopback, and
  sets `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` to that address. Each request
  goes through the platform, which adds the organization's credential, checks
  the alias and meters the budget. The credential never enters the VM, and the
  VM still has no network.

```
 invocation ─► capsule-init ─► capsule-adapter ──► agent command (stdin → stdout)
                    ▲               │  ▲                    │
                    │               │  └─ 127.0.0.1:8411 ◄──┘ OpenAI / Anthropic SDK
                    └── platform ◄──┘     (model endpoint)
                        channel: the answer, the files, every model call
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

Pi itself (Node.js and its package) still has to be packed into an image; that
image has not run in a microVM yet.

## Configuration (`adapter.json`)

Strict JSON, unknown fields refused, at most 64 KiB.

| Field | Meaning |
|---|---|
| `version` | `1` |
| `command` | Program (absolute path in the image) and arguments, at most 64 |
| `input` | `stdin` (default): the text on standard input; `argument`: the text as the last argument |
| `env` | Variables added to or replacing the defaults below; `AGENTCAPSULE_*` names are reserved |
| `models` | Model names the agent asks for → the organization's aliases |
| `default_model` | Alias used for any name absent from `models` |
| `model_address` | Loopback address of the model endpoint (default `127.0.0.1:8411`) |
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
  and, with files, `AGENTCAPSULE_FILES_DIR`.
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
  the output is the reply. The agent cannot send requests itself: that needs the
  A2A adapter (INT-03).

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
  - agents that expose a server (A2A, HTTP) rather than a command (INT-03);
  - sending requests to other agents;
  - files as results;
  - logs of the agent's standard error (OPS-02);
  - streaming from the provider;
  - translation between the OpenAI and Anthropic APIs.

## Qualification

| Check | What it shows |
|---|---|
| `go test ./internal/agentadapter` | The protocol side: acknowledgment, order, replay, files, revocation, the real command runner. The endpoint side: forwarding, alias mapping, stream replay, the error shapes of both APIs. |
| `scripts/verify-adapter.py` | The official OpenAI and Anthropic Python SDKs (pinned in `scripts/adapter-sdk-requirements.txt`), with and without streaming, with tools, through the endpoint and the platform's gateway code to a real provider (a local Ollama serves both APIs). Then an unmodified agent answers an invocation from an attached file. With `--pi`, Pi does the same through both APIs and keeps its session across invocations. |
| `scripts/verify-postgres.py` | The platform side of `/v1/llm/forward`: placement, reservation, settlement, budget refusal, API mismatch. |
| `scripts/verify-product-guest.py --adapted-harness` | The example image, adapted, imported and run in a jailed microVM: its SDK reaches a host model through the loopback endpoint, reads an attached file with a tool call, answers again after sleep and wake, and every call is metered. |

```bash
python -m venv /tmp/sdk && /tmp/sdk/bin/pip install --require-hashes --only-binary=:all: -r scripts/adapter-sdk-requirements.txt
python3 scripts/verify-adapter.py --model <a local model with tool calling> --python /tmp/sdk/bin/python \
  --output ./evidence/adapter-live
```
