# Pi for Agent Capsule

This guest/2 harness runs Pi 1.5.0 with a writable workspace in the agent's
encrypted volume. Pi reads mounted corpora under `/corpus`. The four workspace
tools are `read`, `write`, `edit` and `bash`. A model can delete workspace
files through bash. Agent Capsule checks the organization's and agent's
permissions on every call to a peer or model. [Administrator CLI](../../docs/cli.md)

An organization supplies the model provider, its credentials and model aliases.
The default profile uses the OpenAI-compatible adapter, alias `pi-model`, a
32,000-token context window and a 1,024-token maximum output. Set the window
to one the upstream model actually supports. The gateway accepts up to 960 KiB
of serialized request data. This limit counts bytes.

`agent_discover` finds peers by OASF skill. `agent_ask` submits a question once.
A pending result contains the request ID. After the recipient accepts and
answers, `agent_request_status` retrieves the reply. A later invocation can read
the same task. Agent Capsule's manual inbound consent remains the default.
[Peer requests and permissions](../../docs/adapter.md#other-agents-a2a-endpoint)

## Model profile and compaction

The CLI can attach a typed control part to a direct invocation. The next parts
carry the ordinary prompt and any file information.

```json
{"content":[{"type":"json","json":{"agentcapsule_pi":{"action":"invoke","provider":"capsule-openai","alias":"pi-model","context_window":64000,"max_output_tokens":4096}}},{"type":"text","text":"Read the corpus index and summarize the first document."}]}
```

The provider is `capsule-openai` or `capsule-anthropic`. Settings live in a
temporary directory for this invocation. A direct conversation resumes the
selected provider and alias's session across invocations. The default alias
retains sessions created in v0.1.5. An incoming peer request runs in its own
ephemeral session. Each agent has its own volume.

Pi automatically compacts history when its estimated size crosses the model
window less a reserve of one quarter of that window, capped at 16,384 tokens.
It keeps recent messages up to one third of the window, capped at 20,000.
To read the most recent direct-invocation compaction, send
`{"content":[{"type":"json","json":{"agentcapsule_pi":{"action":"status"}}}]}`.
The command executes locally in the guest. It returns `last_compaction: null`
until a compaction has occurred. A recorded result contains the reason,
outcome and available token counts. Summary text remains in the Pi session.

## Build and verify

The release publisher builds the locked npm dependency tree from the pinned
Node image. The image build exercises real Pi against loopback model and peer
fixtures, including a complete compaction and a subsequent response. Build
both packages from the repository root.

```sh
dagger call pi-agent --release-version 0.1.6 export --path=./build/pi-agent
dagger call corpus-builder --release-version 0.1.6 export --path=./build/corpus-builder
```

For a local development test, set `PI_TEST_BIN` to the absolute path of a Pi
1.5.0 executable and run `node --test examples/pi-agent/profile.test.mjs`.
[Harness registry and signature verification](../../docs/registry.md)
