# Run two Pi agents with a shared corpus

The CLI installs the PaaS on the server. The Pi commands require matching CLI and server builds from the v0.1.6 series with a signed Pi catalog. Upgrade a v0.1.5 installation before using them. Pi and the PDF converter are optional signed packages. Each Pi gets a private writable workspace and a read-only view of the selected corpus version. The commands below use Bash and jq.

## Install the host and enable its optional packages

Run these commands on the Linux/KVM server. An existing host can follow the signed update procedure. Keep its current organization and agent IDs when upgrading. [Installation and upgrades](cli-host.md)

```sh
curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh
agentcapsule install
agentcapsule host pi enable --corpus-repo ArnaudGuiovanna/compagnon > pi-host.json
```

The last command asks for sudo in a local terminal and writes the receipt to the redirected file. For unattended runs, execute it as root or use `--ssh USER@HOST` with noninteractive sudo. It reads the catalog in the installed release, authorizes the two exact package digests from GHCR and allows the named GitHub repository as a corpus source. It configures the builder and restarts the worker when its settings change. The official packages can each use up to 2 GiB. Other registry rules retain their own keys and size limits. Rerun the command with another repository to add a source. Existing agents keep their private volumes.

Enroll a platform operator and create an organization with an owner as described in the CLI guide. The commands below use `platform` for the operator context and `learning` for the organization context. Set quotas for two simultaneously active Pi VMs, the temporary builder and their storage. The default Pi template uses one vCPU, 1 GiB RAM and 1 GiB of persistent disk per agent. Build the corpus before starting the two Pi agents on a small host. [Contexts, enrollment and quotas](cli.md#enroll-the-platform-operator-and-hand-acme-to-its-owner)

```sh
agentcapsule --context platform pi import --file pi-host.json
release=$(jq -er .release pi-host.json)
agentcapsule context use learning
```

The import prints the two import IDs and waits until both signed packages are ready. An interrupted import can be resumed by repeating the command. Use `registry show IMPORT_ID` in the platform context to inspect one download.

## Connect the model and publish the PDF corpus

Supply the API key in a private file containing only its value. Replace the endpoint and model with those provisioned for your account. Reuse the returned alias for both agents.

```sh
provider=$(agentcapsule provider create --name ovh --kind openai_compatible \
  --base-url "$MODEL_ENDPOINT" --auth-mode secret --secret-file "$MODEL_KEY_FILE" \
  --idempotency-key learning-provider-1 | jq -er .data.id)
agentcapsule alias create --alias pi-model --upstream-model "$MODEL_NAME" --provider-id "$provider" \
  --idempotency-key learning-alias-1 --file - <<'JSON'
{"access":"listed"}
JSON
agentcapsule corpus create compagnon --git https://github.com/ArnaudGuiovanna/compagnon \
  --ref main --idempotency-key learning-corpus-1
build=$(agentcapsule corpus build compagnon --ref main --idempotency-key learning-build-1 | jq -er .data.id)
agentcapsule operation wait --type corpus-build "$build"
agentcapsule corpus-build files "$build"
agentcapsule corpus-build index "$build"
agentcapsule corpus-build publish "$build" --version 1 --idempotency-key learning-publish-1
```

Review the conversion results before publishing. A new source repository needs an `agentcapsule-corpus.yaml` at its root. The author can create it with `agentcapsule corpus init DIR` and check it with `agentcapsule corpus lint DIR`. [Corpus format](corpus.md)

## Create the agents and grant access

Use `--a2a` to allow this template to request peer discovery and delegation, subject to the organization's capability policy. Omit the flag for agents that only need the corpus and model.

```sh
template=$(agentcapsule pi template lesson --release "$release" --alias pi-model \
  --corpus compagnon --corpus-version 1 --a2a --idempotency-key lesson-template-1 | jq -er .data.reference)
plan=$(agentcapsule deployment plan --template "$template" --count 2 --active-count 2 \
  --idempotency-key lesson-plan-1 | jq -er '.data | select(.admitted) | .id')
agentcapsule deployment apply --plan "$plan" --idempotency-key lesson-apply-1
agentcapsule operation wait --type deployment "$plan"
agentcapsule agent list
agentcapsule member list
```

Set `PI1` and `PI2` to the two agent IDs, and `MEMBER` to the invoking member's principal ID. Grant the member access. The organization owner also needs an assignment to invoke an agent and read its content.

```sh
for agent in "$PI1" "$PI2"; do
  jq -n --arg p "$MEMBER" '{principal_id:$p,permissions:["invoke","read_content","read_metadata"]}' |
    agentcapsule assignment grant "$agent" --file - --idempotency-key "lesson-access-$agent"
done
agentcapsule agent corpora "$PI1"
agentcapsule agent invoke "$PI1" --file - --watch --text <<'JSON'
{"content":[{"type":"text","text":"Read the Compagnon corpus and write a summary to compagnon.md in your workspace, then read it back."}]}
JSON
```

Each agent can read, write, edit and remove its own workspace files. Deleting a file in PI1's workspace affects only PI1.

## Upgrade two existing Pi agents

After the host update, run `host pi enable` and `pi import` as above. Existing agents keep their harness until an operator selects another release. If PI1 and PI2 already have a published corpus, their model grant and member assignments, keep their IDs and bindings. Back up their volumes and finish any active work before restarting them. [Backup and recovery](recovery.md)

Use an organization context authorized to manage and operate the agents. The example upgrades one agent at a time. The release command prints a receipt with the previous harness and the harness selected for the next boot. The sleep and wake commands each return an operation ID.

```sh
(
  set -euo pipefail
  release=$(jq -er .release pi-host.json)
  for agent in "$PI1" "$PI2"; do
    jq -n --arg v "${release#v}" '{harness:{name:"pi-agent",version:$v}}' |
      agentcapsule agent release "$agent" --file - > "upgrade-$agent.json"
    for action in sleep wake; do
      op=$(agentcapsule agent "$action" "$agent" | jq -er .data.operation_id)
      agentcapsule operation wait "$op"
    done
    agentcapsule agent corpora "$agent"
    agentcapsule pi status "$agent"
  done
)
```

To enable delegation on an older agent that was limited to model and streaming calls, first review `agentcapsule agent capabilities "$PI1"`. The following command adds the two peer capabilities to PI1's own policy. Repeat for PI2 if it should initiate requests too. A receiver can review requests under manual consent.

```sh
agentcapsule agent capabilities "$PI1" |
  jq -e '.data.agent | select(type == "array") | {allowed: (. + ["agents.discover","agents.delegate"] | unique)}' |
  agentcapsule agent set-capabilities "$PI1" --file -
```

## Send a question to the second agent

Make PI2 visible to the organization and choose manual consent. Inspect the effective capabilities of PI1. Its organization, template and harness all need to allow the capabilities used by the request. On a host with a restricted organization policy, the owner can inspect the allowed list with `agentcapsule organization capabilities`. To add peer discovery and delegation for that organization while retaining its current permissions, run the following in its owner context.

```sh
agentcapsule organization capabilities |
  jq -e '.data.allowed | select(type == "array") | {allowed: (. + ["agents.discover","agents.delegate"] | unique)}' |
  agentcapsule organization set-capabilities --file -
```

```sh
agentcapsule agent capabilities "$PI1"
agentcapsule directory set "$PI2" --file - <<'JSON'
{"visible":true,"description":"Reviews learning material","skills":[10302],"domains":[111]}
JSON
agentcapsule communication configure "$PI2" --file - <<'JSON'
{"mode":"manual"}
JSON
jq -n --arg id "$PI2" '{content:[{type:"text",text:("Ask agent "+$id+" to review the first point of the Compagnon corpus. Give me the request ID.")}]}' |
  agentcapsule agent invoke "$PI1" --file - --watch --text
agentcapsule communication held "$PI2"
```

Copy the request ID into `REQUEST`. Consent can be given while PI1 is still watching, from a second terminal. To refuse the request, use `communication decline` in place of `accept`.

```sh
agentcapsule communication accept "$PI2" "$REQUEST"
agentcapsule communication explain "$PI2" "$REQUEST"
jq -n --arg id "$PI2" --arg req "$REQUEST" '{content:[{type:"text",text:("Read the reply from "+$id+" for request "+$req+" using agent_request_status.")}]}' |
  agentcapsule agent invoke "$PI1" --file - --watch --text
```

An invocation ID is printed to stderr when watching text. A manager can run `invocation show INVOCATION_ID` to see requests linked to that invocation. An empty `peer_requests` means that the PaaS has recorded no request under its mandate. Use `invocation list "$PI1" --state failed` to recover an earlier ID.

## Choose a context window

The supplied harness uses the `pi-model` alias for incoming peer requests and for direct invocations without a profile. Its defaults are 32,000 context tokens and 1,024 output tokens. The following example stores a local profile in the selected organization context. Choose values supported by the upstream model and its deployment. Pass the profile on each direct invocation that should use those settings. A different alias also needs a model grant for that agent.

```sh
agentcapsule pi profile set pi-model --provider capsule-openai --context-window 64000 --max-output-tokens 2048
agentcapsule pi profile show pi-model
agentcapsule agent invoke "$PI1" --pi-profile pi-model --file request.json --watch --text
agentcapsule pi status "$PI1"
```

Pi compacts older history automatically. The status command waits for the harness and reads the latest observed compaction and available token counts. It needs the member's `invoke` and `read_content` assignments and works when streaming is disabled. Use `--text` for the raw JSON document. A fresh session can report `null`. The gateway also limits a forwarded request to 960 KiB of encoded data. A token window and a byte limit measure different things.
