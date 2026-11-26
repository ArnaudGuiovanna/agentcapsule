# Agent Capsule CLI cheat sheet

[Project README](../README.md) · [Download the PDF](cli-cheatsheet.pdf)

## Install on the server

Install the CLI on the x86-64 Linux server that will run the agents. It needs systemd, cgroup v2, KVM and persistent storage. Have `curl`, `openssl` and a trusted `cosign` 2.4+ available.

```sh
releases=https://github.com/ArnaudGuiovanna/agentcapsule/releases
curl -fsSLo install-agentcapsule.sh "$releases/latest/download/install.sh" &&
  sh install-agentcapsule.sh --require-signature --dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
agentcapsule version
```

**Portable release.** With a matching CLI and the signed userspace archive, run `agentcapsule install` in your terminal. It requests sudo if needed and shows the API URL when the demo agent answers. In production, first configure TLS and off-host backups in a profile. [Host profile](cli-host.md#profile) · [Recovery](recovery.md)

**Native versions v0.1.0 and v0.1.1** require Ubuntu 24.04. For these versions or scripted installs, run the following as a sudo-enabled user. Redirected output delivers an operation ID immediately. The examples use `jq`.

```sh
umask 077
cli=$(command -v agentcapsule)
sudo "$cli" install --json > install.json
op=$(jq -er '.operation_id' install.json)
sudo "$cli" host operation wait "$op" > receipt.json
jq '{state, invocation_verified, off_host_backup_verified, url}' receipt.json
```

Expect `state: succeeded` and `invocation_verified: true`. Off-host backups have their own check. Keep the URL for login.

### Check or repair the host

Run these as root with the CLI in your PATH or prefix them with sudo and the CLI’s absolute path. Replace `HOST_ID` with the returned `operation_id`.

| Command | What it does |
|---|---|
| `agentcapsule host operation show HOST_ID` | Show the current phase immediately. |
| `agentcapsule host operation resume HOST_ID` | Resume a failed operation after fixing its cause. |
| `agentcapsule host diagnose alerts` | Check the state of local services. |
| `agentcapsule host diagnose journal --service worker` | Read worker events when an agent fails to start or respond. |
| `agentcapsule host diagnose backups` | See when each backup repository last succeeded. |
| `agentcapsule update check` | Check for a server update. |
| `agentcapsule update plan` | Check compatibility and get a plan ID. |
| `agentcapsule update apply --plan HOST_ID` | Apply that plan, then follow the returned operation. |

## Sign in and run an agent

### Platform operator

For a local test, the first operator uses the generated certificate and a single-use, 15-minute token. Run the example as root with the CLI in your PATH. Set `api` to the displayed URL or read it from the completed receipt.

```sh
api=$(jq -er '.url' receipt.json)
agentcapsule context add platform --kind platform --url "$api" \
  --ca /etc/agentcapsule/api.crt
agentcapsule --context platform login \
  --enrollment-file /etc/agentcapsule/first-enrollment.token
agentcapsule --context platform status
```

| Command | What it does |
|---|---|
| `agentcapsule --context platform doctor` | Identify which service to investigate. |
| `agentcapsule --context platform organization list` | List the organizations on the platform. |

### Organization administrator and member

The operator creates the organization using its owner's public identity. The owner then signs in with their own key. Select your signed-in organization context with `agentcapsule context use NAME`. [Set up an organization and its owner](cli.md#enroll-the-platform-operator-and-hand-acme-to-its-owner)

| Command | What it does |
|---|---|
| `agentcapsule agent create --file agent.json` | Create one agent from its harness and resource settings. |
| `agentcapsule agent list` | List visible agents and find an agent ID. |
| `agentcapsule assignment grant AGENT --file rights.json` | Give a member or team access. Use `invoke` to ask and `read_content` to read the answer. |
| `agentcapsule agent sleep AGENT` | Stop the microVM and keep the agent's disk. |
| `agentcapsule agent wake AGENT` | Start the microVM with the same disk. |
| `agentcapsule invocation result ID` | Retrieve your stored answer by invocation ID. |

As the assigned member, replace `agt_…` with the ID from `agent list`. This example streams a reply in your terminal.

```sh
agent='agt_…'
agentcapsule agent invoke "$agent" --file - --watch <<'JSON'
{"content":[{"type":"text","text":"Hello!"}]}
JSON
```

For Pi, a PDF corpus, peer requests and model settings, start with `agentcapsule help pi`. [Two-agent walkthrough](pi.md)

Use `agentcapsule help` for the command list and `agentcapsule install --help` for installer options. [CLI guide](cli.md) · [Project README](../README.md)
