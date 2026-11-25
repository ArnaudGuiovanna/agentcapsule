# Agent Capsule CLI cheat sheet

[Project README](../README.md) · [Download the PDF](cli-cheatsheet.pdf)

## Install on the server

Open a root shell on the Ubuntu 24.04 x86-64 server that will run the agents. It needs a usable `/dev/kvm`, systemd, cgroup v2 and persistent storage. Have `curl`, `openssl` and a trusted `cosign` 2.4+ on the host. The examples use `jq` to read the installation receipt.

```sh
releases=https://github.com/ArnaudGuiovanna/agentcapsule/releases
curl -fsSLo install-agentcapsule.sh "$releases/latest/download/install.sh" &&
  sh install-agentcapsule.sh --require-signature --dir /usr/local/bin
agentcapsule version
```

For a first test, use the default profile. For production, configure your TLS certificates and off-host backups first and pass `--profile /path/to/profile.json` to `install`. [Host profile](cli-host.md#profile) · [Backup and recovery](recovery.md)

```sh
umask 077
agentcapsule install > install.json
op=$(jq -er '.operation_id' install.json)
agentcapsule host operation wait "$op" > receipt.json
jq '{state, invocation_verified, off_host_backup_verified, url}' receipt.json
```

`state: succeeded` and `invocation_verified: true` confirm that the demo microVM answered. `off_host_backup_verified` reports the separate off-host backup check. Keep `receipt.json` for login.

### Check or repair the host

Run these on the server as root. Replace `HOST_ID` with the returned `operation_id`.

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

For the first local login with the default certificate, use the receipt from installation. The enrollment token is valid once, for 15 minutes. A context saves the API address and the type of account.

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

Use `agentcapsule help` for the command list and `agentcapsule install --help` for installer options. [CLI guide](cli.md) · [Project README](../README.md)
