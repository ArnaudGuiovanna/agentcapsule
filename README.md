<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/hero-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme/hero-light.png">
    <img alt="Agent Capsule. Agents need capsules. Fleets need control. The open source platform for fleets of AI agents." src="docs/assets/readme/hero-light.png" width="100%">
  </picture>
</p>

# Agent Capsule

Agent Capsule is a self-hosted platform as a service (PaaS) for running persistent AI agents on a Linux server. An organization deploys an agent program, assigns it to users or teams, and controls its model access, spending limits and document collections. The platform runs each active agent in a dedicated Firecracker microVM. Its encrypted data volume survives shutdown and is reattached when the agent wakes.

[Releases](https://github.com/ArnaudGuiovanna/agentcapsule/releases) · [CLI cheat sheet (PDF)](docs/cli-cheatsheet.pdf) · [HTTP API](docs/api/README.md) · [Operator CLI](docs/cli.md) · [MIT license](LICENSE)

## Platform capabilities

| Function | What the platform provides |
|---|---|
| Agent deployment | Import a signed harness package from an OCI registry and pin each agent to its digest. A harness is the program that handles requests inside the VM. An existing command-line program can use the adapter. The protocol supports implementations in any language. |
| Compute and storage | Start a microVM on demand, set its CPU and memory, and stop it between requests. Each agent has its own encrypted writable volume. Harness images and published document collections can be shared read-only. |
| Identity and access | Keep agents, credentials and budgets within an organization. Assign invocation rights to members, teams or service accounts. The API checks access again when a caller reads a result. |
| Requests and streaming | Submit an invocation over HTTPS, follow its output through Server-Sent Events and resume from the last event ID after a disconnect. The caller can retrieve the stored result by invocation ID. |
| Model access and budgets | Route model requests through the platform gateway. The organization configures provider credentials, model aliases and budgets. The gateway meters usage and keeps provider credentials outside the guest. |
| Document collections | Build a versioned corpus from a Git commit, review the conversion report, then publish it. Agents mount the selected version with Markdown and a searchable SQLite index. OCR and transcription use separately configured services. |
| Agent-to-agent tasks | Discover authorized peers in a private directory and delegate work under an acceptance policy. The platform can wake the receiving agent, deliver the task and retain its result. |

## Deployment profile

| Component | Requirements and interfaces |
|---|---|
| Server | One x86-64 Linux host with KVM, systemd, cgroup v2 and persistent local storage. The v0.1.0 and v0.1.1 server bundles require Ubuntu 24.04. The reference configuration is 8 vCPU, 24 GB RAM and 200 GB NVMe. |
| Control plane | HTTPS API, PostgreSQL and a worker that manages Firecracker. Operators install and maintain the platform on the host with the CLI. Applications use the API to provision and invoke agents. |
| Administration | CLI for Linux, macOS and Windows on amd64 and arm64. It supports installation plans, diagnostics, updates, backup checks and restore tests. |
| Recovery | Configure off-host backups for the database and agent volumes. The reference deployment has one host. Production-host qualification and recovery between two physical hosts remain open. |

## Installation

Download the CLI on the machine that will run the agents. The installer needs `curl` and `openssl`. It verifies the release signature with your `cosign` 2.4 or later, or with a pinned cosign that it downloads and checks when none is installed.

```sh
releases=https://github.com/ArnaudGuiovanna/agentcapsule/releases
curl -fsSLo install-agentcapsule.sh "$releases/latest/download/install.sh" &&
  sh install-agentcapsule.sh --require-signature --dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
agentcapsule version
```

**With the v0.1.0 or v0.1.1 CLI**, run these commands on Ubuntu 24.04. Replace `HOST_ID` with the `operation_id` printed by the first command.

```sh
sudo "$(command -v agentcapsule)" install
sudo "$(command -v agentcapsule)" host operation wait HOST_ID
```

**With the portable installer on this branch**, a matching release must include the signed asset `agentcapsule-userspace-linux-amd64.tar.gz`. Run the following in your normal terminal on the Linux server.

```sh
agentcapsule install
```

The CLI requests sudo when needed, starts the platform services and waits for the demonstration agent to answer. The terminal shows the API URL. In scripts, run as root with `--json` to obtain an operation ID immediately. The completed receipt reports `state: succeeded` and `invocation_verified: true`. The demonstration works without a model-provider key. [Host requirements and installation modes](docs/cli-host.md) · [CLI cheat sheet](docs/cli-cheatsheet.md)

## Technical documentation

- **Integration** — [HTTP API and examples](docs/api/README.md), [harness adapter](docs/adapter.md), [example harnesses](examples/).
- **Data and operations** — [two Pi agents with a shared PDF corpus](docs/pi.md), [corpus format and publication](docs/corpus.md), [metrics and alerts](docs/observability.md), [backup and recovery](docs/recovery.md).
- **Project** — [acceptance test matrix](docs/acceptance.md), [roadmap](ROADMAP.md), [contribution guide](CONTRIBUTING.md), [security reporting](SECURITY.md).
