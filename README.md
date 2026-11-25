<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/hero-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme/hero-light.png">
    <img alt="Agent Capsule. Agents need capsules. Fleets need control. The open source platform for fleets of AI agents." src="docs/assets/readme/hero-light.png" width="100%">
  </picture>
</p>

# Agent Capsule

Agent Capsule is a self-hosted platform as a service (PaaS) for running persistent AI agents on a Linux server. An organization deploys an agent program, assigns it to users or teams, and controls its model access, spending limits and document collections. The platform runs each active agent in a dedicated Firecracker microVM. Its encrypted data volume survives shutdown and is reattached when the agent wakes.

[Releases](https://github.com/ArnaudGuiovanna/agentcapsule/releases) · [HTTP API](docs/api/README.md) · [Operator CLI](docs/cli.md) · [MIT license](LICENSE)

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
| Server | One Ubuntu 24.04 x86-64 host with KVM, systemd, cgroups v2 and persistent local storage. The reference configuration is 8 vCPU, 24 GB RAM and 200 GB NVMe. |
| Control plane | HTTPS API, PostgreSQL and a worker that manages Firecracker. Operators install and maintain the host over SSH. Applications use the API to provision and invoke agents. |
| Administration | CLI for Linux, macOS and Windows on amd64 and arm64. It supports installation plans, diagnostics, updates, backup checks and restore tests. |
| Recovery | Configure off-host backups for the database and agent volumes. The reference deployment has one host. Production-host qualification and recovery between two physical hosts remain open. |

## Installation

The following commands install the CLI on an administration workstation and request an installation plan for a test server. Use a POSIX shell, `curl`, `openssl` and a trusted installation of `cosign` 2.4 or later: the installer refuses to continue without them. Replace `admin@host.example.org` with an SSH account that can run `sudo -n` on the server. The plan reports host compatibility before installation. [Manual installation and signature verification](docs/release.md#verify-a-release)

```sh
curl -fsSLo install-agentcapsule.sh https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh
sh install-agentcapsule.sh --dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
agentcapsule version
agentcapsule install --ssh admin@host.example.org --plan-only
```

The host installation checks the deployment by starting the bundled demonstration agent and verifying an invocation. It requires no model-provider key. [Host installation and first invocation](docs/cli-host.md) · [Step-by-step operator guide in French](docs/guide-sysadmin.md) · [French sysadmin manual for v0.1.1 (PDF)](docs/releases/v0.1.1/manuel-sysadmin.pdf)

## Technical documentation

- **Integration** — [HTTP API and examples](docs/api/README.md), [harness adapter](docs/adapter.md), [example harnesses](examples/).
- **Data and operations** — [corpus format and publication](docs/corpus.md), [metrics and alerts](docs/observability.md), [backup and recovery](docs/recovery.md).
- **Project** — [acceptance test matrix](docs/acceptance.md), [roadmap](ROADMAP.md), [contribution guide](CONTRIBUTING.md), [security reporting](SECURITY.md).
