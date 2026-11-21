<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/hero-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme/hero-light.png">
    <img alt="Agent Capsule. Agents need capsules. Fleets need control. The open source platform for fleets of AI agents." src="docs/assets/readme/hero-light.png" width="100%">
  </picture>
</p>

<p align="center">
  <strong>The open source platform for fleets of AI agents.</strong><br>
  Each agent runs in its own Firecracker microVM, on infrastructure you control.
</p>

<p align="center">
  <a href="https://github.com/ArnaudGuiovanna/agentcapsule/releases/tag/v0.0.1"><img alt="Release v0.0.1, early" src="https://img.shields.io/badge/release-v0.0.1%20(early)-5B616C?style=flat-square"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-1B1E24?style=flat-square"></a>
  <img alt="Go 1.27.4" src="https://img.shields.io/badge/go-1.27.4-1B1E24?style=flat-square&logo=go&logoColor=F3F4F1">
  <img alt="Runs on Linux with KVM" src="https://img.shields.io/badge/runs%20on-Linux%20%2B%20KVM-1B1E24?style=flat-square">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#what-works-today">What works</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#building-and-testing">Build</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

Agent Capsule is not an AI agent. It is the self-hosted platform that runs a fleet
of them: it treats each agent as a real computing resource, isolated, persistent,
administered and governed.

Every agent gets a **capsule**, a microVM with a private encrypted volume that sleeps
when idle and wakes when work arrives. Organizations manage members, teams and
agents; who may invoke an agent or read its results is decided by explicit
assignments, never by an administrative role. Agents call models through a gateway
that keeps provider credentials outside the VM and enforces budgets. The platform
hosts and governs; the harness you bring decides what the agent does.

> [!WARNING]
> **Version 0.0.1 is out: the first release of the platform and its CLI. It is early and not yet proven on a server.**
>
> - All 65 MVP acceptance criteria are met ([docs/acceptance.md](docs/acceptance.md)): signed import from GHCR and live calls through Ollama with a local model passed on November 19. Anthropic’s hosted API is not part of that live qualification.
> - Every KVM campaign and the CLI's install, upgrade and restore runs have passed, but on a single development machine. No install has run on a production host, and no backup has been restored on a physically separate host.
> - The CLI runs on Linux, macOS and Windows. Outside Linux, only the release workflow's native tests have checked it.
> - The release accepts 12 known findings in third-party packages of the server bundle: Keycloak, and Ubuntu's container runtime. Each is reviewed in [the allowlist](scripts/vulnerability-allowlist.json) until 20 January 2027.
>
> Do not run it in production yet. See [ROADMAP.md](ROADMAP.md).

## Core ideas

| Term | Meaning |
|---|---|
| **Agent** | A durable resource owned by an organization, not a process. Stopping it is not deleting it. |
| **Capsule** | The isolated environment an agent runs in: one Firecracker microVM, one encrypted volume. |
| **Harness** | The software that runs inside the capsule, in any language, shipped as a signed OCI package. |
| **Invocation** | A task sent to an agent, queued, delivered in order and answered privately. |
| **Assignment** | The explicit permission for someone to see, invoke or read an agent. |
| **Mandate** | A bounded authorization for one agent to delegate work to another. |

## Install

**1. The CLI, on your workstation** (Linux or macOS; on Windows, Git Bash):

```sh
curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh
agentcapsule version
```

The script downloads the executable for your system from the latest release. It installs it in `~/.local/bin` (`/usr/local/bin` as root) only if its digest matches the release's `SHA256SUMS`. When [cosign](https://github.com/sigstore/cosign) is on your PATH, it also checks that `SHA256SUMS` was signed by this repository's release workflow for that tag. Append `-s -- --require-signature` to `sh` to make the signature mandatory, or `-s -- --version v0.0.1` to pin a release. [Verify by hand](docs/release.md#verify-a-release)

**2. The platform, on an Ubuntu 24.04 amd64 host with KVM and systemd.** Run it from the workstation over SSH (the account needs non-interactive sudo), or as root on the host:

```sh
agentcapsule install --ssh admin@host --plan-only   # checks the host and the signed release
agentcapsule install --ssh admin@host               # installs, prints an operation ID
agentcapsule host operation wait OPERATION_ID --ssh admin@host
```

The CLI installs the signed server bundle of its own release: PostgreSQL, the API, the worker, the patched Firecracker, the guest image, Keycloak, Directory, SLIM and the backups. A reboot or a dropped SSH session does not lose the installation: it resumes. The result proves each step separately: services started, a starter microVM answered, backups configured. TLS names, certificates, storage and an external PostgreSQL are set in a profile. [Host guide](docs/cli-host.md)

**3. Administer it** from the workstation over HTTPS. The host keeps a single-use enrollment token for the first platform operator in `/etc/agentcapsule/first-enrollment.token`. With the default self-signed certificate, the CA to trust is `/etc/agentcapsule/api.crt`:

```sh
agentcapsule context add prod --url https://agents.example.org:9443 --kind platform --ca api.crt
agentcapsule --context prod login --enrollment-file first-enrollment.token
agentcapsule --context prod status
agentcapsule --context prod doctor
agentcapsule --context prod organization create --name Acme --owner-file acme-owner.json --idempotency-key create-acme
```

Commands cover organizations, quotas, members, teams, agents and deployments, LLM providers and budgets, harness imports, audit, backups and restores (`agentcapsule help`). Host updates and the CLI's own update use the signed releases as well:

```sh
agentcapsule update check
agentcapsule update plan --to vX.Y.Z
agentcapsule update apply --plan OPERATION_ID
agentcapsule self update
```

[Administration guide](docs/cli.md)

## What works today

**Run**

- **Capsules**: cold creation, wake/sleep/delete with guest-acknowledged quiescence,
  one writer generation per volume, encrypted volumes, jailed Firecracker VMMs,
  crash recovery of the worker and of PostgreSQL.
- **Invocations**: idempotent admission, per-agent FIFO delivery, TTLs, queue limits,
  dead letters, scheduled invocations, idle closure, and private results that only
  the requester can read. Agents that need to call the platform answer `working` and
  post their result later.
- **Attachments**: files up to 8 MiB, encrypted per segment, usable once by their
  uploader, readable from the guest while the invocation runs, purged afterwards.
- **Limits**:
  - **Ceilings**: each VM has CPU, memory, process and disk ceilings (cgroups and Firecracker rate limiters), tested against hostile guests on KVM.
  - **Restart budget**: a guest that crashes, or never answers an invocation, is stopped and the failure counted. An agent that spends its budget (5 failures an hour by default) becomes `FAILED`, with the reason.
  - **Network**: VMs have no network device. Models and peers are reached only through the platform.
- **Capacity**: work that finds its host full waits in a per-host queue for a VM slot, within its organization's quotas. Idle agents sleep, and a VM that is computing is never stopped to make room.

**Govern**

- **Organizations and access control**: organizations, members, teams, roles, service
  accounts, and per-agent assignments (`read_metadata`, `invoke`, `read_content`).
  Users authenticate with delegated JWTs from the organization's identity provider.
- **LLM gateway**: OpenAI-compatible and Anthropic providers, model aliases,
  encrypted provider credentials, hard/soft token budgets, usage reports.
- **Harness registry**: harness packages are imported from approved OCI registries
  (public or private) by digest, checked against trusted publisher signatures (cosign
  format), cached read-only and published as immutable releases; agents on a release
  share its image, attached read-only and run chrooted in the guest. Agents can be
  upgraded and rolled back, and unused packages leave the cache.

- **Keys**:
  - Volume keys and the restore authority are held by a separate authority service, which can be replicated to a standby host.
  - A deleted agent's key is destroyed only once its store is sealed.
- **Audit**: an audit trail per organization, with exports. Traces carry no raw identifier.

**Operate**

- **Backups and recovery**:
  - PostgreSQL WAL is archived continuously.
  - Each agent's encrypted volume is archived nightly, while it sleeps.
  - Both are shipped off the host to S3 or SFTP.
  - An agent can be restored from its archive, or a lost host's agents on a standby. Both kinds of restore are verified against the restore authority.
  - The objectives are 15 minutes of database loss, 24 hours of volume loss and 1 hour to recover ([ADR 004](docs/adr/004-recovery-objectives.md), [docs/recovery.md](docs/recovery.md)).
- **Monitoring**:
  - Prometheus metrics and alerts: hosts, queues, boots, storage pressure, Directory and SLIM.
  - Garbage collection of unused harness images.
  - A capacity benchmark ([docs/observability.md](docs/observability.md)).
- **Supply chain**:
  - Reproducible release builds with SBOMs, a signed checksums file and build provenance.
  - Signed harness packages.
  - Vulnerability scans of everything shipped.
  - A High or Critical finding fails CI unless a reviewed entry allowlists it until a fixed date ([docs/release.md](docs/release.md)).
- **Host hardening**:
  - Harness images are inspected in a sandbox under a dedicated account.
  - Network hops use TLS, except two that never leave the host. Local hops are Unix sockets that check the peer's account.
  - The host passes a preflight check before the worker starts ([docs/install.md](docs/install.md)).

**Connect**

- **Inter-agent requests** with recipient consent and bounded mandates, over A2A,
  the AGNTCY Directory and SLIM ([docs/interop.md](docs/interop.md)).
- **Harnesses in any language**: Go, or Python with the
  [Python SDK](sdk/python/README.md).
- **Unmodified agents**: `capsule-adapter` runs an existing agent's command for each
  invocation and serves the OpenAI and Anthropic APIs on the VM's loopback, so the
  agent's own SDK reaches the organization's models through the platform, tools
  included, with no credential in the VM ([docs/adapter.md](docs/adapter.md)).

## Architecture

```
            HTTPS (delegated JWT, idempotency keys)
 clients ─────────────────────────────► agentcapsule-api ──┐
                                                           │
                                         PostgreSQL ◄──────┤  control plane
                                                           │  (organizations, queues,
                                       agentcapsule-worker ┘   transit, budgets)
                                          │   │
                     control channel      │   │  platform channel (guest → host:
                     (host → guest:       │   │  peers, LLM, attachments, results)
                      invoke, quiesce)    ▼   ▲
                                   ┌──────────────────────────┐
                                   │ Firecracker microVM      │
                                   │  capsule-init (PID 1)    │
                                   │  harness (agent runtime) │
                                   │  encrypted data volume   │
                                   └──────────────────────────┘
```

| Binary | Role |
|---|---|
| `agentcapsule` | The CLI, for Linux, macOS and Windows. It installs, updates and restores a host, and administers the platform over HTTPS ([docs/cli.md](docs/cli.md)). |
| `agentcapsule-api` | The HTTP API ([OpenAPI 3.1](openapi/openapi.yaml)). |
| `agentcapsule-worker` | Places and supervises VMs, delivers work, serves the platform channel, provisions encrypted volumes. |
| `agentcapsule-admin` | Local, trusted installation commands (bootstrap, keys, host configuration). No network listener. |
| `agentcapsule-authority` | The replica of the key and restore authorities on the standby host ([recovery.md](docs/recovery.md#the-authorities-replica-d-05)). |
| `agentcapsule-harness` | Builds and publishes harness packages (developer/CI tool). |
| `agentcapsule-slim-bridge` | Carries deliveries between agents through a private SLIM node ([its own module](runtime/slimbridge), [docs/interop.md](docs/interop.md#the-slim-bridge-int-04)). |
| `capsule-init` | PID 1 in the guest; holds boot credentials and volume secrets away from the harness and relays its platform calls. |
| `capsule-adapter` | Runs an unmodified agent as a harness (command per invocation, model endpoint on the guest loopback). |
| `capsule-echo` | The reference harness used by tests. |

The delivery, messaging, lifecycle, revocation and deferred-result protocols are
specified as [Quint models](spec/), and traces from those models are replayed
against the implementation in the test suite. The models are also checked
exhaustively, within bounds, with TLC and Apalache: 131 of 134 checks end as
expected and none finds a counterexample. The other three do not finish on a
12-core machine ([spec/README.md](spec/README.md)).

## Requirements

- Linux amd64 with KVM, a kernel 5.14 or later (6.1 or 6.18 preferred) and cgroup v2
  (for running capsules; `agentcapsule-worker -preflight` checks the host), Go **1.27.4**, a C compiler and the
  `libcryptsetup` headers (cgo), PostgreSQL 16 or newer.
- Firecracker 1.17.0 with the volume-lock patch in [runtime/firecracker](runtime/firecracker),
  a guest kernel built from [runtime/guest](runtime/guest), and the guest image built
  by `scripts/build-product-guest.py`.

## Building and testing

The worker links `libcryptsetup.so.12` by its file name, a flag Go refuses
unless `CGO_LDFLAGS_ALLOW` allows it. Allow it once; the scripts set it
themselves.

```bash
go env -w CGO_LDFLAGS_ALLOW='-l:libcryptsetup\.so\.12'
go build ./cmd/...
go test -race ./...            # PostgreSQL-backed tests skip without a database
```

The test runners create their own throwaway environments and never touch an
existing database:

```bash
# Full integration on a private PostgreSQL cluster, with WAL crash recovery
python3 scripts/verify-postgres.py --pg-bin /usr/lib/postgresql/16/bin --native-tools /

# Optional: live LLM checks against a local OpenAI-compatible server (e.g. Ollama)
python3 scripts/verify-postgres.py --pg-bin /usr/lib/postgresql/16/bin --native-tools / \
  --llm-base-url http://127.0.0.1:11434/v1 --llm-model tinyllama:latest
```

KVM campaigns run real jailed VMs and need root for the jailer and cgroups.
They are described in [scripts/README.md](scripts/README.md):
- `verify-product-guest.py` runs the product scenarios, conformance and a capacity benchmark at 1, 5, 10 and 20 VMs;
- `verify-runtime.py` runs the host driver and the worker's control tests.

`scripts/check-models.py` runs the TLC and Apalache checks of the models. It is a release check of about 16 hours. Every MVP requirement is traced to the tests that prove it in [docs/acceptance.md](docs/acceptance.md).

## Running

Install a host with the CLI from a release, as described in [Install](#install). No install has run on a production host yet. [docs/install.md](docs/install.md#what-a-real-host-still-has-to-show) lists what a real host still has to show. To assemble a host by hand, or from source, use these building blocks:

- [docs/install.md](docs/install.md): TLS on every hop, production and
  development modes, and the host preflight.
- [docs/bootstrap.md](docs/bootstrap.md): from an empty database to an
  organization whose first owner signs in.
- [docs/api/README.md](docs/api/README.md): API server and its routes.
- [docs/api/tenant-identity.md](docs/api/tenant-identity.md): trusting an
  organization's identity provider.
- [docs/worker.md](docs/worker.md): worker configuration
  ([example](runtime/worker/config.example.json)), maintenance and delivery.
- [docs/guest/](docs/guest/): guest image, control contract, keys and volumes.
- [docs/recovery.md](docs/recovery.md) and [deploy/](deploy/): backups, the standby
  host, systemd units and Prometheus alerts.

Example harnesses live in [examples/](examples/): `python-echo`, `go-echo`, an
OpenAI SDK agent run unchanged (`adapted-agent`), the Pi coding agent (`pi-agent`)
and an A2A agent (`a2a-agent`).

## Documentation

| Topic | Where |
|---|---|
| Product goals and MVP requirements | [docs/product.md](docs/product.md) |
| The CLI: installing a host, administering the platform | [docs/cli-host.md](docs/cli-host.md), [docs/cli.md](docs/cli.md) |
| Status and remaining work | [ROADMAP.md](ROADMAP.md) |
| MVP acceptance, requirement by requirement | [docs/acceptance.md](docs/acceptance.md) |
| Metrics, alerts, traces and audit | [docs/observability.md](docs/observability.md) |
| Worker: capacity, limits, adoption, deletion | [docs/worker.md](docs/worker.md) |
| HTTP API | [openapi/openapi.yaml](openapi/openapi.yaml), [docs/api/](docs/api/) |
| Agents, assignments, invocations, attachments, deferred results | [docs/api/agents-assignments.md](docs/api/agents-assignments.md) |
| LLM gateway | [docs/api/llm.md](docs/api/llm.md) |
| Streaming model responses and invocation output | [Guest protocol](docs/guest/capsule-control.md), [streaming plan](docs/plan-streaming.md) |
| Building, publishing and reading a corpus from any harness | [Corpus format and guest examples](docs/corpus.md), [corpus API](docs/api/corpora.md) |
| Harness packages, publishing and imports | [docs/registry.md](docs/registry.md) |
| Running an existing agent unchanged | [docs/adapter.md](docs/adapter.md) |
| Guest runtime and the `capsule.v1` contract | [docs/guest/](docs/guest/) |
| Interoperability profile (A2A, OASF, Directory, SLIM) | [docs/interop.md](docs/interop.md) |
| Installing a host: TLS, modes, preflight | [docs/install.md](docs/install.md) |
| Backup, restore and recovery | [docs/recovery.md](docs/recovery.md) |
| Architecture decisions | [docs/adr/](docs/adr/) |
| Formal models | [spec/](spec/) |
| Build, test and verification scripts | [scripts/README.md](scripts/README.md) |
| Releases: audit, signing, SBOMs, verification | [docs/release.md](docs/release.md) |

<details>
<summary><strong>Repository layout</strong></summary>

```
cmd/          binaries (api, worker, admin, authority, harness tool, capsule-init, capsule-echo, capsule-adapter)
internal/     Go packages: controlplane, api, worker, runtime, capsuleprotocol, ...
openapi/      canonical OpenAPI 3.1 contract
spec/         Quint protocol models
docs/         product, API, guest, worker and interop documentation, ADRs
runtime/      Firecracker patch, guest kernel config, example configs, interop qualification
deploy/       private interoperability services, backup, standby, monitoring and systemd units
scripts/      builds, CI checks and KVM/PostgreSQL verification campaigns
sdk/python/   Python harness SDK (capsule.v1, standard library only)
sdk/go/       Go helpers for reading a mounted corpus
examples/     example harnesses and adapted agents
install.sh    the CLI installer (curl | sh), published with each release
.dagger/      reference Dagger module: builds, publishes, signs and verifies harnesses
```

</details>

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first; report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Harnesses keep their own license.
