# Roadmap

Agent Capsule is **pre-MVP**. The core path works and is validated on real KVM: an
organization creates an agent, a member sends it an invocation with an encrypted
attachment, the agent runs in its own Firecracker microVM, reads the file and calls
its model through the platform channel, and posts a result only that member can
read. Two organizations run side by side on one host without seeing each other's
agents, files, models or audit trail. Existing agents run unchanged through
`capsule-adapter`: an OpenAI SDK agent, and Pi, the coding agent, on a real model.
Visible agents are published to a private AGNTCY Directory and searchable by skill,
and an adapted agent reaches the other agents of its organization as A2A agents,
across a SLIM node through the platform's bridge: an agent finds another by
its skill, wakes it and gets its answer, also with the Directory or SLIM down
(gate G2). Large parts of the MVP described in [docs/product.md](docs/product.md)
are still missing, notably observability and a restore procedure.

Status words used below:

| Status | Meaning |
|---|---|
| **Done** | Implemented and validated at the level the item requires |
| **In progress** | Implemented for the main path; remaining work listed |
| **Partial** | A meaningful part exists; significant work remains |
| **Not started** | Nothing beyond design notes |

Validation levels: Go unit and race tests; real PostgreSQL integration with WAL
crash recovery; KVM campaigns with jailed Firecracker VMs (see
[scripts/README.md](scripts/README.md)); live LLM tests against a local
OpenAI-compatible server; Quint models in [spec/](spec/). None of this has been run on
a production host yet.

## Foundations

| ID | Item | Status | Remaining |
|---|---|---|---|
| BASE-01 | Pinned Go toolchain, CI on current packages, repository hygiene | Done | — |
| API-01 | Shared API conventions, canonical OpenAPI 3.1 document | Partial | Remaining endpoint families (events, registry, interop) |
| API-02 | Admin CLI, HTTP examples, redacted diagnostics | Partial | Diagnostic export, guarded destructive commands |
| OPS-01 | Validated configuration, separate secrets, preflight, mock vs production install | Partial | TLS everywhere, private Directory/SLIM, pinned versions, preflight on a target host |
| OPS-02 | Metrics (Prometheus/OpenTelemetry), correlation IDs, redacted logs, alerts: `/metrics` on loopback for the API (route, status, latency) and the worker (jobs, retry reasons, boots, queue delay, capacity, disk), JSON events from closed vocabularies, `X-Request-ID` in each request's event, in the operations it creates and in the worker's events for every job it causes (agent-to-agent requests included), alert rules checked and unit-tested by promtool in CI ([docs/observability.md](docs/observability.md)) ; validated on KVM (worker metrics and job events in the A2A journey) | Done | — (distributed traces with spans: later) |
| OPS-03 | Host capacity, sparse disks, retention/GC, pressure thresholds, scheduler under load | Partial | Thresholds and alerts, load tests |

## Organizations and identity

| ID | Item | Status | Remaining |
|---|---|---|---|
| TEN-01 | Versioned migrations; organizations, principals, memberships, teams, assignments | In progress | — (follows new features) |
| TEN-02 | Delegated identity (JWT from the customer's IdP) bound to the database authority | In progress | Operator tooling for trust rotation |
| TEN-03 | RBAC for five roles; administration separate from invoke/read-content rights | Partial | Remaining routes and result/inbox filters |
| TEN-04 | Members, teams, assignments, revocation, organization disable | In progress | Reassignment to another target; admission/reassignment races |
| TEN-05 | Tenant agents and the per-organization data model; peer requests and agent search confined to one organization; two organizations validated side by side on KVM | Done | — |
| TEN-06 | Service accounts and audit | Partial | Audit export and retention |
| TEN-07 | Quotas and reservations (agents, VMs, CPU/RAM, disk, queues, LLM, storage) | Partial | Physical limits (CAP-03) and load behavior (OPS-03) |

## Capsules and runtime

| ID | Item | Status | Remaining |
|---|---|---|---|
| CAP-01 | Private `capsule.v1` contract, typed envelope, platform channel (peers, LLM, attachments, deferred results); Go and Python harnesses | Partial | Capability negotiation against tenant policy; events |
| CAP-02 | Cold create, desired/observed state, wake/sleep/delete, reconciliation, single RW generation | Partial | Automatic restart policy for agents that should be running |
| CAP-03 | Jailer/cgroups hardening, egress control, CPU/RAM/IO/pid/time limits, bounded restarts | Partial | Egress profiles, IO limits, restart budgets |
| CAP-04 | Unmodified agents ([docs/adapter.md](docs/adapter.md)): `capsule-adapter` runs the agent's command for each invocation and serves the OpenAI and Anthropic APIs on the guest loopback, forwarded as written (tools included) through the metered platform channel; `dagger call adapt` packs an existing image; official SDKs qualified against a real model (validated on KVM) | Done | — (A2A between agents and A2A server agents: INT-03) |

## Invocations and events

| ID | Item | Status | Remaining |
|---|---|---|---|
| EVT-01 | Invocations: admission by assignment, private results, deferred results (`working`) with one outcome among completion, timeout, cancellation and deletion | Partial | `/events` stream, structured JSON content in the guest protocol |
| EVT-02 | Queue TTL, per-agent and per-organization depth limits, dead letters, retries | Partial | Re-admission after capacity returns, operator replay of dead letters |
| EVT-03 | Scheduled invocations, idle closure policy | Partial | Recurring schedules |
| EVT-04 | Encrypted attachments: upload, single use, reading from the guest, quota, purge | Partial | Files as results, external object storage, temporary links |

## LLM gateway

| ID | Item | Status | Remaining |
|---|---|---|---|
| LLM-01 | Providers, aliases, encrypted credentials kept out of VMs, rotation, audit | In progress | Per-agent/team alias access, dedicated secret store (D-05) |
| LLM-02 | OpenAI-compatible and Anthropic adapters, bounded retries, breaker, unknown outcomes; native requests forwarded as written (CAP-04) | In progress | Live test against Anthropic's own API, streaming from the provider |
| LLM-03 | Token budgets (hard/soft), reservations, usage and estimated cost | In progress | Cost budgets, operator reconciliation of unknown outcomes |

## Harness registry

| ID | Item | Status | Remaining |
|---|---|---|---|
| REG-01 | `harness.yaml` manifest, compatibility checks, read-only harness artifact, release states; agents boot from an imported release (validated on KVM) | Done | — |
| REG-02 | Asynchronous OCI import (GHCR, standard registries), allowlists, private-registry credentials, publisher signatures with strict mode (REG-009, cosign format) | Partial | Live GHCR test, keyless signatures (Fulcio/Rekor identities) and provenance attestations, short-lived cloud registry credentials |
| REG-03 | Shared read-only cache by digest, pinned agents, manual upgrade and rollback, safe eviction (validated on KVM) | Done | — |
| REG-04 | Reference Dagger module (build, publish, sign, verify; run by CI); harnesses in Go and in Python (SDK, validated on KVM) | Done | — |

## Interoperability

| ID | Item | Status | Remaining |
|---|---|---|---|
| INT-01 | Qualify OASF, Directory, A2A, SLIM releases; pin a compatibility matrix; private single-host services ([deploy/interop](deploy/interop)) tested in CI | Done | — |
| INT-02 | OASF records published from PostgreSQL to the private Directory (outbox, revisions, schema refusals shown); skill search from a running agent filtered again in PostgreSQL; SDK `find_agents`; search from a VM on KVM, through the A2A adapter (`/agents?skill=`), in the INT-05 journey | Done | — (Agent Cards: INT-03) |
| INT-03 | Agent Cards and a real A2A adapter: tasks, statuses, artifacts, result return. In the guest, `capsule-adapter` serves each reachable agent of the organization as an A2A 1.0 agent (Agent Card, JSON-RPC `SendMessage` and `GetTask`) mapped onto peer requests, with two platform-channel reads (card, request state), and runs agents that are A2A servers themselves, supervised, each job one message; an organization sets per agent whether requests from its other agents are delivered at once (`PUT /v1/agents/{id}/inbound`); qualified with the official A2A Go SDK on both sides and on PostgreSQL ([docs/adapter.md](docs/adapter.md#other-agents-a2a-endpoint)); content exchanged between agents of an organization is bound to the person whose invocation granted the mandate (found by the KVM scenario, two example A2A agents, `verify-product-guest.py --a2a-harness`, validated on KVM); a held request is accepted or declined by whoever may configure the recipient or is assigned to it with invoke (`/v1/agents/{id}/held-requests`, metadata only, audited) | Done | — |
| INT-04 | Host SLIM gateway, authenticated endpoints, vsock bridge, delegation limits. The SLIM bridge ([runtime/slimbridge](runtime/slimbridge), [docs/interop.md](docs/interop.md#the-slim-bridge-int-04)) carries deliveries between agents from the mailbox through the SLIM node to the worker and the VM over vsock, as A2A 1.0 messages; the worker accepts back only its own running attempts and checks the guest's receipt; the bridge ends when its node is lost; optional in the worker configuration; qualified against the private node (`verify-interop.py --services`) ; a delivered request grants no mandate, so delegation is one hop deep; systemd units for the bridge and the services ([deploy/systemd](deploy/systemd)), qualified under systemd (`verify-interop.py --systemd`); a wake budget per organization (`max_peer_wakes_per_hour`, default 60): a request that would wake a sleeping agent beyond it waits, without spending an attempt, then expires at its deadline ; a KVM journey of two A2A agents through a real bridge process and a private SLIM node, with the bridge away and a wake through SLIM (`verify-product-guest.py --slim-bridge-build`, validated on KVM) | Done | — |
| INT-05 | End-to-end flagship journey including Directory/SLIM failures: an agent finds another by its skill from its VM while the other sleeps and gets its answer over A2A and SLIM; with the Directory down the search fails and says so while known agents stay reachable; with the SLIM node down the request waits and the restarted bridge delivers it (`verify-product-guest.py --slim-bridge-build`, validated on KVM) | Done | — |

## Recovery

| ID | Item | Status | Remaining |
|---|---|---|---|
| REC-01 | Recovery decision: local restart vs full disaster, RPO/RTO ([ADR 003](docs/adr/003-restore-rpo.md), [ADR 004](docs/adr/004-recovery-objectives.md)): a local restart loses nothing; after a disaster, database RPO 15 min (WAL archiving), volume RPO 24 h (nightly archives while asleep), RTO 1 h on a standby host kept ready, encrypted backups to S3 and to the standby over SSH; a loss in the window is announced and rescheduled | Done | — (decision; the work is in REC-02 and REC-03) |
| REC-02 | Restore authority, volume archives, restricted boot then activation | Partial | Inspection and repair of real history, activation path; nightly archives of sleeping agents without stopping the worker; the declared-loss state (model, code, API) |
| REC-03 | External encrypted, versioned backups of PostgreSQL and volumes; restore on another host. PostgreSQL: continuous WAL archiving and nightly base backups to S3 and to the standby over SFTP, each encrypted with its own passphrase ([deploy/backup](deploy/backup), [docs/recovery.md](docs/recovery.md)), qualified by `verify-backups.py`: a commit archived within `archive_timeout`, a full restore from either store alone, no clear text in either | Partial | Continuous replay on the standby, freshness metrics and alerts, a failover exercise measuring RPO and RTO ([ADR 004](docs/adr/004-recovery-objectives.md)) |
| REC-04 | Key lifecycle and revocation outside the restored domain; archive deletion policy | Partial | Rotation and sealing policy |

## Release validation

| ID | Item | Status | Remaining |
|---|---|---|---|
| VAL-01 | Formal-model conformance: remaining projections, deletion/maintenance/capacity races, guest writer crash | Partial | Remaining projections |
| VAL-02 | Acceptance scenarios, version matrix, chaos/isolation/load tests, install from scratch, benchmarks | Not started | All |
| VAL-03 | Release audit: dependencies, SBOM, image scans, reproducible signed release, guides | Not started | All |

## Open design decisions

| ID | Question |
|---|---|
| D-01 | Identity and tenant migration (delegated identity chosen; operator bootstrap and migration of legacy data remain) |
| D-02 | Effect of reassignment and revocation on admitted work and past results ([ADR 002](docs/adr/002-assignment-revocation.md)) |
| D-03 | RPO, confirmed results and restore ([ADR 003](docs/adr/003-restore-rpo.md): option B, an announced loss within the window; numbers in [ADR 004](docs/adr/004-recovery-objectives.md)); the P2 model still to be revised for a declared loss |
| D-04 | Delivery closure when notifications are exhausted; any priority or reservation rule that changes progress |
| D-05 | Keys and secrets outside the restored domain; a secret store usable in self-hosting |

## Known limits worth knowing before contributing

- Tested on a single Linux host under WSL2 with KVM; not yet on a production server.
- The reference harnesses are echo/test harnesses. An existing agent runs through
  `capsule-adapter`: one command run per invocation, or an A2A server kept running;
  it can send requests to other agents over A2A. Agents that expose a plain HTTP
  server are not supported yet.
- Between agents of an organization, a request is delivered only if the
  recipient's inbound policy is `auto`. Under `manual`, the default, it waits
  for an approval that no route can give yet, until its deadline.
- Attachments are held in API memory during upload (8 MiB each) and stored in
  PostgreSQL; there is no object storage.
- Cancelling a `working` invocation does not stop computation already running in the
  VM; the agent learns it when it posts its result.
