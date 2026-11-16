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
are still missing, notably restoring agents onto another host and release
validation.

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
| OPS-01 | Validated configuration, separate secrets, preflight, mock vs production install: production mode by default (`AGENTCAPSULE_MODE`), the API on HTTPS only with checked certificates reloaded on SIGHUP, PostgreSQL over a Unix socket or `verify-full`, model providers and registries over HTTPS, model providers at public addresses only (checked after DNS resolution, no redirect) unless the operator allows an internal one, the Directory and SLIM node private behind mutual TLS, a host preflight run by the worker at every start (RUN-012) and on demand (`-preflight`), pinned versions listed ([docs/install.md](docs/install.md), [ADR 010](docs/adr/010-transport-security-and-preflight.md)) | In progress | KVM run of the worker's mandatory checks, preflight on a production server, API certificate expiry alert, systemd units for the API and the worker, signed releases and the items not yet pinned |
| OPS-02 | Metrics (Prometheus/OpenTelemetry), correlation IDs, redacted logs, alerts: `/metrics` on loopback for the API (route, status, latency) and the worker (jobs, retry reasons, boots, queue delay, capacity, disk), JSON events from closed vocabularies, `X-Request-ID` in each request's event, in the operations it creates and in the worker's events for every job it causes (agent-to-agent requests included), alert rules checked and unit-tested by promtool in CI ([docs/observability.md](docs/observability.md)) ; validated on KVM (worker metrics and job events in the A2A journey) | Done | — (distributed traces with spans: later) |
| OPS-03 | Host capacity, sparse disks, retention/GC, pressure thresholds, scheduler under load | Partial | Thresholds and alerts, load tests |

## Organizations and identity

| ID | Item | Status | Remaining |
|---|---|---|---|
| TEN-01 | Versioned migrations; organizations, principals, memberships, teams, assignments | In progress | — (follows new features) |
| TEN-02 | Delegated identity: EdDSA (Ed25519) JWTs signed by the organization's identity provider or client, verified with the keys the operator registers in PostgreSQL; keys added and retired with an overlap, without restarting the API ([ADR 001](docs/adr/001-organization-identity.md#tenant-transition-and-operator-bootstrap-d-01)) | Done | — (OIDC discovery and other algorithms: P1) |
| TEN-03 | RBAC for five roles; administration separate from invoke/read-content rights; every route tested against each role and kind of caller ([docs/api/rbac.md](docs/api/rbac.md)) | Done | — (defaults pending the product owner: ADR 002) |
| TEN-04 | Members, teams, assignments, revocation, organization disable; reassignment to another member or team, ordered against admissions on PostgreSQL | Done | — (defaults pending the product owner: ADR 002) |
| TEN-05 | Tenant agents and the per-organization data model; peer requests and agent search confined to one organization; two organizations validated side by side on KVM | Done | — |
| TEN-06 | Service accounts and audit | Partial | Audit export and retention |
| TEN-07 | Quotas and reservations (agents, VMs, CPU/RAM, disk, queues, LLM, storage) | Partial | Organization quotas on CPU, RAM and disk throughput (per-agent ceilings, ADR 012 P1) and load behavior (OPS-03) |

## Capsules and runtime

| ID | Item | Status | Remaining |
|---|---|---|---|
| CAP-01 | Private `capsule.v1` contract, typed envelope, platform channel (peers, LLM, attachments, deferred results); Go and Python harnesses | Partial | Capability negotiation against tenant policy; events |
| CAP-02 | Cold create, desired/observed state, wake/sleep/delete, reconciliation, single RW generation | Partial | Automatic restart policy for agents that should be running |
| CAP-03 | Jailer/cgroups hardening, egress control, CPU/RAM/IO/pid/time limits, bounded restarts: Firecracker rate limiters on every drive (by default 64 MiB/s and 2000 IOPS on the volume, 128 MiB/s and 4000 on a harness image; drive_limits), a restart budget per agent (5 failed boots or crashes an hour, then FAILED until a wake or agentcapsule-admin clear-agent-failure; migration 0031), no network device and a network namespace per VMM ([ADR 012](docs/adr/012-limits-restart-budgets-egress.md)) | Partial | KVM runs of TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest and TestProductWorkerStopsBootingAGuestThatCrashesAtBoot (next guest build); the internet egress profile and per-agent ceilings (P1) |
| CAP-04 | Unmodified agents ([docs/adapter.md](docs/adapter.md)): `capsule-adapter` runs the agent's command for each invocation and serves the OpenAI and Anthropic APIs on the guest loopback, forwarded as written (tools included) through the metered platform channel; `dagger call adapt` packs an existing image; official SDKs qualified against a real model (validated on KVM) | Done | — (A2A between agents and A2A server agents: INT-03) |

## Invocations and events

| ID | Item | Status | Remaining |
|---|---|---|---|
| EVT-01 | Invocations: admission by assignment, private results, deferred results (`working`) with one outcome among completion, timeout, cancellation and deletion | Partial | `/events` stream, structured JSON content in the guest protocol |
| EVT-02 | Queue TTL, per-agent and per-organization depth limits, dead letters, retries; no priority in the MVP, arrival order per agent ([ADR 007](docs/adr/007-delivery-closure-and-priority.md)) | Partial | Re-admission after capacity returns, operator replay of dead letters; a delivery an attempt may have reached, to an agent that never boots again, waits for its fence; a request to or from an agent that never boots waits for that agent's fence at its closure; a restore can lose may_have_reached ([ADR 007 §7](docs/adr/007-delivery-closure-and-priority.md#7-closure-scope-review-fixes-and-closed-requests-content)) |
| EVT-03 | Scheduled invocations, idle closure policy | Partial | Recurring schedules |
| EVT-04 | Encrypted attachments: upload, single use, reading from the guest, quota, purge | Partial | Files as results, external object storage, temporary links |

## LLM gateway

| ID | Item | Status | Remaining |
|---|---|---|---|
| LLM-01 | Providers, aliases, encrypted credentials kept out of VMs, rotation, audit; per-agent and per-team alias access (listed aliases, grants to agents and teams, refused before any reservation, [ADR 011](docs/adr/011-llm-access-and-cost-budgets.md)) | In progress | Dedicated secret store (D-05); the harness's `llm.invoke` capability (CAP-01); ADR 011's defaults pending the product owner |
| LLM-02 | OpenAI-compatible and Anthropic adapters, bounded retries, breaker, unknown outcomes; native requests forwarded as written (CAP-04); providers called at public addresses only, checked when connecting, unless the operator allows an internal one, and never through a redirect ([ADR 010](docs/adr/010-transport-security-and-preflight.md) §4) | In progress | Live test against Anthropic's own API, streaming from the provider |
| LLM-03 | Token and cost budgets (hard/soft) per organization, agent, alias and period, reservations, usage and estimated cost in exact micro-units, reconciliation of unknown outcomes by the organization ([ADR 011](docs/adr/011-llm-access-and-cost-budgets.md)) | Done | — (ADR 011's defaults pending the product owner) |

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
| REC-02 | Restore authority, volume archives, restricted boot then activation. The maintenance worker archives each agent's encrypted volume about once a day without being stopped: sleeping agents first, a running agent stopped once its archive is 24 h old, with local retention, records (migration 0028), events and metrics ([docs/worker.md](docs/worker.md)); it passed on KVM on 2026-11-13 (`TestProductWorkerNightlyVolumeArchives`, 13 of 13 worker tests). The restore authority declares losses (D-03 option B): `Activate` repairs from an archive first, then declares each outcome still missing for the new incarnation; reruns are recorded; losses are never withdrawn (catalogue schema 2, tests named after the P2 runs). The worker restores an agent on its own host from an archive into a new incarnation (`-restore-agent`): drain, retire, install, restricted boot, inspection through the guest, activation; resumable after a crash at any step; the losses are copied into PostgreSQL and mapped to their invocations (migration 0029, [docs/recovery.md](docs/recovery.md#restoring-an-agent-from-an-archive)). The same transaction queues the lost invocations again under their mailbox ID and mandate, unless the requester was revoked or the input purged; the API shows them as `lost`, with `lost_at` (migration 0030). The restore passed on KVM on 2026-11-15 (`TestProductWorkerRestoresAgentFromArchive`: losses exactly the invocations after the archive, rerun under the same IDs to `completed` with `lost_at`, the old incarnation refused; 14 of 14 worker tests, guest v20). Agent-to-agent events a restore lost are delivered again to the restored agent under their mailbox ID; a request in a final state never reopens; what is not delivered again keeps a reason, and an active request its recipient will not get again fails at once (migration 0033, [ADR 008](docs/adr/008-redelivering-lost-agent-requests.md)); KVM test `TestProductWorkerRestoresAgentToAgentExchange` written, not run | Partial | Restoring onto another host (D-05); the KVM run of TestProductWorkerRestoresAgentToAgentExchange; ADR 008's product owner questions |
| REC-03 | External encrypted, versioned backups of PostgreSQL and volumes; restore on another host. PostgreSQL: continuous WAL archiving and nightly base backups to S3 and to the standby over SFTP, each encrypted with its own passphrase ([deploy/backup](deploy/backup), [docs/recovery.md](docs/recovery.md)), qualified by `verify-backups.py`: a commit archived within `archive_timeout`, a full restore from either store alone, no clear text in either. Freshness: metrics and alerts for WAL archiving (age, backlog, failures, settings) and for the base backups of each repository ([docs/observability.md](docs/observability.md)), and for the age of the volume archives on the host. Standby: it replays the WAL archive continuously, from its local SFTP copy then from S3, and is promoted in 0.5 s; in the qualification, exactly the rows not yet archived were lost ([deploy/standby](deploy/standby)). Volume archives leave the host every hour, encrypted again with rclone crypt, to their own S3 bucket and to the standby, never rewritten, pruned by age only (30 and 7 days); shipping and the standby's replay lag have metrics and alerts (`verify-archive-shipping.py`). Failover of the database and the API, measured on one machine with `archive_timeout` scaled to 30 s: RTO 1.6 s to the first authenticated write, every lost write inside the announced window (`verify-failover.py`, in CI) | Partial | The failover of the agents and the worker (needs D-05 and KVM) and the exercise on real hosts ([ADR 004](docs/adr/004-recovery-objectives.md#measured-values)); protecting the standby's archive copies from a compromised host; object lock qualified with the chosen provider |
| REC-04 | Key lifecycle and revocation outside the restored domain; archive deletion policy ([ADR 018](docs/adr/018-key-lifecycle-and-archive-deletion.md)). Deleting an agent destroys its volume key right after its store is sealed, on the primary and the replica, so none of its archives opens anywhere; no undo. The worker deletes a deleted agent's archives from its host within the hour, recorded or taken on demand; the stores' copies expire by age (7 and 30 days); unfinished deletions are measured and alerted after 6 hours. Transit keys rotate yearly with an overlap: activation and startup keep the key of every live payload and attachment, and agentcapsule-admin transit-key-usage says when an old key can go. The seal rule ADR 006 wave 3 enforces is stated | Partial | ADR 018's five defaults pending the product owner; rotating the unlock key without a failover, and a rotatable LLM credential key (LLM-01) |

## Release validation

| ID | Item | Status | Remaining |
|---|---|---|---|
| VAL-01 | Formal-model conformance: remaining projections, deletion/maintenance/capacity races, guest writer crash. Every run and witness of the models is listed with its Go projection in [spec/projections.md](spec/projections.md), checked by `scripts/check-model-projections.py` (run by the hygiene check): 118 full, 64 partial, 46 model-only, 8 pending, 5 gap of 241. Projected on 2026-11-16: the guest writer crash (`TestAbortedWriterThenFence`, the writer process killed inside its transaction), the deletion of a destination in P3, the fair admission runs on the host queue, the renewal crash, the closure scope, and more P1 and restore runs | Partial | The P3 maintenance and capacity cases replayed with SQL (a capacity adapter), the P3 deletion with other work in flight, recycling and global admission order; the runs pending ADR 006 waves 5 and 7; power loss in the durability and fencing runs |
| VAL-02 | Acceptance scenarios, version matrix, chaos/isolation/load tests, install from scratch, benchmarks: every P0 requirement traced to the tests of its acceptance criterion in [docs/acceptance.md](docs/acceptance.md) (39 met, 24 partial, 1 not met, 1 needs KVM of 65 on 2026-11-16), checked by `scripts/check-acceptance.py` in the hygiene check; the MVP outcome as one ordered scenario with its missing links; the install from scratch without root (`scripts/verify-install.py`, in CI): build, PostgreSQL, migration, platform credential, the API over HTTPS, an organization and its trust, the authority service, the worker's preflight, a call by the owner | Partial | The outcome's missing links (one host run from the install to the agents as root, the restore from the external copy); a version matrix kept by a check; chaos tests (network partitions, full disk, power loss); load tests and benchmarks (OPS-03); the KVM runs listed in docs/acceptance.md |
| VAL-03 | Release audit: dependencies, SBOM, image scans, reproducible signed release, guides ([ADR 013](docs/adr/013-release-supply-chain.md), [docs/release.md](docs/release.md)): govulncheck and licenses, SPDX SBOMs, grype scans with an expiring allowlist, reproducible builds checked on every pull request, a tag-only release workflow with cosign keyless signatures and SLSA provenance | Partial | A first release from a tag (the workflow has not run; Go 1.27.4 first), the fixes of the first audit's findings, the guest image reproducible across hosts and published with its sources, the product owner's answers to ADR 013 |

## Open design decisions

| ID | Question |
|---|---|
| D-01 | Identity and tenant transition. Decided and built in [ADR 001](docs/adr/001-organization-identity.md#tenant-transition-and-operator-bootstrap-d-01) on 2026-11-16: no installation holds legacy owner data, so nothing is migrated; the legacy owner domain is closed (agentcapsule-api refuses acp_ tokens, agentcapsule-admin bootstrap removed); one documented, audited, repeatable operator bootstrap from an empty database ([docs/bootstrap.md](docs/bootstrap.md)); trust keys in PostgreSQL with rotation and overlap (migration 0034). Remaining: removing the legacy owner domain's code once its tests move to organizations; the product owner's answers (organization names, overlap, who rotates keys) |
| D-02 | Effect of reassignment and revocation on admitted work and past results ([ADR 002](docs/adr/002-assignment-revocation.md)) |
| D-03 | RPO, confirmed results and restore ([ADR 003](docs/adr/003-restore-rpo.md): option B, an announced loss within the window; numbers in [ADR 004](docs/adr/004-recovery-objectives.md)); the P2 model is revised for a declared loss (`noUndeclaredLoss`) and implemented: declared losses, reruns, the API's `lost` state. Defaults confirmed by the product owner on 2026-11-16 (automatic rerun under the same ID; a job acting outside the agent passes that ID as an idempotency key; an agent setting to ask before a rerun comes after the MVP) |
| D-04 | Delivery closure when notifications are exhausted; any priority or reservation rule that changes progress. Decided in [ADR 007](docs/adr/007-delivery-closure-and-priority.md) on 2026-11-16: a reply whose delivery dies leaves the request replied, the reply readable by the sender's agent until the end of its retention, and the operator told (a metric, an event, an alert); no priority in the MVP, priority moves to P1. Built on 2026-11-16: the reply's retention from the death, the sender's read of its reply (`/status`, A2A `GetTask`, also after the replier's deletion), the dead-delivery metric, event and alert, and, asked the same day, the death at its deadline of a delivery whose agent never boots, without booting it when no attempt reached it; P1 and P3 gain that death as an action. Amended on 2026-11-16 (§7): a request's closure fences its two parties only; review fixes (a retention for dead replies that had none, the death of an unsent delivery behind the mailbox head, deletions left to cancel, the status read decided under its content's lock and without locking the recipient); request content closed before delivery kept 7 days from its closure (default pending the product owner). Remaining: a KVM run with the rebuilt guest and the updated KVM tests, TLC and Apalache checks of the revised models, the restore risk of §7.2 (h), and EVT-02's items |
| D-05 | Keys and secrets outside the restored domain; a secret store usable in self-hosting. Decided in [ADR 005](docs/adr/005-keys-outside-restored-domain.md): a synchronous replica of the authorities on the standby; receipt token secrets under a daily key destroyed after 24 hours; in degraded mode a revocation is pending until the standby holds it (finding 1, option (a)). Modelled (replica, promotion, degraded mode, PostgreSQL reconciled behind the authorities); the synchronous replica is built (`agentcapsule-authority`, mutual TLS, HPKE-wrapped keys, one stream for both authorities), with its promotion (`agentcapsule-authority promote`, next epoch, fence receipts bound to their epoch, the old primary refused) and degraded mode after 30 s without the standby (outcomes and fences continue; keys, seals and restores wait; alerts). Remaining: the announcement after a degraded period, revocation records (pending until the standby holds them, finding 1), reconciliation with PostgreSQL, the daily receipt key, the authority service's waves 4 to 7 (designed in [ADR 006](docs/adr/006-authority-service.md), accepted 2026-11-16; waves 1 to 3 are built: the service and its protocol (two local sockets with peer checks, holds with caps and a quiet period after a restart, keys outside JSON, one owner per authority directory) and the worker on it (its `authority` section, the old sections refused, a key held under its binding only, a restore that pauses while the service is away, the preflight through the service, systemd units, the `agentcapsule-authority` scrape job and `AgentCapsuleAuthorityServiceDown`), and key destruction checks the seal (`destroy_key` refused unless the restore authority holds the store sealed; armed, checked in the transaction that records the destruction); the KVM product tests through the service remain to run). Until a replica is installed, a lost host loses the agents' memory |

## Known limits worth knowing before contributing

- Tested on a single Linux host under WSL2 with KVM; not yet on a production server.
- The reference harnesses are echo/test harnesses. An existing agent runs through
  `capsule-adapter`: one command run per invocation, or an A2A server kept running;
  it can send requests to other agents over A2A. Agents that expose a plain HTTP
  server are not supported yet.
- Between agents of an organization, a request is delivered at once only if
  the recipient's inbound policy is `auto`. Under `manual`, the default, it
  waits until a person who may configure the recipient, or is assigned to it
  with invoke, accepts it (`/v1/agents/{id}/held-requests`), or until its
  deadline.
- Attachments are held in API memory during upload (8 MiB each) and stored in
  PostgreSQL; there is no object storage.
- Cancelling a `working` invocation does not stop computation already running in the
  VM; the agent learns it when it posts its result.
