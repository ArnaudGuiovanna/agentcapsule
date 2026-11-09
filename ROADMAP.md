# Roadmap

Agent Capsule is **pre-MVP**. The core path works and is validated on real KVM: an
organization creates an agent, a member sends it an invocation with an encrypted
attachment, the agent runs in its own Firecracker microVM, reads the file and calls
its model through the platform channel, and posts a result only that member can
read. Large parts of the MVP described in [docs/product.md](docs/product.md) are
still missing, notably booting agents from registry releases, standard
interoperability (A2A, SLIM, Directory), observability and a restore procedure.

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
| OPS-02 | Metrics (Prometheus/OpenTelemetry), correlation IDs, redacted logs, alerts | Not started | All |
| OPS-03 | Host capacity, sparse disks, retention/GC, pressure thresholds, scheduler under load | Partial | Thresholds and alerts, load tests |

## Organizations and identity

| ID | Item | Status | Remaining |
|---|---|---|---|
| TEN-01 | Versioned migrations; organizations, principals, memberships, teams, assignments | In progress | — (follows new features) |
| TEN-02 | Delegated identity (JWT from the customer's IdP) bound to the database authority | In progress | Operator tooling for trust rotation |
| TEN-03 | RBAC for five roles; administration separate from invoke/read-content rights | Partial | Remaining routes and result/inbox filters |
| TEN-04 | Members, teams, assignments, revocation, organization disable | In progress | Reassignment to another target; admission/reassignment races |
| TEN-05 | Tenant agents and the per-organization data model | In progress | Two isolated organizations demonstrated on KVM |
| TEN-06 | Service accounts and audit | Partial | Audit export and retention |
| TEN-07 | Quotas and reservations (agents, VMs, CPU/RAM, disk, queues, LLM, storage) | Partial | Physical limits (CAP-03) and load behavior (OPS-03) |

## Capsules and runtime

| ID | Item | Status | Remaining |
|---|---|---|---|
| CAP-01 | Private `capsule.v1` contract, typed envelope, platform channel (peers, LLM, attachments, deferred results) | Partial | Capability negotiation against tenant policy; events; second harness language (REG-04) |
| CAP-02 | Cold create, desired/observed state, wake/sleep/delete, reconciliation, single RW generation | Partial | Automatic restart policy for agents that should be running |
| CAP-03 | Jailer/cgroups hardening, egress control, CPU/RAM/IO/pid/time limits, bounded restarts | Partial | Egress profiles, IO limits, restart budgets |

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
| LLM-02 | OpenAI-compatible and Anthropic adapters, bounded retries, breaker, unknown outcomes | In progress | Live test of the Anthropic adapter, streaming |
| LLM-03 | Token budgets (hard/soft), reservations, usage and estimated cost | In progress | Cost budgets, operator reconciliation of unknown outcomes |

## Harness registry

| ID | Item | Status | Remaining |
|---|---|---|---|
| REG-01 | `harness.yaml` manifest, compatibility checks, read-only harness artifact, release states | Partial | Booting an agent from the imported artifact (attach `harness.ext4` read-only, `capsule-init` mounts and runs it), validated on KVM |
| REG-02 | Asynchronous OCI import (GHCR, standard registries), allowlists, signatures | Partial | Registry credentials, live GHCR test, signature/attestation policy (REG-009) |
| REG-03 | Shared read-only cache by digest, pinned agents, documented manual updates | Partial | Eviction, documented manual upgrade and rollback |
| REG-04 | Reference Dagger module; harnesses in Go and in Python or TypeScript | Not started | All (the `agentcapsule-harness pack/push` tool exists) |

## Interoperability

| ID | Item | Status | Remaining |
|---|---|---|---|
| INT-01 | Qualify OASF, Directory, A2A, SLIM releases; pin a compatibility matrix | Partial | Supported profile decision |
| INT-02 | OASF records, private Directory sync, filtered Agent Cards | Not started | All |
| INT-03 | Real A2A adapter: tasks, statuses, artifacts, result return | Not started | All |
| INT-04 | Host SLIM gateway, authenticated endpoints, vsock bridge, delegation limits | Not started | All |
| INT-05 | End-to-end flagship journey including Directory/SLIM failures | Not started | All |

## Recovery

| ID | Item | Status | Remaining |
|---|---|---|---|
| REC-01 | Recovery decision: local restart vs full disaster, RPO/RTO ([ADR 003](docs/adr/003-restore-rpo.md)) | Not started | Decision |
| REC-02 | Restore authority, volume archives, restricted boot then activation | Partial | Inspection and repair of real history, activation path |
| REC-03 | External encrypted, versioned backups of PostgreSQL and volumes; restore on another host | Partial | Procedure on a separate KVM host, freshness alerts |
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
| D-03 | RPO, confirmed results and restore ([ADR 003](docs/adr/003-restore-rpo.md)) |
| D-04 | Delivery closure when notifications are exhausted; any priority or reservation rule that changes progress |
| D-05 | Keys and secrets outside the restored domain; a secret store usable in self-hosting |

## Known limits worth knowing before contributing

- Tested on a single Linux host under WSL2 with KVM; not yet on a production server.
- One organization has been exercised on KVM end to end; isolation between two
  organizations on KVM is not yet demonstrated.
- The reference harness is an echo/test harness, not a general agent runtime.
- Attachments are held in API memory during upload (8 MiB each) and stored in
  PostgreSQL; there is no object storage.
- Cancelling a `working` invocation does not stop computation already running in the
  VM; the agent learns it when it posts its result.
