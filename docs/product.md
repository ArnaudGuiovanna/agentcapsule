# Agent Capsule — product document

This document describes the **target product**: its purpose, core concepts, the
scope of the first release (the MVP, priority P0), and its security and data
protection principles. It does not say what is implemented; `ROADMAP.md` tracks
status using the requirement IDs below (for example `TEN-001`). Priorities:
**P0** required for the MVP, **P1** near term, **P2** later.

## 1. Problem and vision

**Problem.** Organizations that want to give their people autonomous AI agents
must assemble isolation, identity and permissions, runtime hosting and updates,
LLM provider access, durable storage, wake-up on events, message delivery,
agent-to-agent communication, audit and quotas themselves. Chat products and
raw LLM APIs offer neither an isolated computer per agent nor its lifecycle.

**Vision.** Any organization can give its people autonomous, isolated,
configurable, on-demand agents on infrastructure it controls. Agent Capsule is
an open-source, API-first, self-hosted platform that is agnostic of harness,
model, client and registry: it provides hosting primitives and does not decide
what an agent thinks or does. An organization brings its own LLM providers
and harnesses (any language), creates agents for members or teams, and runs
each active agent in its own Firecracker microVM. Agents keep their private
state while stopped, wake on a request, an event or a peer's task, and
delegate to authorized peers through OASF, the AGNTCY Agent Directory, A2A and
SLIM, under the organization's budgets and permissions.

**MVP outcome.** On one KVM-capable host, an administrator imports several
harnesses (at least Go plus Python or TypeScript), creates isolated agents for
two organizations, uses them over HTTPS, stops and wakes them without data
loss, shows agent A discovering agent B and getting its answer over A2A/SLIM
although B was stopped (tested against pinned versions, not mocks), and
restores agents from an external backup.

**Principles.**

1. **Encapsulation:** harnesses run only inside microVMs, never on the host.
2. **Organizational ownership** of agents, assignments, budgets and permissions.
3. **Separation:** the platform hosts and governs; the harness decides what the agent does.
4. **Stopping is not deleting.**
5. **Immutable** images and harnesses, referenced by digest.
6. **Real standards** for interoperability; the host/guest protocol `capsule.v1` stays private.
7. **Secure by default:** no exposed VM, no implicit privilege, no master secret in a guest.
8. **No proprietary edition** holds back core features.
9. **API-first**, administration included.
10. **Evidence over promises:** claims rest on reproducible measurements.

**What it is not.** A learning, tutoring or LMS product or a content
marketplace; a language
model, inference API or consumer chat interface; a Kubernetes replacement, GPU
provider or virtual desktop; a way for individuals to own or take away an
agent; a claim that Firecracker alone prevents every leak or harmful action.

## 2. Users and deployment model

**Users.** Platform operators, organization administrators, team managers,
members using their assigned agents through any client, harness developers,
integrators building on the API, and contributors.

- **Self-hosted.** Runs without any managed service or commercial dependency on the project; no external telemetry without consent. The platform is MIT-licensed; harnesses keep their own license.
- **Single host first.** Reference target: one Linux server with 8 vCPU, 24 GB RAM and 200 GB NVMe. One node is a single point of failure: no high availability is claimed and off-host backups are mandatory. Multi-node is P2.
- **KVM required.** Firecracker needs read/write `/dev/kvm`; a preflight checks kernel, cgroups v2, disk, network and jailer permissions and refuses an incompatible host. VM isolation is never simulated; the `mock` development runtime validates neither security nor performance.
- **Surface.** An HTTPS API and a minimal administration and diagnostic CLI; no graphical client in P0.
- **Capacity.** Starting points, to be measured: 256–512 MiB and 1 vCPU per microVM, 10 active VMs, a free-disk reserve. Stopped agents use storage but no VM memory.

## 3. Core concepts

### Organizations, members and roles

- The **organization** is the tenant and the isolation boundary. The platform operator creates organizations and has no access to their content.
- Principals are **members** (people, authenticated by delegated identity) and **service accounts**. **Teams** group members.
- Roles are `org_owner`, `org_admin`, `agent_operator`, `agent_user` and `auditor`. They are administrative: no role, not even `org_owner`, grants invocation or content access.

### Agents and assignments

- An **agent** is a stable identity in an organization, pinned to a harness release and a base image, with resource limits, a model alias and a private volume. It is individual, shared by a team, or specialized (offered to other agents).
- An **assignment** grants a member or a team `read_metadata`, `invoke` and/or `read_content` on an agent, without transferring ownership. Rights are checked at each use, so a revocation applies to the next request.
- A result is readable only by its requester while they hold `read_content`, and does not follow a reassignment. A harness may still remember past exchanges in its volume.

### Capsules

- One Firecracker microVM per active agent, under the jailer, with its own UID, cgroups and limits. Guest layout: read-only base OS at `/`, read-only harness at `/opt/harness` (shared by digest), private volume at `/var/lib/agent`, size-limited tmpfs for `/tmp` and `/run`.
- The private volume is **encrypted**. It is unlocked only inside the guest and never mounted on the host. Its key is held by a key authority kept apart from data backups and is revoked on deletion.
- At most one microVM owns a volume: leases carry a generation number, and commands from an older generation are rejected.
- States: `PROVISIONING`, `STOPPED` (no VM, no VM memory), `STARTING`, `READY` (the harness answers health checks), `BUSY`, `QUIESCING`, `FAILED`, `DELETING`, `DELETED`; desired and observed states are reconciled after crashes. P0 stops are cold: no memory snapshots.

### Harnesses and capsule.v1

- A **harness** holds the agent loop. Any language works; dependencies are bundled at build time, never installed at boot. It ships as a read-only ext4 image with a `harness.yaml` manifest declaring version, base image, entrypoint, resources, requested capabilities (such as `llm.invoke` or `agents.delegate`) and egress. **Effective rights = harness capabilities ∩ organization policy ∩ agent policy.**
- **capsule.v1** is the private, framework-independent host/guest protocol, carried over vsock with version negotiation. Host to guest: health, capabilities, invoke, events, quiesce, A2A task delivery. Guest to host, over the **platform channel**: peer discovery and tasks, LLM calls, attachment reads, deferred results. Agent and organization identity come from the channel and boot generation, never from the payload.

### Invocations, events and attachments

- An invocation is admitted only when identity, current authorization, the durable job and its idempotency receipt commit together; the API returns `202` and an `operation_id`, and the work wakes a stopped agent. A harness may answer `working` and post its result before a deadline; every invocation ends with exactly one outcome.
- Events are durable external events or simple scheduled events. Queues have TTL, priority and depth limits, bounded retries and dead letters; an idle agent stops after a timeout, never mid-work.
- Delivery is **at least once** with deduplication; exactly-once is never promised for external effects such as LLM calls, emails or payments. Harnesses checkpoint and deduplicate in their volume.
- **Attachments** are opaque references with MIME type, size, hash and access control, bound to organization, agent and sender, read over the platform channel and purged on expiry. The platform carries files; interpreting them is the harness's job.

### LLM gateway

Organizations bring their own provider keys, stored encrypted; keys never enter
a guest. Harnesses call **model aliases** (such as `default-assistant`). The
gateway resolves the provider and enforces the `llm.invoke` capability,
**budgets** (hard and soft caps on tokens and estimated cost per organization,
agent, model and period), timeouts, bounded retries and per-provider circuit
breakers. Keys rotate without rebuilding harnesses. Prompts and responses are
not logged unless an organization policy says so.

### Inter-agent requests

- **Discovery.** Visible agents have an OASF record in a private Directory, searchable while stopped and filtered by organization, ACL and caller. A record grants no right to call.
- **Consent.** The recipient side sets discoverability and whether inbound requests are accepted by policy or manually by a responsible person. Nothing is delivered before acceptance; the sender can cancel until an outcome exists.
- **Mandates.** Delivered work carries a **mandate**: created once, bounded by budget and expiry, revoked if the work is canceled or abandoned. Onward requests run under it. A peer's response carries no mandate, so a reply alone cannot start a new delegation.
- **Flow.** A submits a task; the platform checks policy, stores it before acknowledging, wakes B if needed, delivers through SLIM and B's vsock link, and returns B's answer to A as a durable A2A result. Delivery does not mean success.
- **Limits.** ACLs, TTL, hop and fan-out limits, wake budgets and token quotas stop cycles and spawn storms. Peer content is untrusted input. Cross-organization traffic is refused by default. Content is visible only to the parties and stored with transit encryption.

### Interoperability goals

| Standard | Role | Limit |
|---|---|---|
| OASF | Describes skills and capabilities | Grants no right |
| AGNTCY Agent Directory | Private search, including stopped agents | Not an access control list |
| A2A | Tasks, statuses, results | Distinct from `capsule.v1` |
| SLIM | Secure transport between active endpoints | Cannot reach a stopped VM alone |
| Platform mailbox | Durable storage, wake-up, redelivery | Subject to quotas |

Versions are pinned and conformance-tested; nothing is called A2A compatible
without real validation. Official AGNTCY components are deployed, not
reimplemented. The admin endpoint `/v1/agent-tasks` is not the A2A protocol.

### Harness registry

Harnesses are built off-host (a reference Dagger module run by CI), published
to an OCI registry (GHCR first, any approved registry) and imported by digest.
A package holds `harness.yaml`, `harness.ext4`, `checksums.json` and optional
OASF and provenance files. Releases are verified, immutable, cached read-only
and shared; creating an agent builds nothing. Agents stay pinned; in P0,
upgrades are manual and documented (backup, health check, rollback when
possible), and data migration is the harness's job.

### Operations and recovery

- **Observability.** Health and readiness endpoints, Prometheus/OpenTelemetry metrics, traces with pseudonymized IDs, redacted logs, and an operator CLI for queues, boot errors, redacted diagnostics, restore tests and garbage collection.
- **Capacity protection.** Disk alerts at 70% and 80%; imports and new volumes refused past a pressure threshold; alerts on CPU, memory, queue age, boot failures and Directory or SLIM outages.
- **Backups.** Off-host, encrypted, versioned backups of PostgreSQL, agent volumes and harness digests, taken consistently (quiesce first), with freshness alerts.
- **Restore.** Tested regularly on another KVM host. RPO and RTO are documented and measured ([ADR 004](adr/004-recovery-objectives.md): database 15 minutes, agent volumes 24 hours, RTO 1 hour on a standby host); after a full disaster, work acknowledged inside the announced RPO window can be lost. A lost invocation is shown as `lost`, with the time of the loss, and runs again under the same identifier unless its requester was revoked. A restore never revives memberships, assignments, tokens, delegations or keys revoked since the backup.
- **Revocation.** Deactivating a member revokes their tokens, sessions and delegations; no later call succeeds, not even reading a result or replaying a receipt. Work accepted earlier may finish for the organization, which keeps the agents.
- **Deletion.** Blocks new work, stops the VM, destroys the volume, its key and temporary credentials, and removes the Directory record. Backups expire per policy, not instantly.

## 4. MVP (P0) requirements

### Organizations, identity and authorization

| ID | Requirement | Acceptance |
|---|---|---|
| TEN-001 | Create, read, deactivate organizations | Platform operator or bootstrap only; audited |
| TEN-002 | Tenant ID on every resource | Out-of-tenant access refused, even with guessed IDs |
| TEN-003 | Five roles (see above) | RBAC matrix tested per role and resource |
| TEN-004 | Service accounts with scoped, expiring tokens | Instant revocation; tokens stored hashed; creation logged |
| TEN-005 | Assign agents to members or teams | Unassigned members can neither invoke nor read |
| TEN-006 | Revoke a member and their delegations | Revoked sessions and tokens make no new call |
| TEN-007 | Quotas: agents, active VMs, RAM, CPU, storage, tasks, LLM budget | Typed refusal before any reservation |
| TEN-008 | Verifiable end-user identity | OIDC/JWT or signed delegation from a trusted client; free-form user IDs refused |
| TEN-009 | Audit log of administrative actions | Who, when, resource, outcome; no conversation content |

Isolation also covers search, metrics, logs, attachments, download URLs and
statistics. The organization is derived from authentication, never from a
request body.

### Harness registry and supply chain

| ID | Requirement | Acceptance |
|---|---|---|
| REG-001 | Import from an OCI reference pinned by digest | Asynchronous, tracked by `operation_id` |
| REG-002 | GHCR and any standard OCI registry | Same test passes on GHCR and a local registry |
| REG-003 | Verify digest, size, media type, architecture, manifest, base | Tampered or incompatible package rejected |
| REG-004 | Only approved registries and publishers | Arbitrary or SSRF-style references refused |
| REG-005 | Immutable releases | `name:version` maps to a stable digest; no overwrite |
| REG-006 | Shared read-only cache with safe eviction | Two agents share one image; active releases kept |
| REG-007 | No tenant code compiled on the host | Only pull, validation and boot observed |
| REG-008 | Status `IMPORTING`, `READY`, `REJECTED`, `DEPRECATED` | Queryable; errors leak no secret |
| REG-009 | Trust policy for signatures and attestations | Strict mode rejects unauthorized releases |
| REG-010 | Go and an interpreted language tested | Same protocol; no platform dependency on them |

### Capsules and runtime

| ID | Requirement | Acceptance |
|---|---|---|
| RUN-001 | Creation provisions identity and volume without booting | `STOPPED`; no Firecracker process |
| RUN-002 | Wake starts a jailed microVM with planned resources | KVM, jailer, cgroups checked; `READY` |
| RUN-003 | One microVM per writable volume | Concurrent wakes yield one generation |
| RUN-004 | Sleep quiesces, flushes, cold-stops | No process or RAM left; data kept |
| RUN-005 | Delete blocks tasks, destroys resources per policy | Audited; no volume left mounted |
| RUN-006 | Desired and observed states separated | Reconciled after a worker crash |
| RUN-007 | CPU, RAM, I/O, time and process limits | A hostile agent stays within ceilings |
| RUN-008 | Unique sockets, UIDs, resources, cleaned up | Nothing left for another capsule |
| RUN-009 | Memory persists on the private volume | Write, stop, restart, read the same value |
| RUN-010 | No harness in the control plane | Execution observed only in guests |
| RUN-011 | Usable status on boot failure or saturation | `FAILED` or `QUEUED`; no spawn loop |
| RUN-012 | Mandatory preflight | No Firecracker mode without `/dev/kvm` and a compatible kernel |

### Invocations and events

| ID | Requirement | Acceptance |
|---|---|---|
| EVT-001 | Durable write before acknowledgement | An API crash after ACK loses nothing |
| EVT-002 | Accepted work wakes a stopped agent | `STOPPED → READY → BUSY`, unattended |
| EVT-003 | Idempotency key per client and event | One key, one business operation |
| EVT-004 | Unique lease and generation per agent | Never two writable copies |
| EVT-005 | Bounded retries, backoff, dead letter | No unbounded loop |
| EVT-006 | TTL, priority, queue limits per tenant and agent | Expired tasks never run |
| EVT-007 | Work waits through resource shortage | Resumes, or expires with a clear error |
| EVT-008 | Event scheduled at a fixed time | Runs no earlier than due |
| EVT-009 | Results available by polling | `GET /v1/operations/{id}` gives state and result or error |
| EVT-010 | Idle shutdown that respects jobs | No stop during uncheckpointed work |

### LLM gateway

| ID | Requirement | Acceptance |
|---|---|---|
| LLM-001 | Several providers and aliases per organization | No mandatory provider |
| LLM-002 | OpenAI-compatible and native Anthropic adapters | Mock tests plus optional live tests |
| LLM-003 | Keys outside VMs, encrypted at rest | No key in volumes, snapshots or traces |
| LLM-004 | Calls mediated by agent, scope and budget | Unauthorized agents refused |
| LLM-005 | Tokens and estimated spend per tenant, agent, model | Per-period metrics; hard and soft caps |
| LLM-006 | Sound timeouts, limits and retries | Quota errors explicit; no reboot loop |
| LLM-007 | Rotate or disable keys without rebuilds | Effective on the next request |
| LLM-008 | No secret in API, logs, metrics or A2A messages | Redaction tests pass |

### Discovery and inter-agent communication

| ID | Requirement | Acceptance |
|---|---|---|
| A2A-001 | Valid OASF record per visible agent | Updated when capabilities change |
| A2A-002 | Records in a private Directory | Skill search works while `STOPPED` |
| A2A-003 | Results filtered by tenant, ACL, caller | Other organizations invisible |
| A2A-004 | Real A2A adapter for supported tasks | Agent Card and transitions tested on the pinned spec |
| A2A-005 | At least one exchange over SLIM | Visible in the private SLIM node |
| A2A-006 | Task stored before acknowledging the sender | Worker crash loses no accepted task |
| A2A-007 | Wake a stopped recipient, deliver over vsock | B answers from its own VM |
| A2A-008 | Distinct accepted, delivered, working, completed, failed, expired | Delivery is not success |
| A2A-009 | No unauthorized delegation, cycles or unbounded fan-out | ACL, TTL, hops, wake budget tested |
| A2A-010 | Result stored and returned to the caller | A gets it, after waking if needed |
| A2A-011 | Private data kept out of the Directory | Only authorized descriptions indexed |
| A2A-012 | Cross-tenant communication denied by default | Explicit attempts rejected |

### Content, capabilities and clients

| ID | Requirement | Acceptance |
|---|---|---|
| EXT-001 | Text and structured JSON messages | Invocation works |
| EXT-002 | Attachments by reference with MIME, size, hash, ACL | Right agent only; cross-tenant refused |
| EXT-003 | Catalog of capabilities declared by each harness | Matches manifest and policy |
| EXT-008 | Admin CLI and HTTP examples | Every MVP feature usable without a UI |

### API conventions

Versioned `/v1` JSON over HTTPS, specified in OpenAPI 3.1
(`openapi/openapi.yaml`); bearer tokens with subject, organization and scopes;
`Idempotency-Key` on every mutation; `202` plus `operation_id` for asynchronous
work; opaque IDs and cursors; `application/problem+json` errors with a stable
`code`; bounded payloads; temporary download URLs bound to identity. No route
forwards a raw Firecracker or shell command to the host.

## 5. Out of scope for P0

- **P1:** advanced OIDC/SSO; installable signed skills (EXT-004); SSE streaming (EXT-005); outbound webhooks and notifications (EXT-007); calendar connectors; consistent memory snapshots and warm restore; automatic harness migration and canary rollout; LLM routing and fallback; web console and more SDKs.
- **P1/P2:** large or real-time audio and video (EXT-006).
- **P2:** multi-node pools and migration; public cross-organization federation; harness marketplace; multi-source event orchestration; advanced cost optimization.
- **Never in the core:** tutoring or other business logic; a managed SaaS offer; a mandatory graphical client.

## 6. Security and isolation principles

- **Tenant isolation.** Deny by default. Every resource is tenant-scoped and filtered server-side; guessed IDs reveal nothing; no writable storage is shared; cross-access tests ship with the product.
- **Untrusted harness code** runs only in a jailed microVM (own UID, cgroups, seccomp, limits, controlled egress) with no path to Firecracker sockets, other agents' files or tenant secrets.
- **No secrets in guests.** Provider keys stay in the control plane. A capsule gets only its volume key and short-lived boot credentials bound to organization, agent and generation (revoked on stop and delete); capsule-init holds them and the harness sees neither.
- **Network.** Egress is denied except through the platform. Internet access with allow or deny lists is a separate, riskier profile under which secrets cannot be protected.
- **Least privilege.** Roles grant no content access, service accounts stay within their scopes, and the privileged worker accepts only typed commands from the API.
- **Authorization on every call.** OASF records and SLIM messages never prove rights; rights are never inferred from message text; sensitive actions can require human approval.
- **Supply chain.** Digest-pinned releases; provenance, signatures, SBOMs and scans per trust policy; approved registries only.
- **Audit** of administrative actions (who, when, resource, outcome), without conversation content.
- **Vulnerabilities.** Private disclosure via `SECURITY.md`, dependency and image scanning, Firecracker and kernel patching, signed releases.

## 7. Data protection principles

- **The organization is the data controller** for its agents. Members remain data subjects: the product favors transparency, minimization, explicit retention and separated access.
- **Private by default.** Administrators cannot read members' conversations, and no admin endpoint allows hidden monitoring; content access needs an explicit feature, legal basis and policy. Operators see technical metrics only.
- **Transit encryption.** Invocations, results, inter-agent messages and attachments held by the platform are encrypted with keys distinct from volume keys, bound to their parties and purged after a bounded retention.
- **No content logging by default.** Tokens, prompts and attachments are redacted everywhere.
- **Retention by data class.** Agent data follows organization rules; transport data and technical metadata expire automatically; audit follows the legal context; backup retention and purge are documented.
- **Honest deletion.** Live data is removed promptly; immutable backup generations expire per policy.
- **No general compliance claim.** Sensitive HR uses or automated assessment of people need legal analysis and safeguards specific to the use case.

## 8. Glossary

| Term | Meaning |
|---|---|
| Capsule | The Firecracker microVM running one active agent, with its encrypted private volume |
| Harness | The agent runtime inside a capsule, in any language, shipped as an immutable OCI release |
| capsule-init | The in-guest supervisor: mounts disks, starts the harness, holds boot credentials, relays calls |
| Worker | The privileged host service running Firecracker and the jailer, managing volumes and reconciling state |
| Control plane | API, scheduler, policies and PostgreSQL state governing organizations, agents and work |
| Organization | The tenant: owner of agents, credentials, budgets and policies; the isolation boundary |
| Member | A person in an organization, authenticated through delegated identity |
| Team | A group of members that can receive assignments |
| Assignment | A grant of `read_metadata`, `invoke` and/or `read_content` on an agent to a member or team |
| Invocation | A message or task sent to an agent, stored durably and tracked as an operation |
| Delegated identity | End-user login by tokens signed by a trusted client or OIDC provider, mapped to a member |
| Service account | A tenant-scoped technical identity with scoped, expiring, revocable tokens |
| Platform channel | The authenticated path from a harness through capsule-init and vsock to the platform |
| Transit encryption | Encryption of content the platform stores between parties, with dedicated rotatable keys |
| Mandate | A durable, bounded, revocable authorization attached to delivered work |
