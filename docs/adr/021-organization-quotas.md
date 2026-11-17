# TEN-07 — Organization quotas on agents, active VMs, vCPUs, RAM and storage

Date: November 17, 2026. **Status: built on November 17, 2026**, with
defaults pending the product owner (see [Questions](#questions-for-the-product-owner)).
References: TEN-007, EVT-007 and RUN-011 of the [product spec](../product.md),
TEN-07 and CAP-03 of the [roadmap](../../ROADMAP.md),
[ADR 012](012-limits-restart-budgets-egress.md) (ceilings per VM; ceilings
per organization were P1), [ADR 017](017-capacity-queue-and-dead-letter-replay.md)
(the capacity queue), the models [fair_admission.qnt](../../spec/fair_admission.qnt)
and [barrier_capacity.qnt](../../spec/barrier_capacity.qnt).

## Context

TEN-007 asks for quotas on agents, active VMs, RAM, CPU, storage, tasks and
LLM budget, with a typed refusal before any reservation. Before this record:

| Limit | Scope | Set by | Past it |
|---|---|---|---|
| Tasks: waiting instructions per agent and per organization | organization | its owners and administrators (`quota:manage`) | 429 `queue_full` before anything is accepted |
| LLM budget | organization, alias, agent | its owners and administrators | refused before the call |
| Attachment storage | organization | its owners and administrators | 429 `attachment_quota_exceeded` |
| VMs at once (`max_active`) | host | the operator | work waits in the capacity queue (ADR 017) |
| Volume storage | host | the operator (`ConfigureHostStorage`) | 503 `storage_capacity_unavailable` |
| vCPUs, RAM, disk throughput | one VM | the agent's resources, the worker's `drive_limits` | the VM's own ceiling (ADR 012) |

Nothing bounded what one organization takes of a shared installation: it
could create agents until the host's storage was full, and keep every VM slot
of a host.

## Decision

### 1. Who sets them

The **platform operator** sets an organization's quotas. These quotas share
the installation's hosts between organizations: an organization that could
set them could also raise them. Queue limits, attachment storage and LLM
budgets protect an organization from its own costs, and stay its own
(`quota:manage`). The organization's owners, administrators and auditors read
their quotas and usage (`usage:read`, like `GET /v1/queue`). Default pending
the product owner (question 1).

| Route | Who | What |
|---|---|---|
| `GET /v1/organizations/{id}/quotas` | the platform operator (`platform:admin`) | limits and usage |
| `PUT /v1/organizations/{id}/quotas` | the platform operator | replaces every limit; idempotent, the organization part of the receipt |
| `GET /v1/organizations/current/quotas` | `org_owner`, `org_admin`, `auditor` (`usage:read`) | the caller's organization's limits and usage |

A limit is a number or `null`; `null`, or an organization never limited, is
no limit. A new installation, and every existing organization, keeps working
as before (migration 0045).

### 2. What counts

| Quota | Counts | Checked |
|---|---|---|
| `max_agents` | the organization's agents not yet deleted: provisioning, live and being deleted | at creation |
| `max_storage_mib` | the data volumes of the same agents | at creation |
| `max_active_vms` | its VMs booted for work, starting, running or stopping, on every host | at each boot for work |
| `max_vcpus`, `max_memory_mib` | the vCPUs and RAM of those VMs | at each boot for work; at creation, an agent that alone needs more is refused |

Not counted: a boot only for a barrier (a fence, a provisioning's
initialization, a restore, a deletion's seal). It is the platform's act,
short, and must not wait for the organization (barriers keep their priority,
`barrier_capacity.qnt`). Not counted either: volume archives, attachments
(their own quota), and the VMM's own 256 MiB beside the guest's RAM. An
agent being deleted keeps counting until its deletion ends: its volume and
VM exist until then.

### 3. Creation: a typed refusal before any reservation

`POST /v1/agents` checks the organization's quotas in its transaction, under
the organization's row (every creation of one organization already takes it)
and the quota lock (§6), before the host's storage checks and before any row
is written. Past a quota it answers **409 `organization_quota_exceeded`**,
with `quota`: `max_agents`, `max_storage_mib`, `max_memory_mib` or
`max_vcpus`. No agent, operation, enrollment or volume exists afterwards.

409 rather than 429: waiting does not help. An agent must be deleted, or the
operator must raise the quota; a client that retries 429 by itself would loop.
The existing `attachment_quota_exceeded` keeps its 429. A 409 also puts the
refused attempt in the organization's trail (TEN-009, ADR 014 §10).

The organization's quota comes before the host's own limits, so that its
answer does not depend on the host's load. The host's storage limit still
answers 503 `storage_capacity_unavailable` (its tenant path is now tested).

### 4. Wake and delivery: work waits, as in ADR 017

A wake, a delivery or a resume past the organization's active VMs, vCPUs or
RAM is **accepted and waits**; it is not refused. Why:

- EVT-007 asks that work wait through a resource shortage and then resume,
  or expire with a clear error. ADR 017 made a full host wait rather than
  refuse; an organization at its quota is the same shortage, local to the
  organization. Its VMs stop through idle policies, sleeps and the ends of
  their work, and the waiting work then boots.
- A refusal at the API would be wrong either way: usage changes between the
  request and the boot, which the worker performs later.
- Deliveries between agents and resumes have no caller to refuse.
- The work's deadline bounds the wait: an instruction that never left its
  queue dies with `capacity_unavailable`, as for a full host.

How it waits:

- **The boot is the reservation.** `claimPlacement` checks the quotas in the
  transaction that turns the placement `STARTING`, under the quota lock: this
  check is authoritative, on one host or several. Past a quota it returns
  `OrganizationQuotaError`, and the job tries again later without spending a
  delivery attempt (retry reason `organization_quota`).
- **The capacity queue orders it.** `AdmitToSlot` puts the agent in its
  host's capacity queue with the reason `organization_quota`; it shows
  `QUEUED`, with `queue_reason` `organization_quota` (`capacity` for a full
  host).
- **No head-of-line blocking.** A waiter for its own organization's quota
  holds no slot against other organizations: it does not count among the
  older waiters they wait for. Order among waiters for the host is unchanged.
- **Order within the organization.** An agent fits only if its
  organization's older waiters on the host fit with it: newer work of an
  organization does not overtake its older work.
- **The organization's idle VMs make room.** The organization's oldest
  waiter on the host may stop the organization's own VMs on this host that
  are not computing, by ADR 017's rule (idle first, then those that only
  wait, the least recently active first, never one that computes), as many
  as its need takes. Those stops free host slots too. VMs of the organization
  on another host are not stopped for it.
- **Room offered at once.** Each pass makes available the jobs of the oldest
  waiter for the host and of each organization's oldest waiter for its quota.
- A credential renewal the quota refuses waits for the next pass. A boot
  only for a barrier is never refused.

### 5. Changing quotas

- A quota below current usage is accepted: nothing running stops and nothing
  is deleted. New creations are refused, and new boots wait until usage falls
  under it.
- A `max_vcpus` or `max_memory_mib` below what one of the organization's
  agents needs alone is refused, **409 `quota_below_agent`** with `quota`:
  that agent could never boot, and its work would wait until its deadline
  every time. Creation refuses the converse (§3).
- Each change is audited in the organization's audit (`organization_audit`,
  action `organization.quotas_set`, with `changed`), which its trail shows
  when the values changed. A replay of the same key adds nothing. The values
  are in `GET .../quotas`, with `updated_at`.

### 6. Races

Every check and every change of one organization's quotas takes the
transaction-scoped advisory lock `organization-quota/<organization>`: the
creation (after the organization's row and the host's row), the boot's claim
(after the agent's and the placement's rows) and the change (after the
organization's row). It is the last lock each takes, so it adds no cycle.
Concurrent creations, and concurrent boots on one host or two, never exceed
a quota; a change of quotas and a creation that race never leave an agent
larger than the quota. `AdmitToSlot` only orders; when its decision races a
boot on another host, the claim refuses, and the agent waits at its next
attempt.

## The models

- `fair_admission.qnt`: unchanged. It models one admission queue with
  exclusive clients, one per slot, and no organizations. Without quotas the
  Go queue behaves as before, and `TestCapacityQueueProjectsFairAdmissionDeadOwner`
  still projects `deadOwnerTest`. With quotas, a second resource per
  organization appears that the model does not have: "new work never
  overtakes older work" now holds among waiters for the host and within an
  organization, while a waiter for its own organization's quota may be
  overtaken by other organizations, by design. A model of that rule (two
  organizations, one quota, a shared slot pool, checking no excess and no
  starvation within an organization under fairness) would be a new module;
  it is not written.
- `barrier_capacity.qnt`: unchanged. Barriers are neither counted nor
  refused; the quota adds no wait to them.
- The quota's safety (never more than the limit) rests on one serialized
  check, the claim's; the PostgreSQL tests with concurrency check it.

No model changed, so no Quint check was owed; TLC and Apalache need Java,
which this machine lacks, and Quint is not installed in this worktree.

## Consequences

- An organization at its VM quota with idle VMs gets its new work booted by
  stopping one of its idle VMs; with only computing VMs, its new work waits.
  Other organizations are not slowed by it.
- An operator's capacity alert (`AgentCapsuleWorkWaitingForCapacity`) counts
  only work waiting for the host. Work waiting for its organization's quota
  is counted apart (`agentcapsule_worker_agents_waiting_for_quota`): it is
  the organization's limit, not a lack of hosts.
- The quotas do not choose a host, and do not move agents between hosts.
  Agents are created on the API's host, as before.

## What was built

- Migration 0045: `organization_quotas`; `capacity_waits.reason`; the audit
  action `organization.quotas_set`.
- `internal/controlplane/organization_quotas.go`: the quotas, the creation
  and boot checks, the routes' store functions. `capacity_queue.go`: the
  reason, the room per organization, the stops for the quota, the promotion
  per organization. `placements.go`, `tenant_agents.go`: the checks.
- The worker: the stops for the quota, the retry reason, the gauge, the
  renewal's wait. The API: the three routes, the problem's `quota`, the
  agent's `queue_reason`.
- Docs: [organizations.md](../api/organizations.md),
  [agents-assignments.md](../api/agents-assignments.md),
  [examples.md](../api/examples.md), [rbac.md](../api/rbac.md),
  [worker.md](../worker.md), [observability.md](../observability.md), the
  OpenAPI.

Not built: per-agent ceilings within the organization (ADR 012 question 1,
P1); disk throughput per organization (P1); quotas on archives; a default
quota for new organizations (question 6); an operator command beside the
route.

## Tests

Each new behaviour's test failed before its change (the new APIs: they did
not compile):

- `internal/controlplane`: `TestConcurrentCreationsNeverExceedTheOrganizationsQuotas`
  (failed: 8 agents created under a quota of 3),
  `TestConcurrentBootsNeverExceedTheOrganizationsQuotas` (failed: 7 boots
  under a quota of 3; also fails with the check but without the lock),
  `TestWorkWaitsForItsOrganizationsQuotaWithoutHoldingBackOthers` (failed:
  work admitted past the quota), `TestWorkStopsItsOrganizationsIdleVMsForItsQuota`,
  `TestQuotaChangesAndCreationsNeverLeaveAnAgentThatCannotBoot` (fails without
  the locks of the change), `TestThePlatformSetsAnOrganizationsQuotas`,
  `TestTenantCreationPastTheHostStorageIsRefusedBeforeAnyReservation` (the
  host's limit on the tenant path: passed before, untested until now).
- `internal/api`: `TestHTTPOrganizationQuotas`; the three routes' rows of
  `TestRBACMatrix`; `TestHTTPExamplesRunAsWritten` with the quotas section.
- `internal/worker`: `TestRetryReasons` (`organization_quota`).

KVM tests to run (root): those of ADR 017 §6, since `bootForWork` changed:
`TestDispatchPreparationAndOneSlotCapacity`,
`TestBarrierCapacityOneSlotThreeStoresAndReplay`,
`TestDispatchServiceClosureExpirationAndDeletion`,
`TestProductWorkerStopsBootingAGuestThatCrashesAtBoot`. A KVM test of a wake
waiting for its organization's quota, then booting once the organization's
other VM sleeps, is not written.

## Questions for the product owner

1. **Who sets the quotas.** Acme's owner wants more agents than the operator
   allowed. Options: (a) only the operator sets them; the organization reads
   them (built); (b) the organization's owner may also set lower limits for
   itself, within the operator's. Recommendation: (a) for the MVP; (b) is a
   small addition later.
2. **A wake past the VM quota.** Acme may run 2 VMs; both run and Alice wakes
   a third agent. Options: (a) the wake is accepted and waits, the agent
   `QUEUED` with `queue_reason: organization_quota`, until one of Acme's VMs
   stops (built); (b) the wake is refused at once with 409
   `organization_quota_exceeded`. Recommendation: (a), as for a full host
   (ADR 017): work waits through a shortage, and a refusal would race the
   boot anyway.
3. **A quota smaller than an agent.** Acme has an 8 GiB agent and the operator
   sets its RAM quota to 4 GiB. Options: (a) refused with 409
   `quota_below_agent` until the agent is deleted (built); (b) accepted, and
   that agent's work waits until its deadline every time. Recommendation: (a).
4. **An agent being deleted.** Acme deletes an agent and creates another at
   once, at its agents quota. Options: (a) refused until the deletion ends,
   since its volume and VM still exist (built); (b) the deleted agent stops
   counting at the deletion's request. Recommendation: (a); a deletion ends
   within minutes.
5. **Stopping the organization's idle VMs.** Acme is at its VM quota with one
   idle VM and one busy; Bob's invocation arrives for a third agent. Options:
   (a) the idle VM is stopped and the third agent boots (built, ADR 017's
   rule); (b) the invocation waits for the idle VM's idle policy.
   Recommendation: (a).
6. **Defaults for a new organization.** Options: (a) no limit until the
   operator sets one (built); (b) an installation-wide default the operator
   configures once. Recommendation: (a) for the MVP, (b) when the platform
   hosts organizations it does not know.
