# EVT-02 — Work that waits for capacity, and replay of dead letters

Date: November 16, 2026. **Status: built on November 16, 2026**, with
defaults pending the product owner (see [Questions](#7-questions-for-the-product-owner)).
On KVM, the product tests of the capacity paths passed on November 17, 2026,
and the runtime's on November 18, 2026 (see [Validation](#6-validation)).
References: EVT-002, EVT-005, EVT-006, EVT-007 and RUN-011 of the
[product spec](../product.md), EVT-02 of the [roadmap](../../ROADMAP.md),
[ADR 003](003-restore-rpo.md) (reruns), [ADR 007](007-delivery-closure-and-priority.md)
(dead deliveries, no priority), [ADR 012](012-limits-restart-budgets-egress.md)
(restart budgets), the models
[fair_admission.qnt](../../spec/fair_admission.qnt),
[barrier_capacity.qnt](../../spec/barrier_capacity.qnt) and
[service_progress.qnt](../../spec/service_progress.qnt).

## Context

EVT-02 left two items: "re-admission after capacity returns" and "operator
replay of dead letters". EVT-007 asks that work wait through a resource
shortage and then resume, or expire with a clear error. RUN-011 asks for a
usable status on saturation (`FAILED` or `QUEUED`) and no spawn loop.

A host runs at most `max_active` VMs. An organization's queues are bounded
per agent and in total. Both are "capacity", and they act at different times:
the queue limits at admission, the host's slots at delivery.

## 1. Today's behaviour

The lines are those of `mvp-integration` at `b4cdcd0`.

### A new request

`checkQueueRoom` counts the organization's waiting instructions under an
advisory lock (`internal/controlplane/instruction_queues.go:82-97`) inside the
admission transaction, after the receipt lookup
(`instructions.go:59`, `:134`). A full queue returns `ErrQueueFull` before any
write, and the API answers 429 `queue_full` with `Retry-After: 5`
(`internal/api/server.go:205-207`). A replay of an accepted request is
answered from its receipt and never refused. The host's capacity plays no part
at admission. **Met.**

### Accepted work waiting for a VM slot

- **A delivery to a stopped agent did not wait: it evicted.** The dispatcher
  boots the recipient under the host's exclusive turn
  (`internal/worker/control_linux.go:69-117`). On `ErrCapacity` it called
  `makeBarrierCapacity` (`:98-103`), which stopped the running VM with the
  smallest agent ID, whatever it was doing (`:191-207`), then booted.
- **That VM's work was then dropped until something else woke it.** Nothing
  boots an agent whose VM stopped while it held work in progress. An
  invocation it had acknowledged "working" failed at its `result_due_at` with
  `work_timeout`, an error that does not say why. A crash had the same effect.
  [worker.md](../worker.md) said so: "its general wake and a sufficient
  residence time are not yet guaranteed".
- **A wake did not evict; it retried.** `lifecycleOperation` boots without
  eviction (`internal/worker/lifecycle_operations_linux.go:46`); `ErrCapacity`
  retries its job with backoff, without end.
- **No order among what waited.** A job that failed moved to the tail
  (`internal/controlplane/work.go:149-151`) and waited its backoff, 1 to 30
  seconds by default (`internal/worker/dispatch_linux.go:21-30`, `:104`;
  `work.go:184`). When a slot freed, the first job past its backoff took it:
  newer work could overtake older work.
- **What spends nothing, and what expires.** A boot failure spends no
  delivery attempt (retry reason `capacity`,
  `internal/worker/telemetry_linux.go:22`, `:46-47`). An instruction past its
  deadline that no attempt reached dies without its agent
  (`internal/controlplane/instruction_delivery.go:356-377`, discovered by
  `work.go:60-61`), `close_reason` `expired`, `error_code` `delivery_failed`
  (`:432`). Nothing runs after its deadline: a claim refuses it (`:128-130`).
- **Status.** A stopped agent whose work waited showed `STOPPED`
  (`tenant_agents.go:58-62`); `converged` was false if a wake was open.

### Work refused for capacity

Only admission refuses, for the queue limits. That work is never admitted
again by itself: the client retries after `Retry-After`. Accepted work is
never refused for a full host.

### What EVT-007 needs

For a refused client: `Retry-After`, as built. For accepted work: it must
wait without being dropped, resume when capacity returns, and otherwise expire
at its deadline with a clear error. Today's gaps:

1. work evicted for capacity (or by a crash) is not resumed when capacity
   returns;
2. a delivery evicts a VM in the middle of its work, which then fails late
   with `work_timeout`;
3. what waits has no order: newer work overtakes older work;
4. waiting is not visible (`STOPPED`, not `QUEUED`), and an expiry while
   waiting says only `delivery_failed`.

"Re-admission after capacity returns" is therefore built as: accepted work,
and work interrupted by a stop, boots again in arrival order once a slot
frees, or dies at its deadline with `capacity_unavailable`.

## 2. Decision

### 2.1 What work may stop

Work that needs a VM for a stopped agent (a delivery, a wake, a resume) takes
a free slot, or stops a VM that is not computing:

1. an idle one, which owes no work (`owesWork`: no pending delivery, no open
   operation, no open exchange, no model call in flight; the idle policy's own
   rule);
2. then one that only waits: for its next delivery, a wake, or another
   agent's answer;

the least recently active first in each group. It never stops a VM that is
**computing**: an invocation acknowledged "working" or a request being
processed, before their deadlines, unless the agent waits for another agent's
answer; or a model call in flight.

An agent that waits for another agent's answer is not computing on purpose.
If it held its slot, a full host could never boot the agent it waits for, and
both would wait until a deadline. Stopped, it loses nothing: the answer's
delivery boots it again and its harness resumes. A barrier is unchanged in
principle: it reserves its slot ahead of new work (`barrier_capacity.qnt`) and
may stop any VM, now an idle one first and a computing one last.

### 2.2 The capacity queue

When no slot can be had, the agent waits in its host's capacity queue
(`capacity_waits`, migration 0035), keeps its first place when asked again,
and shows `QUEUED`. Its job spends no attempt. An agent boots only when fewer
older waiters remain than the slots it could use (free, then stoppable):
new work never overtakes older work that waits, whatever its organization.
This is the `fifo` policy of `fair_admission.qnt`, with exclusive clients, one
per slot. A waiter whose work is no longer due (delivered, canceled, dead,
its agent `FAILED`, running or deleted) leaves the queue at the next decision;
one whose delivery just expired stays until that delivery dies, so that the
death can say why. An agent with nothing that needs a slot never waits: the
wake of a `FAILED` agent still ends with `restart_budget_exhausted`.
When an agent boots, the next waiter's jobs are tried at once; each pass does
the same for a slot freed by a sleep, a deletion or a crash. Fairness is
first-come first-served across organizations, not a share per organization:
the model has no such share, and priority is P1 ([ADR 007](007-delivery-closure-and-priority.md)).
[ADR 021](021-organization-quotas.md) adds an organization's own quotas on
VMs, vCPUs and RAM: work past them waits in the same queue, and such a
waiter does not count among the older waiters other organizations wait for.

Code: `AdmitToSlot`, `SlotTaken`, `PromoteCapacityHead`, `EvictionOrder`
(`internal/controlplane/capacity_queue.go`); `bootForWork` and
`makeBarrierCapacity` (`internal/worker/control_linux.go`), used by deliveries
and wakes.

### 2.3 Resume

An agent whose VM stopped while it held work in progress gets a `resume` job
(`DiscoverWork`): the worker boots it again through the capacity queue
(`Placements.resume`), and its harness takes the work up from its SQLite
intents (the reference harness's and capsule-adapter's pending jobs run again
at start). Not resumed: once that work ended or passed its deadline, a
`FAILED` agent, or an agent someone asked to sleep after the work began
(default pending the product owner, question 1). A crash spends the restart
budget, so a guest that keeps crashing stops being booted (RUN-011, no spawn
loop).

### 2.4 Clear status and error

- The agent's `state` is `QUEUED` while it waits (RUN-011).
- An instruction whose deadline passed, unsent, while its agent waited for a
  slot fails with `error_code` `capacity_unavailable` (`close_reason`
  `expired`). An unsent one that expired for another reason keeps
  `delivery_failed`; one an attempt may have reached keeps
  `delivery_outcome_unknown`.
- The operator sees `agentcapsule_worker_agents_queued`,
  `agentcapsule_worker_capacity_oldest_wait_seconds` and the alert
  `AgentCapsuleWorkWaitingForCapacity` (more than 10 minutes).

### 2.5 Replay of dead letters

The operator (`agentcapsule-admin replay-dead-letter -operation-id <id> -key
<k> [-ttl <d>]`) and an organization's owners and administrators
(`POST /v1/invocations/{id}/replay`, `quota:manage`, the right that manages
the organization's queues) put an instruction that died without reaching its
agent back in its agent's queue.

| | A rerun (ADR 003) | A replay |
|---|---|---|
| Identifier and event ID | kept | kept |
| Attempts | new budget | new budget |
| Window | its TTL again, from the decision | its deadline kept; a new window (1 s to 24 h) only when given, and required once the deadline passed |
| Place in the queue | its first place: the restore took back what came after | the end: the agent processed later work since, and receives events in queue order |
| Mandate | kept, remaining budget, expiry moved | the same, valid again (only a rerun that died unsent has one) |
| Requester | must still hold `invoke` | must still hold `invoke` (`requester_revoked`) |
| Content | `input_purged`, `attachments_purged` | the same refusals |
| Queue limits | not counted | counted (429 `queue_full`) |

A replay is refused, and nothing changes, when an attempt may have reached
the agent (`outcome_unknown`): the dead letter's retirement fenced
`event/<id>` in the agent's store for good, so the same event ID can never
apply, and another event ID could apply it twice (default pending the product
owner, question 2). Also refused: anything but a dead letter
(`invalid_transition`), an agent being deleted (`agent_unavailable`), past
the deadline without a new window (`expired`). The administrator gains no
access to the content or the result (D-02): they stay the requester's.

Each replay is audited in `instruction_replays` (who: the operator or the
principal; when; how the instruction had died; its new deadline), in the
replay's transaction. The invocation is `accepted` again and shows
`replayed_at`. The API route is idempotent through its key, the command
through `-key`. A replay is a person's act: it adds no automatic retry loop
(EVT-005).

Code: `internal/controlplane/instruction_replays.go`, the route in
`internal/api/instructions.go`, `cmd/agentcapsule-admin/replay_linux.go`.

## 3. The models

- `fair_admission.qnt`: unchanged. The capacity queue follows its `fifo`
  policy with exclusive clients. `TestCapacityQueueProjectsFairAdmissionDeadOwner`
  replays `fairAdmissionExclusive.deadOwnerTest` against PostgreSQL: client 2
  heads the queue and boots, leaves, queues again behind client 1, which boots
  first; 2 does not boot while 1 holds the slot. The model is a
  three-client component; the projection does not prove the Go service.
- `barrier_capacity.qnt`: unchanged. Barriers keep priority and may stop the
  resident VM (`evict`); the model does not choose a victim among several, so
  the new order (idle first) is outside it.
- `service_progress.qnt` (P3): unchanged. Its `admit` already takes the head
  of one admission queue and needs the VM free (`running == Set()`): new work
  never preempts work being executed. Go now follows this more closely than
  before, when a delivery stopped any VM. P3 does not model a VM stopped by a
  barrier and booted again; the resume job is outside it.
- `delivery.qnt`: unchanged. Its `seq` is both an event's identity and its
  place. In Go the event ID (the mailbox ID) is the identity and `seq` the
  place. A replay keeps the identity and takes a new place at the end, and
  only for an event no attempt may have reached, which the harness never
  processed: `effectOnce` and `fifo` (over the places the harness processes)
  hold. A model of the replay would need identity and place apart; it is not
  needed for these two properties.

No model changed, so no Quint check was owed; the existing runs of the three
models were run again (§6). TLC and Apalache need Java, which this machine
lacks.

## 4. Consequences

- A host full of computing VMs makes new work wait, instead of stopping a
  computation. That work boots in order as computations end, or dies at its
  deadline with `capacity_unavailable`. A computing agent that keeps
  receiving work keeps its slot: deliveries to a running VM need no slot.
  Work waiting behind it can then expire (question 3).
- An agent waiting for another agent's answer may be stopped for other work;
  the answer boots it again.
- A barrier may still stop a computing VM; that agent resumes once capacity
  returns.
- An evicted VM is still stopped without quiescence, as before.

## 5. What was built

- Migration 0035: `capacity_waits`, the `resume` job kind,
  `instruction_replays`.
- The capacity queue, the eviction order, the resume job, the `QUEUED` state,
  `capacity_unavailable`, the metrics and the alert.
- The replay: store, API route, operator command, `replayed_at`.
- `owesWork`, the idle policy's work rule, shared by the idle policy and the
  eviction order (no change to the idle policy).
- Docs: [worker.md](../worker.md), [agents-assignments.md](../api/agents-assignments.md),
  [observability.md](../observability.md), the OpenAPI.

Not built: a share of capacity per organization (P1 with priority); a
minimum residence time; a quiesced stop for eviction; replaying deliveries
between agents (only instructions have dead letters a person owns).

## 6. Validation

Tests, each failing before its change (new APIs: they did not compile):

- `internal/controlplane`: `TestAFullHostAdmitsWaitingWorkInArrivalOrder`
  (failed on `QUEUED`), `TestWorkWaitingPastItsTTLNeverRunsAndLeavesTheQueue`
  (failed on `capacity_unavailable`), `TestInterruptedWorkIsResumed` (failed:
  no resume job), `TestWorkStopsOnlyVMsThatAreNotComputing` and
  `TestAnAgentWaitingForAnotherDoesNotHoldItsSlotAgainstIt` (failed against
  an idle-only rule), `TestAFailedAgentDoesNotWaitForCapacity` (failed: the
  wake waited), `TestCapacityQueueProjectsFairAdmissionDeadOwner`,
  `TestAnAdministratorReplaysADeadLetter`,
  `TestAReplayAfterTheDeadlineNeedsANewWindow`, `TestWhatCannotBeReplayed`,
  `TestTheOperatorReplaysADeadLetter`.
- `internal/api`: `TestHTTPReplayOfADeadLetter`, and the replay route's row of
  the authorization matrix (`TestRBACMatrix`, [rbac.md](../api/rbac.md)).
- `cmd/agentcapsule-admin`: `TestReplayDeadLetterCommand`.
- `deploy/prometheus/alerts_test.yml`: `AgentCapsuleWorkWaitingForCapacity`.

Results, on November 16, 2026:

- The PostgreSQL campaign `scripts/verify-postgres.py`: passed, 1,248 tests
  in the integration phase (748 top-level, none skipped), every test above
  among them, then the crash and recovery phases (local evidence
  `quint/results/verify-postgres-evt02-readmission`).
- The unit tests of `internal/controlplane`, `internal/api`,
  `internal/worker`, `internal/runtime` and `cmd/agentcapsule-admin` with
  `-race`; `go vet` of these packages, with the KVM build tags for the
  worker; `scripts/check-repo-hygiene.py`.
- `scripts/verify-alerts.py` with promtool (Prometheus 3.5.0, pinned image):
  37 rules checked, the rule tests pass.
- Quint 0.33.1: every model typechecks; the runs of `fair_admission.qnt`
  (`noOvertakeTest`, `deadOwnerTest`), `barrier_capacity.qnt` (2) and P3 (38)
  pass; `quint run` finds no `safety` violation in `fairAdmissionExclusive`
  (20,000 samples of 30 steps), `barrierCapacityOk` (20,000 of 30) or
  `serviceProgressOk` (200,000 of 40).

KVM tests to run (root): `TestDispatchPreparationAndOneSlotCapacity` (the
resident sender now waits for an answer, so it is stopped as before),
`TestBarrierCapacityOneSlotThreeStoresAndReplay`,
`TestDispatchServiceClosureExpirationAndDeletion`,
`TestProductWorkerStopsBootingAGuestThatCrashesAtBoot` (wakes go through the
queue), and a new test still to write: on a one-slot host, a barrier stops an
agent working on a deferred invocation, and the resume job boots it again so
that it completes. On November 17, 2026, with guest v26,
`TestProductWorkerStopsBootingAGuestThatCrashesAtBoot` passed, and so did
`TestProductWorkerWakesQueuesAndKeepsAWorkingAgentAwake`: on a one-slot host,
work for a stopped agent waits `QUEUED` while another computes, then boots
once the slot frees. The other three passed on November 18, 2026, in
`scripts/verify-runtime.py` at 1b4a7c3, with control guest v8
(`quint/results/runtime-20261118T131446Z`). The test of the resume is not
written.

## 7. Questions for the product owner

1. **A sleep during work.** Alice puts her agent to sleep while it works on an
   invocation it acknowledged "working". Options: (a) the sleep wins: the
   agent stays asleep and the invocation fails at its due time unless she
   wakes it (built); (b) the platform boots it again to finish the work, as
   it does for a new invocation. Recommended: (a); a sleep is a person's act.
2. **A dead letter whose outcome is unknown.** An instruction died after an
   attempt may have reached the agent. Options: (a) refuse its replay; the
   requester sends a new invocation if the work did not happen (built); (b)
   replay it under a new event ID, at the risk of running it twice.
   Recommended: (a).
3. **A host full of computing agents.** Options: (a) new work waits until a
   computation ends or the work's deadline passes (built); (b) after a
   minimum residence time, new work stops a computing agent, which resumes
   later and starts its computation again. Recommended: (a) for the MVP,
   with the alert telling the operator to add capacity.
4. **Who replays.** Options: (a) the operator and the organization's owners
   and administrators (built); (b) also agent operators; (c) also the
   requester, for their own dead letters. Recommended: (a); a requester can
   send the work again as a new invocation.
5. **Where a replay goes.** Options: (a) the end of the agent's queue
   (built); (b) its first place, like a rerun. Recommended: (a); the agent
   already processed what came after it.
