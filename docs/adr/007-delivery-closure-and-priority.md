# D-04 — Delivery closure and priority

Date: November 16, 2026. **Status: decided by the product owner on November
16, 2026** (see [Decision](#decision)); **built on November 16, 2026**: §2
items 1 to 6 (see [What was built](#6-what-was-built)). **Amended on November
16, 2026** (§7): a request's closure fences its two parties only, the findings
of an independent review are fixed or recorded, and the content of a request
closed before delivery gets a retention (a default pending the product
owner). This record states the two decisions, what the code did when they were
taken, what changes, and what the models say.
References: product spec §3, EVT-005, EVT-006 and §5
([product.md](../product.md)), EVT-02 and D-04 of the
[roadmap](../../ROADMAP.md), the models
[service_progress.qnt](../../spec/service_progress.qnt),
[concurrent_protocol.qnt](../../spec/concurrent_protocol.qnt) and
[barrier_capacity.qnt](../../spec/barrier_capacity.qnt).

## Context

Agent A sends a **request** to agent B. B answers with a **reply** (content)
or the request ends with a **status** (no content: `DECLINED`, `EXPIRED`,
`CANCELED`, `FAILED`). The platform carries the reply or the status to A as a
**delivery**: one entry of A's mailbox, handled in arrival order. Each
**attempt** may reach A's VM; a delivery has at most `attempt_limit` attempts
(3). A delivery ends **delivered**, **dead** or **canceled**. It **dies** when
its attempts are used up or its own deadline passes. EVT-005 forbids an
unbounded loop, so a delivery that keeps failing must die.

D-04 asked two questions:

1. What happens to a request when the delivery of its reply or status to A
   dies.
2. Whether the MVP has priority, as EVT-006 asks ("TTL, priority, queue
   limits per tenant and agent"), when each agent handles its work strictly in
   arrival order and the progress model proves every request completes under
   that order.

## Decision

1. **A reply that cannot be delivered.** Chosen: **(a) the request is closed
   as replied. The reply stays readable by A when it comes back, until the end
   of retention, and an event tells the administrator.**
   - Rejected: (b) close it as failed on both sides. B did its work, and a
     replied request cannot change state (`request_state_guard`,
     `internal/controlplane/schema.sql:462-468`).
   - Rejected: (c) retry until the request's deadline instead of a fixed
     number of attempts. An A that keeps failing would keep its mailbox head
     until then, and every delivery behind it would wait.
2. **Priority.** Chosen: **(a) no priority in the MVP: keep arrival order;
   priority moves to P1.**
   - Rejected: (b) priority with aging. It needs a revision of the progress
     model.
   - Rejected: (c) reserving a share of VMs for some organizations. Same
     problem.

## 1. Today's behaviour

This section is the code when the decisions were taken. §2 says what changed;
§6 what was built.

### How a delivery to A dies

1. B replies. One transaction sets the request to `REPLIED` with its reply,
   and adds the reply's delivery to A's mailbox
   (`internal/controlplane/replies.go:99-111`). The delivery's own deadline
   is 7 days (`closure.go:237-238`). Its attempt limit is the column default,
   3 (`schema.sql:150`).
2. Before an attempt, the worker prepares A: wake, capacity, credentials, the
   channel's health (`internal/worker/control_linux.go:71-120`). A failure
   there spends no attempt (`control_linux.go:104-107`).
3. Each claim spends one attempt (`delivery.go:113-195`). A failed send leaves
   its lease to expire, 30 seconds by default; the job is retried with
   backoff, 1 to 30 seconds by default
   (`internal/worker/service_config_linux.go:345-346`).
4. When the claim finds the delivery past its deadline (`delivery.go:152-154`)
   or out of attempts (`delivery.go:158-160`), the dispatcher retires it
   (`delivery.go:420-423`, `452-454`).
5. `RetireDelivery` marks it closing, publishes the revocation subject
   `event/<id>`, fences it in A's store, then sets it `DEAD` and removes its
   outbox row (`delivery.go:341-375`). The fence boots A for the barrier if it
   is stopped (`control_linux.go:151-171`).

A status takes the same path.

### The request on each side

There is one request row for both sides. It stays `REPLIED`: the death touches
only the delivery. `sender_notified` stays false; only an acknowledgment sets
it (`delivery.go:266-269`). Both owners got an inbox entry when B replied
(`closure.go:245-251`). B's side is finished: its harness committed its work
before replying.

### What A can read

- **A's agent cannot read the reply.** The platform channel's
  `/v1/agent-requests/{id}/status` returns state, recipient and deadline
  only; "the reply itself arrives as a 'reply' event, never through this read"
  (`internal/capsuleprotocol/peer_status.go:26-35`,
  `internal/controlplane/peer_reads.go:60-90`,
  `internal/worker/platform_linux.go:277-288`). A dead delivery is never sent
  again.
- **A2A `GetTask` stays `WORKING`.** capsule-adapter learns the reply only
  from the event (`internal/agentadapter/engine.go:183-197`). `GetTask` asks
  `/status`, gets `REPLIED`, and shows `TASK_STATE_WORKING` with
  `request_state` `PROCESSING` (`internal/agentadapter/a2a.go:424-448`,
  `495-500`). It stays so.
- **A status is readable.** For a dead status, `/status` gives the final
  state, and the adapter records it (`a2a.go:440-446`). For a status, A's
  read already meets decision 1.
- **People.** `GET /v1/agent-requests/{id}` returns the reply to the owner of
  either agent (`owner_messaging.go:146-187`), dead delivery or not. An
  organization's agents have no owner (`migrations/0010_tenant_agents.sql:7-10`),
  so no person reads their requests through the API.

### How long the reply is kept

With no end. A reply's retention starts only when its delivery is acknowledged
(`delivery.go:277-284`, `transit.go:435-439`). A dead reply keeps
`purge_after` empty, so the purge never takes it (`transit.go:443-458`). Only
the deletion of A or B removes it (`revocation.go:79-80`). An instruction is
treated differently: its input's retention starts when its delivery dies
(`instruction_delivery.go:393`). The API docs already say that requests refused
or expired without delivery have no purge deadline
([api/README.md](../api/README.md#private-exchanges-and-consent)).

### What tells an operator

Nothing marks the death. Each failed attempt is a retried job
(`job_retried`, `agentcapsule_worker_job_retries_total`). The death itself
ends the job as done: `job_done` and
`agentcapsule_worker_jobs_total{kind="delivery",outcome="done"}`
(`internal/worker/dispatch_linux.go:93-95`,
`internal/worker/telemetry_linux.go:150-161`, `193-209`).
`AgentCapsuleJobsFailing` needs a job failing three times or more for 15
minutes (`deploy/prometheus/alerts.yml:36-42`); with the defaults a delivery
dies within a few minutes, so it does not fire. Nothing is audited. Unlike an instruction
(`close_reason`, `instruction_delivery.go:382-384`), the delivery keeps no
reason.

### Other ways a delivery ends without reaching A

- **A never boots, or fails its health check.** No attempt is spent, so the
  delivery never dies. It keeps A's mailbox head; the job is retried with
  backoff, without end. Its 7-day deadline is checked only in a claim, which
  needs a prepared A. `AgentCapsuleJobsFailing` and
  `AgentCapsuleVMBootFailures` fire.
- **A comes back after 7 days.** The first claim finds the deadline passed
  and the delivery dies at that moment, though A could now take it.
- **B is deleted.** Every payload B is a party to, the reply included, is
  purged when its deletion is requested (`revocation.go:79-80`). Once the
  deletion's barriers pass, a pending reply is canceled, and A gets a status
  without content, `REPLIED` with the reason `content_revoked`; a dead reply
  not yet received gets it too (`revocation.go:305-340`). capsule-adapter
  ignores a status whose state is `REPLIED` (`engine.go:221-226`), so the
  task stays `WORKING`.
- **A is deleted.** Its deliveries are canceled; there is no one to tell.

### Against decision 1

| Part of decision 1 | Today | Matches |
|---|---|---|
| The request is closed as replied | `REPLIED` from B's reply; the death does not touch it | Yes |
| The reply stays readable by A when it comes back | A's agent cannot read it; the A2A task stays `WORKING`. The owner of a personal agent can | No |
| Until the end of retention | No retention starts; kept until A or B is deleted | No |
| An event tells the administrator | The death counts as a job done | No |

### Priority today

There is none, in the code, the API or the schema. Each agent's mailbox is
FIFO: only its head is claimed (`delivery.go:87-108`) or discovered as work
(`work.go:53-58`). `instruction_queues.go:27-30` and
`openapi/openapi.yaml:1306-1307` say so.

`PRIORITY` in the models is not a user-facing priority. In
`service_progress.qnt` (lines 50, 57-62), new work is not admitted while a
barrier is pending: a request closing, or a notification being retired. In
`barrier_capacity.qnt` (lines 21-25), a queued store barrier takes the VM slot
before a new ordinary call. Both are rules that keep barriers from being
starved, and the code follows them. Each model has an instance without the
rule (`serviceProgressNoPriority`, `barrierCapacityNoPriority`), of the
broken kind [spec/README.md](../../spec/README.md) describes.

## 2. What changes

For decision 1. The request's state needs no change. Each item lists the test
that fails without it.

1. **Start the reply's retention when its delivery dies.** In
   `RetireDelivery`'s last transaction (`delivery.go:356-375`), when the dead
   delivery is a reply, start the reply's retention as an acknowledgment does
   (`Transit.delivered`), and as `RetireInstruction` already does for an
   instruction. The dispatcher passes its transit to the retirement
   (`delivery.go:452-454`). The reply is then kept 7 days after the death,
   like 7 days after a delivery. Size: small, about 20 lines.
   - Test: `TestDeadReplyStartsRetention` (PostgreSQL). A reply fails three
     attempts and is retired. Its payload's `purge_after` is 7 days after the
     death. Once it has passed, `PurgeExpired` clears the payload and
     `GET /v1/agent-requests/{id}` has no `reply`. Today `purge_after` stays
     empty.
   - Docs: the "no purge deadline" sentence of
     [api/README.md](../api/README.md#private-exchanges-and-consent) no
     longer covers replies.
   - **Built** as written (`markDead`, `delivery.go`).
2. **Let A's agent read its reply.** `/v1/agent-requests/{id}/status` on the
   platform channel also returns the reply to the sender, while the request is
   `REPLIED` and the reply is kept. It reads it through the transit with the
   checks of the owners' read (`readPeerContent`,
   `peer_payloads.go:163-210`). Once the reply is purged, the read says so
   (reason `content_purged`, or `content_revoked` after a deletion).
   capsule-adapter's refresh (`a2a.go:424-448`) stores the reply as the
   task's result: `GetTask` then answers `TASK_STATE_COMPLETED` with the
   artifact `reply`. Without content, the task ends `COMPLETED` with no
   artifact and the reason in its metadata. The read works whether the
   delivery is pending, delivered or dead: the event stays the way a reply
   arrives, the read is how A catches up. Size: medium, about 200 lines in
   `internal/controlplane`, `internal/capsuleprotocol`, `internal/worker` and
   `internal/agentadapter`.
   - Test: `TestSenderReadsReplyAfterDeadDelivery` (PostgreSQL). After the
     death, A's VM reads the reply; B's VM and a third agent get
     `not_found`; after the purge the read has no content and says why.
     Today `/status` carries no reply.
   - Test: `TestA2AGetTaskCompletesAfterDeadReply` (agentadapter). The
     platform answers `REPLIED` with a reply and no event arrives; `GetTask`
     answers `COMPLETED` with the artifact. Today it answers `WORKING`.
   - Docs: [adapter.md](../adapter.md) ("Waiting for the answer"), the
     `REPLIED` row of [interop.md](../interop.md) ("A2A states"), the
     `/status` read in [agents-assignments.md](../api/agents-assignments.md).
   - Why a read and not a second delivery: dead is final in both models
     (§3). Sending the reply again would be a new event the models do not
     have, and it would bring back the loop that bounded attempts remove.
   - **Built** as written: `Transit.RequestStateFromVM`
     (`peer_reads.go`), `reply` and `reason` on
     `capsuleprotocol.RequestStatus` (the client refuses a malformed reply),
     the worker's read through its transit, capsule-adapter's refresh. A
     host without the transit, or an older one, still answers without the
     reply: the task then waits for the event, as before. The guest relays
     this read (`capsule-init` is built with `internal/capsuleprotocol`):
     the reply reaches capsule-adapter once the guest is rebuilt.
3. **Tell the operator.** The metric, event and alert of §4. The retirement
   reports a death, with its reason, to the dispatcher, which counts and logs
   it after the commit. Size: small, about 60 lines of Go, one rule in
   `deploy/prometheus/alerts.yml` and its tests.
   - Test: `TestDeadDeliveryIsCountedAndLogged` (worker, PostgreSQL). A reply
     dies; the counter `{kind="reply",reason="attempts_exhausted"}` is 1 and
     one `delivery_dead` event is written. Today the pass counts a job done
     and logs `job_done`.
   - Test: a promtool case in `deploy/prometheus/alerts_test.yml`: one death
     fires `AgentCapsuleDeliveryDead`; none keeps it silent.
     `scripts/verify-alerts.py` fails until the metric is registered.
   - Docs: [observability.md](../observability.md) (metrics, events, alerts).
   - **Built** as written, as `controlplane.DeathObserver`: the retirement
     reports each death once it has committed; the worker counts and logs it.
     Every series of the counter is served from zero, so that `increase()`
     sees the first death. The job that retired the delivery still logs
     `job_done`. `TestDeliveryDeathsAreReported` checks the report with and
     without the fence. The worker's test runs with no host: both deliveries
     die without booting their agent (item 5).
4. **Say what follows a death.** [worker.md](../worker.md) says a
   notification "can also exhaust its attempts" and stops there. It then says:
   the request keeps its state, the reply stays readable by A for 7 days, the
   operator is told. Size: a paragraph, with items 1 to 3.
   - **Built**, with item 5: "What follows a dead delivery".
5. **Let a delivery to an A that never boots die.** Asked by the product
   owner on November 16, 2026, after this record first listed it under "Not
   changed". Preparation spends no attempt (`control_linux.go:104-107`) and
   the deadline was checked only inside a claim (`delivery.go:152-154`,
   `instruction_delivery.go:128-130`), which needs a prepared A. So a reply,
   status or instruction to an A that never boots never died, an instruction
   stayed `accepted` past its TTL, and its job was retried with backoff for
   good, against EVT-005 and EVT-006.
   - The dispatcher checks, before preparing A, whether a reply, status or
     instruction is due to die: closing, past its deadline, or out of
     attempts with no live lease (`retirementDue`). If so, and A is live, it
     retires it without preparing A. A request is still closed by its own
     closure, and a delivery to an A being deleted is still canceled by the
     deletion, with no one to tell (`TestExpiredDeliveryToADeletedAgentIsCanceled`).
     Preparation still spends no attempt: a recipient that cannot boot must
     not use up the budget before its deadline.
   - The retirement fences A's store only if an attempt may have reached it
     (`may_have_reached`). When none was ever allowed to, none can be now:
     `AuthorizeDispatch` and `AuthorizeInstruction` need a current lease on
     an open delivery before its deadline, and the retirement holds the row.
     There is no delayed send to fence, so the delivery dies in that
     transaction, without booting A and without a revocation subject. A dead
     reply starts its retention (item 1) and A reads it when it comes back
     (item 2); an instruction fails (`delivery_failed`, `close_reason`
     `expired`) and its input starts its retention; a rerun's mandate is
     revoked, and a rerun whose requester lost the right is skipped, as a
     claim would. The death is counted (item 3) with reason `expired`, or
     `attempts_exhausted` for attempts claimed but never sent.
   - A delivery an attempt may have reached still waits for its fence: a
     delayed send could otherwise apply it after its death
     (`leased_delivery.qnt`, `noLateEffect`). It is closing, so never sent
     again, and it dies once A boots for the barrier (a restricted boot that
     accepts barriers only).
   - Tests: `TestExpiredDeliveryDiesWithoutItsRecipient` (PostgreSQL; a
     reply, a status and an instruction to an agent that never boots die at
     their deadline without a claim or a fence; the agent reads its dead
     reply when it returns). Without the change the expired delivery waits
     for its recipient. `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence`
     documents the case left to the fence. The models gain the action (§3).
6. **End the A2A task on a revoked reply's status.** When B is deleted before
   its reply reached A, A gets a `REPLIED` status without content, reason
   `content_revoked` (`revocation.go:305-340`). capsule-adapter ignored a
   `REPLIED` status (`engine.go:221-226`), so the task stayed `WORKING`. It
   now ends `COMPLETED` with no artifact and the reason in its metadata, as
   item 2 says for a reply without content. Test:
   `TestARevokedReplyEndsTheTask` (agentadapter); without the change the task
   stays `SUBMITTED` when the platform no longer answers, `WORKING` when it
   does.

Not changed:

- **`sender_notified`** stays false after a death. It means "A received it",
  and B's deletion relies on it to send A a status without content
  (`revocation.go:305-340`).
- **Preparation spends no attempt.** Item 5 makes the deadline independent
  of A's boot instead.
- **Attempts and deadline.** 3 attempts and 7 days stay. Option (c) was
  rejected.

For decision 2, only the docs change (§5).

## 3. The models

### Decision 1, items 1 to 4 and 6: no change

"Closed as replied, reply kept, delivery dead" is already a state of both
models.

- **P3, `service_progress.qnt`.** B's reply is `complete`: the job becomes
  `Terminal` with `result: Success` and `inbox: true`, and its notification
  `Pending` (`finished`, lines 63-69). Failed attempts lead to `RetiringDead`,
  then `retireNotification` makes it `Dead` (lines 110-127). `notified` counts
  `Dead` as ended (line 46), so `notificationTerminates` holds; the job stays
  terminal and successful, and `observe`, the user's read, is separate from
  the notification (lines 130-134). The trace
  `terminal-notification-failure-keeps-inbox` is this exact run: complete, two
  failed attempts, retire, observe. `TestPreimplementationP3ITF` replays it
  against PostgreSQL, and the sender's owner reads the reply after the death.
- **P1, `concurrent_protocol.qnt`.** The reply commits the request `Replied`
  with its event (lines 86-89, 147). `retire` only makes the event
  `DeadEvent`; the request's phase never changes again (lines 294-298).
  `notified`, here "A received it" (`sender_notified`), stays false.
  `retiredNotificationTest` checks this for a dead status
  (`concurrent_protocol_test.qnt:87-92`). No run covers a dead reply, though
  `beginRetire` allows one (lines 248-252). A run `retiredReplyTest`, the same
  steps on the reply's event, would document decision 1 in P1. It is
  optional.

The read of item 2 changes no state the properties use, like `observe`. The
models do not hold content, so retention is outside them.

The two models use `notified` for two things. In P3 it means the notification
ended (`Acked`, `Dead` or `Cancelled`). In P1 it means A received it. This
record says "ended" and "received".

### Item 5: the death at the deadline is now a model action

It was not one. In P3 a notification died only after `MAX_ATTEMPTS` failed
attempts, each needing its store available (`notify`), then
`retireNotification`, which needs the store and the slot; `deadline` closes
requests only. In P1 `beginRetire` needs `attempts == ATTEMPTS`, and
`retire` needs the destination's fence acknowledgment (`WAIT_ALL`), which
needs the store alive or sealed (`canFence`). Neither model had a deadline
for a reply or status, nor a death without the store. Both gain one
(November 16, 2026):

- **P3, `service_progress.qnt`.** `expireNotification(i)`: the head
  notification's deadline passes. One never attempted (`attempts == 0`)
  becomes `Dead` at once, without its store or a slot; one attempted becomes
  `RetiringDead` and waits for `retireNotification`, as an exhausted one.
  It is not assumed fair: no progress property relies on it, and
  `notificationTerminates` can only gain from it. The reliable instance,
  which promises receipt (`successfulDelivery`), has no deadline. Runs:
  `scenario20Test` (an unattempted notification dies while its store is
  lost; the sender's owner still observes the outcome), `scenario21Test`,
  `refusal21x0Test` and `scenario21x1Test` (an attempted one waits for its
  store).
- **P1, `concurrent_protocol.qnt`.** An event records `sent` once an RPC is
  allowed to carry it (`authorize`; `may_have_reached` in SQL).
  `expireEvent(e)`: a reply's or status's deadline closes it, whatever its
  attempts and lease. `retireUnsent(e)`: a closing event never sent becomes
  `DeadEvent` without its destination's fence. Closing, it can be neither
  claimed nor authorized, so no effect of it can begin. Two invariants join
  `safety`: `unsentInert` (an event never sent has no effect and no RPC past
  its claim) and `noLateEffect` (no effect is applied to a dead event, as in
  `leased_delivery.qnt`). Runs: `expiredUnsentReplyTest` (the reply dies
  while A is stopped, with no fence receipt; the request stays `Replied`,
  not received), `expiredSentReplyWaitsForFenceTest`,
  `expiredSentReplyRetiredAfterFenceTest`, and
  `unfencedRetireAllowsLateEffectTest`: retiring a sent event without its
  fence lets its RPC apply it after its death, which `noLateEffect`
  refuses. That is why item 5 fences a delivery an attempt may have
  reached.

§7 revises both actions: an unattempted notification or unsent event dies
anywhere in its queue, and only while the agents its delivery needs are
active; P3's `attempts == 0` is stated against Go's `may_have_reached`.

Checks run (spec/README.md), evidence under
`quint/results/quint-delivery-reliability/`: every model typechecks; the
`quint test` runs of P1 (29), P3 (35), the P1 prefixes, the loaded state and
the five witness guards pass; `quint run` finds no `safety` violation in
P3's five instances (200,000 samples of 40 steps each), in
`concurrentProtocolFour` (100,000 of 40) and from P1's loaded state (50,000
of 30). Not run here, for want of a Java runtime: Apalache (`quint verify`)
and TLC, so neither P1's exhaustive depth-bounded safety
(`concurrent_bounded.qnt`) nor the temporal properties of P3. The P1 and P3
conformance fixtures under `internal/controlplane/testdata/` pin their own
copies of the models and are unchanged.

### Decision 2: no change

The models have no user priority, and the MVP adds none. `PRIORITY` stays
what it is: barriers ahead of new work. Priority with aging would revise P3's
admission queue (a list served from its head, lines 57-62), P1's FIFO
(`FIFO`, and its broken instance `concurrentProtocolNoFifo`) and the barrier
queue of `barrier_capacity.qnt`. That is P1 work, with the feature.

## 4. The administrator's event

There is no `/events` stream yet (EVT-01); SSE streaming and outbound
notifications are P1 (EXT-005, EXT-007). Four forms were considered.

| Form | Who learns it | Cost | Limits |
|---|---|---|---|
| (a) A metric, a log event and an alert | The operator of the installation | Small | No tenant identifiers: it says that deliveries died, not whose |
| (b) An audit entry, `agent.delivery_dead`, in `GET /v1/audit` | The organization's `org_owner`, `org_admin`, `auditor` | Medium: a migration | The audit names the principal who answers for each action (`actor_principal_id` is required, `migrations/0010_tenant_agents.sql:52,58`); nobody answers for a death. Personal agents have no organization |
| (c) A field on the request, `GET /v1/agent-requests/{id}` | The owners of personal agents | Small | Reaches the parties, not an administrator |
| (d) An event on the `/events` stream or a webhook | The organization | Large | P1 |

**Recommended: (a) now, (d) with P1.**

- **Metric.** `agentcapsule_worker_deliveries_dead_total`, a counter, labels
  `kind` (`reply`, `status`, `instruction`) and `reason`
  (`attempts_exhausted`, `expired`). The deadline wins when both hold, as for
  instructions. Instructions are counted too: their deaths take the same
  path and cost nothing more.
- **Event.** `delivery_dead`, on standard error, with `kind`, `reason` and the
  `request_id` of the API request that started the work, if any, as
  `job_retried` has. The operator follows that ID to the person's report.
- **Alert.** `AgentCapsuleDeliveryDead`:
  `increase(agentcapsule_worker_deliveries_dead_total{kind=~"reply|status"}[15m]) > 0`,
  severity `warning`, with fixed text: "A reply or status could not be
  delivered to the agent that sent the request; the request keeps its
  outcome." Instructions are left out of the alert: their requesters see them
  as dead letters (`?state=failed|expired`).
- A worker that stops between the commit and the count loses one count. The
  dead delivery in PostgreSQL stays the record.
- Built (item 3): every series of the counter is served from zero, so that
  the alert's `increase()` sees the first death of each kind and reason.

"The administrator" is the installation's operator, the one person with a
channel for platform events in the MVP: the product owner confirmed this on
November 16, 2026, so (a) is the MVP form. Telling the organization's
administrators, (b), would need a platform actor in the audit and a
migration; it can come with (d).

## 5. Docs changed with this record

Decision 2:

- [product.md](../product.md): §3 "Invocations, events and attachments" and
  EVT-006 lose "priority" and keep TTL and queue limits; §5 lists priority
  under P1.
- [agents-assignments.md](../api/agents-assignments.md) ("Queues, deadlines
  and dead letters"): "No priority" cites this record.

Left as they are, because they stay true: `openapi/openapi.yaml:1306-1307` and
`internal/controlplane/instruction_queues.go:27-30` ("there is no priority").

Decision 1 changed, with the code: [worker.md](../worker.md) ("What follows
a dead delivery"), [observability.md](../observability.md),
[adapter.md](../adapter.md) ("Waiting for the answer"),
[interop.md](../interop.md) (the `REPLIED` row of "A2A states"),
[agents-assignments.md](../api/agents-assignments.md) (the `/status` read)
and [api/README.md](../api/README.md) (transit retention).

## 6. What was built

On November 16, 2026, on the branch `delivery-reliability`: §2 items 1 to 6,
the docs of §5, the model actions of §3, and a fix found on the way: a
request between an organization's agents, its reply and its status no longer
write inbox items with an empty `user_id` (`requests.go`, `closure.go`), rows
nobody read.

Validation: the unit tests of the packages changed, with `-race`; the
PostgreSQL campaign `scripts/verify-postgres.py`, passed (1,126 tests in the
integration phase, among them every test named above, then the crash and
recovery phases; local evidence
`quint/results/verify-postgres-delivery-reliability`);
`scripts/verify-alerts.py` with promtool (Prometheus 3.5.0), passed; the
model checks of §3, passed. The product guest was rebuilt without root
(`quint/results/product-guest-build-v21`). Not yet run: a KVM campaign with
that guest, since the guest relays the status read of item 2 (see
Remaining).

Remaining:

- **A KVM run** of the product guest rebuilt from this branch (its
  `capsule-init` relays the status read) and of the a2a-agent harness
  rebuilt with the new capsule-adapter: `TestProductWorkerTenantAgentsTalkOverA2A`,
  and the dispatch tests that retire deliveries through a real worker and
  guest (`TestDispatchServiceRequestReplyAndNotification`,
  `TestDispatchPreparationAndOneSlotCapacity`,
  `TestDispatchServiceClosureExpirationAndDeletion`,
  `TestDispatchWorkerCrashRecovery`).
- **A delivery an attempt may have reached, to an A that never boots again,**
  stays closing until A boots for its fence (item 5). Dying without it
  could let a delayed send apply it (`noLateEffect`). If the fence boot
  itself keeps failing, the agent becomes `FAILED` after its restart budget
  ([ADR 012](012-limits-restart-budgets-egress.md)): the boots stop, the
  operator sees `AgentCapsuleAgentFailed`, and the fence waits for a wake.
- **A request to or from an agent that never boots.** Its closure at its
  deadline (the `expiration` job) fenced every store of the installation, so
  any agent that never booted held every request. Since §7 it fences the
  request's two parties only: it still waits for its own party to boot for
  that barrier, and stays `DELIVERING` or `PROCESSING` meanwhile (see the
  product owner question in §7.1).
- **Request content closed before delivery is never purged.** Built in §7.3.
- **TLC and Apalache** checks of the revised P1 and P3 (§3, §7).
- **The restore risk of item 5**, recorded in §7.2 (h).

## 7. Closure scope, review fixes and closed requests' content

On November 16, 2026, on the branch `delivery-closure-scope`. Each change
names the test that fails without it.

### 7.1 A request's closure fences its two parties only

**Before.** `beginClosure` made every agent of the installation that was not
being provisioned a fence target of the request's closure
(`request_closure_targets`), as P1's `closedSafe` required
(`AGENTS.forall`). An expiry, a cancellation or a failure committed only once
every store had acknowledged `request/<id>`. One agent that never boots held
every request of the installation in `DELIVERING` or `PROCESSING`.

**What the model shows.** An event that carries `request/<id>` goes only to
the request's parties: the request to its recipient, the reply to its sender
(`subjects` and `dest` in P1). No other store can hold an effect of the
request, and fencing it protects nothing. P1 states it as `closureScope`,
which holds for every route and fails only when subjects are not scoped to
their request (`concurrentProtocolWrongRequestFence`). The model allows less
still:

- the sender's fence: a request under closure never has a reply
  (`closedNeverReplied`, now in `safety`), because a reply needs no closure
  and a closure needs an active request;
- the recipient's fence, when no attempt was allowed to carry the request
  (`sent`; `may_have_reached` in SQL): that request has no effect
  (`unsentInert`), and none can be authorized once the closure begins
  (`dispatchable`).

**Rule chosen: the two parties, always.** Both narrower rules rest on SQL state
that a restore of PostgreSQL within its 15-minute RPO
([ADR 004](004-recovery-objectives.md)) can lose: the reply that makes
"replied" and "closed" exclusive, and `may_have_reached`. A send under way at
the disaster, over SLIM for instance, could then carry `request/<id>` to a
party after a closure that did not fence it. The parties are fixed when the
request is created, and no other store receives an event that carries
`request/<id>`, restore or not. A late request is the worse case: the
recipient would work on a request its sender sees expired.

- Code: `beginClosure` inserts the two parties (`closure.go`).
- Model (P1): `canCommitClose` waits for `closureAcks`, the parties' receipts;
  `closedSafe` quantifies over the parties. Runs:
  `closureFencesOnlyItsPartiesTest` (a stopped agent that is not a party
  cannot be fenced), `closureCommitsWithoutOtherStoresTest` (the closure
  commits without it, and a send under way to the recipient cannot apply;
  with the old rule the closure waits), `closureScopeTest`, and
  `closureWithoutRecipientAllowsStaleEffectTest`, the witness that the
  recipient's fence is needed: committed without it, the send under way
  applies the request after its expiry and `noStaleEffect` fails.
- Test: `TestRequestClosureFencesOnlyItsParties` (PostgreSQL). A third
  agent's store is unavailable; a request's expiry and a cancellation commit
  with their two parties as the only targets, and a send under way to the
  recipient is refused by its fence. Without the change the closure waits for
  the third store.
- Projections: the P1 replay compares a closure's barrier receipts on the
  request's parties (`preimplementation_projection_test.go`); its frozen
  traces still fence every store, and every fence is still checked in SQLite.
  P3 has two stores, the parties of each request: unchanged. The KVM tests
  that counted every store are updated (`control_integration_test.go`,
  `dispatch_integration_test.go`, `seals_integration_test.go`).

What still waits: a request whose own party never boots. Question for the
product owner, scenario: agent B never boots; A sends it a request that
expires. Today the request stays `DELIVERING` until B boots for the closure's
fence, and A's task waits. Options: (a) keep this, safe against a database
restore; (b) when no attempt was ever allowed to carry the request, close it
without B's fence, as item 5 does for a reply, which brings the restore risk
(h) to requests. Recommended: (a) until (h) is fixed, then (b).

### 7.2 Findings of an independent review

- **(a) Replies that died without a retention.** A reply that died before
  item 1, or through `RetireDelivery` without the transit, kept
  `purge_after` empty: never purged, and the status read served it for good.
  The purge pass now starts the retention of a dead reply that has none, at
  that pass: its death is not recorded, and the pass is never earlier than
  the death (`Transit.PurgeExpired`). No migration: the retention's length is
  the transit's, which SQL does not hold. Test:
  `TestDeadReplyWithoutRetentionGetsOne`.
- **(b) An expired reply behind a request delivery.** The retirement needed
  the mailbox head (`isHead`), and the worker discovered only heads. A reply
  or status behind a request delivery to an agent that never boots never
  died. A reply, status or instruction that no attempt reached now dies past
  its deadline wherever it is in the queue: it never reached the agent, so
  the order of what the agent receives is unchanged. The worker discovers it
  (`DiscoverWork`). One an attempt may have reached is the head, and still
  waits for its fence. [worker.md](../worker.md) now says what still waits
  for an agent that never boots. Test: `TestExpiredDeliveryBehindAStuckHeadDies`
  (a reply behind a request delivery, an instruction behind an instruction
  an attempt may have reached). Models: P1's `retireUnsent` never required
  the head (`unsentReplyDiesBehindHeadTest`); P3's `expireNotification` no
  longer requires it for an unattempted notification (`scenario22Test`).
- **(c) Deletions.** `retirementDue` read the destination's phase without a
  lock, and the retirement checked no phase. A delivery could die, and alert,
  where the deletion of an agent should cancel it: a reply whose author is
  being deleted, or a delivery whose destination's deletion committed in
  between. The retirement now checks, under the agents' locks, that the
  agents its delivery needs are live (`deliverable`: the destination, and
  both parties for a reply), in its first transaction and again after the
  fence; otherwise it returns `ErrUnavailable` and the deletion cancels the
  delivery. Instructions likewise. Test:
  `TestRetirementLeavesADeletionToCancel` (deletion between the check and
  the retirement, the reply's author being deleted, deletion during the
  fence, an instruction's agent deleted). Models: P1's `retire` and `retireUnsent` need `retirable`
  (`retirementLeavesDeletionTest`, `deletionCancelsExpiredReplyTest`); P3's
  `expireNotification` needs an eligible destination (`refusal22x0Test`,
  `scenario22x1Test`).
- **(d) Offboarding.** The docs said a reply is revoked once "the person it is
  bound to has lost access". Offboarding keeps the principal, and
  [ADR 002](002-assignment-revocation.md) lets work accepted before a
  revocation complete for the organization, without making its result
  readable to the former member. The code follows ADR 002: the agents keep
  the reply. The wording is fixed ([agents-assignments.md](../api/agents-assignments.md),
  `peer_reads.go`, `peer_payloads.go`). Test:
  `TestOffboardingLeavesTheReplyToTheAgent` pins this behaviour; it passed
  before the change, which is to the docs.
- **(e) P3 and `may_have_reached`.** P3 decides on `attempts == 0`, Go on
  `may_have_reached`. A P3 attempt (`notify`) is a claim, its authorization
  and its send in one step, so every P3 attempt may have reached the store.
  Go also counts a claim that a crash interrupted before its authorization:
  that delivery dies without a fence, where P3 retires it behind one. P3
  thus never assumes less than Go; P1 has the exact rule (`sent`). Written
  in `expireNotification`.
- **(f) The reason of a purge under way.** `senderReply` checked the purge
  before its locked read: a purge committed in between was reported as
  `content_revoked`. It now locks the reply's content first and decides from
  it: gone at the end of its retention is `content_purged`, gone before is
  `content_revoked` (the deletion of a party). Test:
  `TestStatusReadReportsAPurgeUnderWay`.
- **(g) A lighter status read.** capsule-adapter polls `/status` every 2 s;
  the read locked both agents, the request and the content. It now locks the
  caller's agent (its placement check) and the content only. A request's
  parties never change and a `REPLIED` request never changes again. The
  deletion of either party purges the content in the transaction that ends
  its `LIVE` phase, so content found unpurged under its lock has two live
  parties. Test: `TestStatusReadLeavesTheRecipientUnlocked` (the recipient's
  agent and the request are locked by another transaction).
- **(h) Recorded, not fixed: a restore can lose `may_have_reached`.** A
  restore of PostgreSQL within its 15-minute RPO can lose a committed
  `may_have_reached=true`. A send authorized in the lost window may still be
  on its way: a message delayed in SLIM can outlive the restore. After the
  restore that delivery looks unsent. Past its deadline it dies without its
  fence (item 5), and the delayed send can then reach the restored agent and
  apply it after its death, which `noLateEffect` forbids in P1, a model
  without restores. A reply reaches an agent that could already read it; an
  instruction may run although its requester sees it failed. The request
  closures of §7.1 do not depend on `may_have_reached`. Ways out, for later:
  record the authorization outside the restored domain, in the authority
  service ([ADR 006](006-authority-service.md)), before the send; or, when
  the database is restored, mark every pending delivery as possibly reached,
  so that each dies behind its fence.

### 7.3 Content of a request closed before delivery

A request refused, canceled, expired or failed before it reached its
recipient kept its private content with no purge deadline. No doc or record
fixed a rule ([api/README.md](../api/README.md) left it to EVT-04). **Default
pending the product owner:** the retention starts at the closure and lasts as
long as a delivered request's, 7 days. The closure paths do not hold the
transit's retention, so the worker's purge pass starts it on its first pass
after the closure, then purges once it has passed (`Transit.PurgeExpired`).
Content closed before this change gets its 7 days from the first pass after
the upgrade.

- Test: `TestRequestClosedBeforeDeliveryIsPurged` (declined, canceled,
  expired; a request waiting for consent keeps its content). Without the
  change the content keeps no deadline.
- Question for the product owner, scenario: Alice's agent asks Bob's agent
  something; Bob declines, or the request expires unanswered. How long does
  the platform keep the question's text? Options: (a) 7 days from the
  closure, like a delivered request (the default); (b) purge it at the
  closure, since nobody will deliver it; (c) keep it until an agent is
  deleted, as before. Recommended: (a): the owners can still read what was
  asked for a week, and nothing is kept for good.

### 7.4 Validation

- Each new Go test was run against the code before its change and failed,
  except `TestOffboardingLeavesTheReplyToTheAgent` (a fix to the docs).
- The tests of `internal/controlplane` and `internal/worker` with `-race`
  against PostgreSQL 18: passed.
- The PostgreSQL campaign `scripts/verify-postgres.py`: passed, 1,138 tests
  in the integration phase (640 top-level), every test above among them, then
  the crash and recovery phases
  (local evidence `quint/results/verify-postgres-delivery-closure-scope`).
- The model checks of [spec/README.md](../../spec/README.md), evidence under
  `quint/results/quint-delivery-closure-scope/`: every model typechecks; the
  runs of P1 (36), P1 with manual consent (5), the P1 prefixes (2) and loaded
  state (1), P3 (38) and the five witness guards pass; the five broken
  witness schedules violate their invariant, as they must; `quint run` finds
  no `safety` violation in P3's five instances (200,000 samples of 40 steps),
  in `concurrentProtocolFour` (100,000 of 40) or from P1's loaded state
  (50,000 of 30). The new P1 runs `closureCommitsWithoutOtherStoresTest` and
  `retirementLeavesDeletionTest`, and the P3 runs `scenario22Test` and
  `refusal22x0Test`, fail against the models before this change.
- Not run here: TLC and Apalache (no Java runtime), so neither P1's
  exhaustive depth-bounded safety nor P3's temporal properties; and the KVM
  tests, which need root: `TestControlVMDeliveryAndRevocation`,
  `TestSealedStoreAllowsLaterRevocationAndClosure` and
  `TestDispatchServiceClosureExpirationAndDeletion`, whose closure counts
  changed, with the other dispatch tests listed in §6.
