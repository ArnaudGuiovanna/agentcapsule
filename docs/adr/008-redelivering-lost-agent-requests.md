# D-03 follow-up — Delivering again the agent-to-agent events a restore lost

Date: November 16, 2026. **Status: proposed and built on November 16, 2026**
on the branch `rec02-a2a-redelivery`, with defaults pending the product owner
(see [Questions](#questions-for-the-product-owner)). It answers item 1 of
"What remains" in [ADR 003](003-restore-rpo.md#what-remains).
References: [ADR 002](002-assignment-revocation.md) (accepted work may
finish), [ADR 003](003-restore-rpo.md) (declared losses, the reruns of
invocations and their confirmed defaults), [ADR 007](007-delivery-closure-and-priority.md)
(dead deliveries, the sender's read of its reply, retention), the models
[restore_authority.qnt](../../spec/restore_authority.qnt) (P2),
[concurrent_protocol.qnt](../../spec/concurrent_protocol.qnt) (P1) and
[service_progress.qnt](../../spec/service_progress.qnt) (P3).

## The problem

Agent A sends a **request** to agent B. B answers with a **reply**, or the
request ends with a **status** (`DECLINED`, `EXPIRED`, `CANCELED`, `FAILED`).
The platform carries each as an **event**: one entry of the destination's
mailbox, delivered under its mailbox ID. When an event reaches an agent, the
worker records its outcome in the restore authority.

A restore from an archive older than a delivery loses that outcome: the
restored store lacks the event, its effects and its deduplication record.
ADR 003 declares the loss and runs lost invocations again. For an
agent-to-agent event it only recorded the loss:

- B's store can lose a **request** event;
- A's store can lose a **reply** or a **status** event.

The request itself lives in PostgreSQL, outside the restored volume. A restore
of one agent never changes it.

## Decision

1. **Who runs again: the restored agent only.** The lost event is delivered
   again to the agent that lost it, under the same mailbox ID, at its place in
   its queue. The other agent's side was not lost and runs nothing. This is
   ADR 003's automatic rerun under the same identifier.
2. **A request in a final state never reopens.** `REPLIED`, `DECLINED`,
   `EXPIRED`, `CANCELED` and `FAILED` stay as they are (`request_state_guard`,
   P1 `terminalStable`). A request event is delivered again only while its
   request is `PROCESSING`, has no closure under way and is before its
   deadline. The request then goes back to `DELIVERING`, which is what the
   platform knows: its recipient no longer holds it. A reply or a status is
   delivered again to the sender while its request keeps its final state.
3. **A request that its recipient will not get again fails at once.** When an
   active request is not delivered again because its requester was revoked or
   its content is gone, it is closed `FAILED` with the reason
   `lost_in_restore`, and its sender gets the status. It does not wait for its
   deadline. (Default pending the product owner, question 1.)
4. **What is not delivered again is recorded with a reason**, like a skipped
   rerun (`peer_redeliveries.skip_reason`):
   - `request_closed`: a request event whose request is final, closing or past
     its deadline;
   - `agent_unavailable`: a party the delivery needs is being deleted;
   - `requester_revoked`: the person a request was sent for can no longer
     invoke the sender;
   - `content_purged`: the request's or reply's content is no longer kept.
5. **The sender learns as it learns of any request**: the status read of
   ADR 007 (`/v1/agent-requests/{id}/status`) and the events. Its A2A task
   follows the status read. The owner's read gains `lost_at`.
6. **The sender's owner can cancel** a request being delivered again, like any
   active request. A reply or a status repeats an outcome already decided; it
   is not cancelable.

## Scenarios

In every scenario A sends request R to B, under a mandate from an
invocation of person P. "Restored" means restored from an archive older than
the event in question.

| # | What happened before the restore | Restored | Lost event | Decision | R becomes | The sender sees |
|---|---|---|---|---|---|---|
| 1 | B received R and was working on it | B | request | delivered again to B | `DELIVERING`, then `PROCESSING` once delivered, then B's answer | status read `DELIVERING` then `PROCESSING`; A2A task `submitted`, then `working`, then `completed` with B's reply |
| 2 | B answered R | B | request | not delivered again: `request_closed` | `REPLIED`, unchanged | nothing new: A has the reply, or reads it |
| 3 | R expired, was canceled or failed after B received it | B | request | `request_closed` | unchanged | nothing new |
| 4 | B received R; R is past its deadline, not yet closed | B | request | `request_closed` | `EXPIRED` at the expiration job | the `EXPIRED` status |
| 5 | B answered R and the reply reached A | A | reply | delivered again to A | `REPLIED`, unchanged; `sender_notified` false until it arrives | the reply event again; the status read returns the reply |
| 6 | R ended without a reply and the status reached A | A | status | delivered again to A | unchanged | the status event again |
| 7 | as 1, but P can no longer invoke A | B | request | `requester_revoked`; R fails | `FAILED` (`lost_in_restore`) | the `FAILED` status; A2A task `failed` |
| 8 | as 1, but R's content was purged | B | request | `content_purged`; R fails | `FAILED` (`lost_in_restore`) | the `FAILED` status |
| 9 | as 5, but the reply's content was purged | A | reply | `content_purged` | `REPLIED` | status read: `REPLIED`, reason `content_purged`; A2A task `completed` without an artifact |
| 10 | as 5, but B is being deleted | A | reply | `agent_unavailable` | `REPLIED` | status read: `REPLIED`, reason `content_revoked` once the deletion purges the reply |
| 11 | as 1, but A is being deleted | B | request | `agent_unavailable` | the deletion cancels R | nobody to tell |
| 12 | B answered R; then B, then A, are restored | B, then A | request, then reply | B: `request_closed`; A: delivered again | `REPLIED` | the reply event again |
| 13 | B was working on R; then B, then A, are restored, A from before it sent R | B, then A | request; A's invocation | B: delivered again; A's invocation runs again (ADR 003) | `DELIVERING`, then as 1 | A's rerun sends R again: with the same idempotency key it gets R back; with another, a new request |

Notes on the scenarios:

- **An event whose delivery is still open** (the authority recorded the
  outcome, PostgreSQL never got the acknowledgment) runs again through its own
  retry, as for invocations. It gets no decision.
- **An event closed without delivery** (dead or canceled) stays closed. A dead
  reply stays readable through the status read (ADR 007).
- **Requester revoked.** The check applies to a request event only: B would
  run new work for P, which ADR 003 allows only for a requester who may still
  invoke. A reply or a status repeats an outcome already decided; it runs no
  new work for P, and its content is readable by A's agent through the status
  read anyway (ADR 007 §7.2 (d), ADR 002). The check runs at the restore.
  Unlike an invocation's rerun, a request delivered again is not checked again
  before its claim: once queued, it is an ordinary delivery of work accepted
  before the revocation (ADR 002), and a first delivery is not checked either.
- **Content.** A request's or reply's content is kept 7 days after its
  delivery. An archive of the volume is at most 24 hours old, and the worker
  keeps 7 of them, so only an old archive reaches purged content. While a
  redelivery is queued, its content waits without a retention; the retention
  starts again at its delivery, or at its death (ADR 007).
- **Deletions.** The delivery needs the same live agents as any delivery
  (`deliverable`): its destination, and both parties for a request or a
  reply. A deletion that begins after the decision cancels the queued
  redelivery as it cancels any delivery, and tells A when a reply is canceled
  (`sender_notified` is false again, so B's deletion sends A the status
  `REPLIED` with `content_revoked`).

## What changes in the code

- **Migration 0033**: `peer_redeliveries` (restore, outcome, mailbox, request,
  kind, `queued` or `skipped`, reason), never changed or deleted.
- **The restore's last transaction** (`CompleteVolumeRestore`) locks the
  restored agent and the other party of each lost event, in the order of every
  other path, then copies the losses, decides the reruns of invocations
  (ADR 003) and the redeliveries (`scheduleRedeliveries`), and puts the volume
  back in service. The locks keep a deletion from committing between the
  decision and the requeue.
- **A redelivery** sets the mailbox back to `PENDING` with fresh attempts and
  no possible reach. Its old sends died with the old incarnation: the restore
  retired its VMs, and every check of the old incarnation fails. A request
  keeps its own deadline and goes back to `DELIVERING`; a reply or a status
  gets a fresh 7-day window and `sender_notified` false. The delivery path is
  unchanged. Its outcome, recorded by the worker on delivery, is the
  authority's rerun (`RecordOutcome` calls `RecordRerun` for a declared loss):
  the outcome's status becomes `rerun_confirmed`.
- **The API**: `GET /v1/agent-requests/{id}` gains `lost_at`, the time a
  restore last lost one of the request's events. The status read is
  unchanged. The restore receipt's `reruns_queued` and `reruns_skipped` count
  the redeliveries with the reruns, and each loss of `RestoreLoss` carries its
  decision.

No guest change: the guest protocol and capsule-adapter are untouched.

## The models

- **P2** ([restore_authority.qnt](../../spec/restore_authority.qnt)) is
  unchanged. A redelivery is P2's rerun of a lost event: it follows a loss
  declared for this incarnation (`noSilentRerun`), keeps the event ID, and is
  recorded once (`recordRerun`). P2's `due(e)` holds when the event's subject
  is not revoked; the platform's subjects of a request event are its two
  agents, `request/<id>` (revoked by a closure) and the event itself. The rules
  above skip more than `due` does: a final request, a revoked requester, purged
  content. P2 allows that: it has no liveness, and a job that does not run
  again breaks no safety property.
- **P1** ([concurrent_protocol.qnt](../../spec/concurrent_protocol.qnt))
  gains two actions. P1 had no restore: a delivered event never went back to
  pending, and a request never went back from `Processing`.
  - `loseOutcome(e)`: the destination, retired, loses the event's effect; no
    RPC carries it any more.
  - `redeliver(e)`: a lost event goes back to pending under the same ID and at
    its place. A request event only while its request is `Processing` with no
    closure, the request going back to `Delivering`; a reply or status only
    while its request is final, its sender no longer notified. The agents its
    delivery needs are active (`retirable`).
  Every `safety` invariant holds. Runs: `restoredRecipientGetsRequestAgainTest`,
  `restoreNeedsRetiredStoreTest`, `finalRequestDoesNotReopenTest`,
  `closingRequestIsNotRedeliveredTest`, `restoredSenderGetsReplyAgainTest`,
  `restoredSenderGetsStatusAgainTest`, `deletionBlocksRedeliveryTest`,
  `closureCancelsRedeliveryTest`, and the negative
  `reopenedRequestBreaksTerminalStableTest`: a redelivery that reopens a
  replied request breaks `terminalStable`.
- **P3** ([service_progress.qnt](../../spec/service_progress.qnt)) gains
  `redeliverRequest(i)` (an executing request goes back to admission) and
  `redeliverNotification(i)` (an acknowledged notification is pending again).
  Both happen only before the run stabilizes, like a store loss, and are not
  assumed fair, so the progress properties keep their assumptions: a
  redelivered request still ends at its deadline. Runs: `scenario23Test`,
  `scenario23x1Test`, `scenario24Test`, `refusal24x0Test`.

The skipped redelivery that fails a request (decision 3) is P1's
`closeRequest(r, FailRequest)`, which any active request allows: no new
action.

### Go projections

| Model run | Go test (`internal/controlplane/peer_redeliveries_test.go`, PostgreSQL) |
|---|---|
| `restoredRecipientGetsRequestAgainTest` | `TestRestoreRedeliversALostRequest` |
| `finalRequestDoesNotReopenTest`, `closingRequestIsNotRedeliveredTest` | `TestRestoreDoesNotReopenAFinalRequest` |
| `restoredSenderGetsReplyAgainTest`, `restoredSenderGetsStatusAgainTest` | `TestRestoreRedeliversALostReplyAndStatus`, `TestBothPartiesRestored` |
| `deletionBlocksRedeliveryTest` | `TestRedeliveryIsSkippedWithAReason/other_agent_being_deleted` |
| `closureCancelsRedeliveryTest` | `TestARedeliveredRequestCanBeCanceled` |
| (no model run: content and persons are outside P1) | `TestRedeliveryIsSkippedWithAReason` (requester revoked, request and reply content purged) |
| `restoreNeedsRetiredStoreTest` | no Go projection: the coordinator retires the VMs before it installs (`TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage`) |

The KVM product test `TestProductWorkerRestoresAgentToAgentExchange`
(`internal/worker/product_restore_integration_test.go`) proves it end to end:
scenarios 2, then 12 with A's invocation run again, the authority's
`rerun_confirmed` for the reply. It is written and not yet run.

## Questions for the product owner

1. **A request its recipient will not get again.** Scenario: Alice's agent
   asks Bob's agent a question; Bob's agent is restored from last night's
   archive and has forgotten the question, and Alice has left the
   organization since. Options: (a) fail the request at once, and Alice's
   agent is told it failed (the default); (b) leave it until its deadline,
   then it expires. Recommended: (a): the agent learns at once that no answer
   will come, instead of waiting up to the deadline.
2. **A request already answered.** Scenario: Bob's agent answered Alice's
   agent, then Bob's agent is restored from before the question and has
   forgotten both. Options: (a) leave it: the answer stands and Alice's agent
   has it; Bob's agent's memory of the exchange stays lost (the default);
   (b) send the question to Bob's agent again so that it remembers, and throw
   its new answer away: it costs a model call and may repeat an action outside
   the agent; (c) reopen the request and send Alice's agent a second answer.
   Recommended: (a). (c) would break the rule that a final request never
   changes, and Alice's agent would act twice.
3. **The requester check.** Scenario: Bob's agent is restored and gets
   Alice's question again; an hour later, before Bob's agent wakes, Alice
   leaves. Options: (a) Bob's agent still answers: the redelivery is work
   accepted before she left (the default, as for a first delivery); (b) check
   again before the delivery and fail the request, as ADR 003 does for an
   invocation's rerun. Recommended: (a) for the MVP.
4. **The sender's task goes back.** While B's request is delivered again, the
   sender's A2A task shows `submitted` again after `working`. Options: (a) keep
   it: it says what the platform knows (the default); (b) keep the request
   `PROCESSING` during the redelivery, which hides the restore but needs the
   delivery path to accept a request it believes delivered. Recommended: (a).

## Validation

- Each test of `peer_redeliveries_test.go` was run against the code before
  the change and failed: the restore made no decision for the lost event.
- The PostgreSQL campaign `scripts/verify-postgres.py`: passed, 1,245 tests in
  the integration phase (741 top-level), none skipped, then the crash and
  recovery phases (local evidence
  `quint/results/verify-postgres-rec02-a2a-redelivery`).
- The model checks of [spec/README.md](../../spec/README.md), evidence under
  `quint/results/quint-rec02-a2a-redelivery/`: every model typechecks; the
  runs of P1 (45), P1 with manual consent (5), the P1 prefixes (2) and loaded
  state (1), P3 (42), P2 (34) and the five witness guards pass; the five broken
  witness schedules violate their invariant, as they must; `quint run` finds no
  `safety` violation in P3's five instances (200,000 samples of 40 steps), in
  `concurrentProtocolFour` (100,000 of 40) or from P1's loaded state (50,000
  of 30). The new runs use the new actions, so they cannot pass against the
  models before this change.

## Not done

- **The restore receipt** counts redeliveries with the reruns
  (`reruns_queued`, `reruns_skipped`) rather than in separate counters.
- **The status read** does not carry `lost_at`: that would change the guest
  protocol. The owner's read does.
- **A KVM run** of the new product test, which needs root.
- **TLC and Apalache** checks of the revised P1 and P3 (no Java runtime here).
