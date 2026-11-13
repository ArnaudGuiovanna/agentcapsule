# D-03 — RPO, confirmation and restore

Date: November 8, 2026. **Status: option B chosen on November 8, 2026**
(announced loss within the RPO window). The P2 model was revised on November 13,
2026 (see [Model revision (option B)](#model-revision-option-b)). The
implementation session reviewed that contract diff and reran its checks before
the restore authority's code changed (REC-02). The product owner has not
reviewed it yet; the defaults at the end await confirmation.
The failure domains and the numbers (RPO, RTO, storage) were set on November 13
in [004-recovery-objectives.md](004-recovery-objectives.md).
References: product spec §10.4 ([product.md](../product.md)), REC-01 to REC-04,
D-05.

## The conflict to resolve

- The P2 model ([restore_authority.qnt](../../spec/restore_authority.qnt))
  imposes `noLostAcknowledgedOutcome`: a result **already confirmed**
  (`everAcked`) must be present in the data of a restored store before its
  activation (`Ready`). Otherwise activation is refused.
- Product spec §10.4 point 6 accepts, after a disaster, **possible losses within
  the explicitly announced RPO window**, with rescheduling of the jobs.

The two are not compatible for a complete disaster: if the host and its recovery
source are lost, the most recent backup may predate a confirmation. According to
the model, the agent could then never be reactivated. Today the activation
refusal is kept (see D-03 in the roadmap); the encrypted cold capture is not a
restore (0 of 22 P2 projections).

## What the decision must settle

1. The **failure domains**: local recovery (process, database, restarted host)
   and complete disaster (host lost, restore on another host).
2. The **durability of the recovery source** for the confirmation history,
   independent of the restored volume.
3. What a user may believe of a **confirmation** ("accepted", "delivered",
   "completed"), and what remains true after a restore.
4. The announced **RPO/RTO**, which must be measured (REC-03) and not assumed.

## Options

### A. Confirmation journal outside the restored domain (model kept)

Confirmations are written to an independent, durable authority (a journal
replicated off the host). A restore activates only if this journal and the data
agree.

- Keeps `noLostAcknowledgedOutcome` without weakening it; no model to change.
- Requires an additional external dependency and its own durability, hard to
  sustain on a single VPS. Contradicts the "simple single-node" spirit of the
  product spec.

### B. Announced loss within the RPO window (product spec kept)

A restore may lose the results confirmed after the last backup. Activation is
allowed, the loss is reported to the caller and the jobs are rescheduled
idempotently.

- Consistent with the product spec and feasible on a single host.
- Requires **changing the model**: `noLostAcknowledgedOutcome` becomes "no
  *unannounced* loss", with an observable "declared loss" state. The current P2
  traces and the tests attached to them must be regenerated; the contract diff
  must be presented before the code (rule D-03 of the roadmap).
- A "confirmed" result can no longer be presented as durably guaranteed; a
  distinct status vocabulary is needed ("accepted", "durable").

### C. Two confirmation levels

An "accepted" confirmation (subject to the RPO) and a "durable" confirmation
(written outside the domain, option A) coexist. The model guarantees only the
second.

- Gives the caller the choice of durability cost.
- The largest scope: two contracts, two families of tests.

## Recommendation (non-binding)

Option **B** is the most compatible with the product spec and the single-node
constraint, provided that the P2 model is explicitly revised and the real RPO is
measured. Option A should be chosen only if a "never a lost confirmation"
guarantee is a product requirement. This recommendation does not replace the
product owner's decision.

## Consequences to handle after the decision

- Update `restore_authority.qnt` and regenerate its traces only if B or C is
  chosen, with the negative checks. Done for B: see the next section.
- Write the loss-window policy in product spec §10.4 and in the API (statuses).
- Unblock REC-02 (22 P2 projections) and REC-03 (restore on a second host).
- Handle D-05 (keys, secrets, revocations outside the restored domain) together:
  a backup predating an offboarding must reactivate neither members, nor tokens,
  nor revoked delegations, whichever the option.

## Model revision (option B)

November 13, 2026. **Status: reviewed by the implementation session (checks
rerun), then implemented in the restore authority; the product owner's review
is pending.** This is
the contract diff that rule D-03 requires. Files:
[restore_authority.qnt](../../spec/restore_authority.qnt) (the model),
[restore_authority_test.qnt](../../spec/restore_authority_test.qnt) (runs) and
[restore_witness.qnt](../../spec/restore_witness.qnt) (fixed schedules).

### Old guarantee

`noLostAcknowledgedOutcome`: an active store (`Ready`) holds every outcome
ever acknowledged for it. Activation was refused while the restored image
lacked one. An image older than an acknowledgment could therefore never be
activated again, unless an archive still held the outcome.

The old guarantee stays in the model as a **negative witness**. It is no longer
part of `safety`. `declaredLossBreaksFormerGuaranteeTest` and the schedule
`restoreWitnessDeclaredLossFormerInvariant` show the case that forced option
B: the image predates the acknowledgment, no archive holds the outcome, and
the loss is declared. Safety holds at every step; the old guarantee fails at
activation.

### New observable state

The restore authority keeps it, outside the restored domain:

- `lost`: the declared losses. Each entry names an event and the restored
  image (its incarnation) that lacks it. Entries are only ever added.
- `rerun`: the declared losses whose job ran again and was recorded.

Two definitions read this state for callers:

- `outcomeStatus(e)`, for the current image of the event's store:
  - `Unrecorded`: no outcome is recorded.
  - `Confirmed`: recorded, no loss declared for this image.
  - `LostRescheduled`: declared lost for this image; the rerun is pending.
  - `RerunConfirmed`: the rerun is recorded.
- `due(e)`: the job must run again. Its loss is declared for this image, the
  outcome is still missing, and its subject is not revoked.

Two actions write it:

- `declareLoss(a)` runs during the restore, after the restricted boot. The
  authority compares its outcome records with the restored image and records
  each missing outcome. It is allowed only if no archive can repair the image,
  and only if an outcome is missing.
- `recordRerun(e)` runs after the rerun's local commit and before the external
  success, like `recordOutcome`. It is allowed only for a loss declared for the
  current image, and only once.

Activation (`activate`) now needs every outcome that the authority recorded for
the store to be in the image **or** declared lost for this image. Its other
conditions are unchanged.

### New guarantees (part of `safety`)

| Invariant | Meaning |
| --- | --- |
| `noUndeclaredLoss` | An active store may lack an acknowledged outcome only if its loss was declared for this image. A loss declared for an earlier image does not cover a later restore. |
| `declaredLossesSurvive` | A declared loss is never withdrawn. |
| `lossesNameAcknowledgedWork` | A declared loss always names an acknowledged event. |
| `rerunsFollowDeclaredLoss` | A rerun is recorded only for a declared loss. |
| `noSilentRerun` | An acknowledged event runs again only after its loss was declared for the current image. The rerun keeps the event ID, so a duplicate delivery is a no-op. |

The other invariants keep their meaning: `revocationsSurvive`,
`noRestoredRevocation`, `permanentSeals`, `keyDestructionSurvives`,
`erasedKeysUnavailable`, `noStaleEffect`, `identitiesFresh`, `acksSound`,
`activationCurrent` and `retiredBeforeInstall`. An image older than an
offboarding declares its loss, but it revives neither the revocation, nor the
seal, nor the key, nor the job.

### Checks

Positive runs: `declaredLossAllowsActivationTest`,
`declaredLossIsRerunOnceTest`, `lostArchiveLeadsToDeclaredLossTest`,
`declaredLossSurvivesControlBackupRestoreTest`,
`eachRestoreDeclaresItsOwnLossTest`, `backupAfterRerunNeedsNoDeclarationTest`.

| Negative check | What it shows |
| --- | --- |
| `undeclaredLossPreventsActivationTest`, `restoreWitnessMissingHistoryGuard` | Activation is refused while a loss is undeclared. |
| `restoreAuthorityMissingHistoryTests`, `restoreWitnessMissingHistoryBroken` | Without that check, a loss goes unannounced and the job reruns silently. |
| `restoreAuthorityRollbackTests`, `restoreWitnessForgottenLossBroken` | An authority restored from a backup forgets an announced loss. |
| `earlierDeclarationDoesNotCoverLaterLossTest` | A second restore must declare its own loss. |
| `repairComesBeforeDeclarationTest`, `noDeclarationWithoutLossTest` | No loss is declared when an archive can repair it, or when nothing is missing. |
| `rerunNeedsDeclaredLossTest`, `declaredLossIsRerunOnceTest` | A rerun is recorded only for a declared loss, and only once. |
| `oldImageDoesNotReviveOffboardedJobTest`, `oldImageDoesNotReviveDestroyedKeyTest` | An old image brings back no revoked subject, sealed store, destroyed key or job. |

The model does not check liveness: it shows that the job is due and can run,
not that it eventually runs.

### What a caller sees

- A result confirmed before a disaster is "confirmed". It is no longer
  guaranteed across a disaster: it may be lost within the announced window.
- After a restore that lost it, the result has its own state, "lost in a
  restore", visible to the organization. The job runs again with the same
  identifier.
- After the rerun, the result is "rerun confirmed". The loss stays on record.
- If the subject was revoked after the backup, the result stays "lost" and the
  job does not run again.
- A result that was never confirmed is not declared lost. Its work simply runs
  again.

### What is done and what remains for the code (REC-02)

#### Done: the restore authority

All of this is in `internal/restoreauthority`.

- **Catalogue.** Schema version 2 adds two tables, kept outside the restored
  domain with the rest of the catalogue:
  - `losses`: outcome, store, incarnation;
  - `reruns`: outcome, incarnation, digest.

  Triggers refuse any update or delete, so a declared loss and its rerun are
  never withdrawn. The version is SQLite's `user_version`; version 1 did not
  record it. Running `agentcapsule-admin init-restore-authority` again
  upgrades a version 1 catalogue in place and keeps its identity. Until then,
  a version 1 catalogue keeps working and keeps the old guarantee, and the
  loss operations return `ErrUnavailable`. `Open` never changes the schema.
  An unknown version fails closed.
- **Activation path.** `Catalog.Activate` takes the coordinator's `Inspect`,
  `Repair` and `Publish` callbacks:
  1. It inspects the image against the outcomes the authority recorded for
     the store. Each outcome carries its current digest: its latest rerun's
     digest, or else the first one.
  2. If outcomes are missing, `Repair` copies them from an available archive.
     It runs outside the catalogue transaction. An error aborts before any
     declaration.
  3. It inspects again and declares each outcome still missing, for the
     receipt's incarnation. That transaction commits before `Publish` runs,
     so a published `Ready` never hides an undeclared loss. It declares only
     what the inspection reports. It refuses an outcome the authority never
     recorded (`ErrInput`).
  4. `WithActivation` inspects a third time and runs `Publish`. It is the
     model's guard: it refuses with `ErrHistory` while a missing outcome has no
     loss declared for this incarnation. A loss declared for an earlier
     incarnation does not count. The old refusal remains only here.
- **Rerun.** `RecordRerun` records the rerun of a loss declared for the
  current incarnation. It runs after the rerun's local commit and before its
  external success. A loss has one rerun: a retry with the same digest is a
  no-op, and another digest is `ErrConflict`. Without a loss declared for this
  incarnation, it returns `ErrNotDeclared`. `RecordOutcome`, which the worker
  already calls on every delivery, calls it when the delivered outcome is
  declared lost for the current incarnation. So the worker needs no change.
  Otherwise `RecordOutcome` accepts a known ID only with its current digest.
- **Reading.** `Losses(store)` lists a store's losses and their reruns, in
  every incarnation. `OutcomeStatus(id)` gives the model's `outcomeStatus`
  for the current incarnation of the outcome's store: `unrecorded`,
  `confirmed`, `lost` or `rerun_confirmed`, with the outcome's losses. The
  model's `due` also needs the job's subject, which only the control plane
  knows.

#### Go projections of the runs

The Go tests are written by hand from the runs in
[restore_authority_test.qnt](../../spec/restore_authority_test.qnt). No Go
test reads the model's traces. The tests are in
`internal/restoreauthority/losses_test.go`, unless the table names
`catalog_test.go`.

| Quint run | Go test |
| --- | --- |
| `undeclaredLossPreventsActivationTest` | `TestUndeclaredLossPreventsActivation`; on real SQLite data, `TestActivationRequiresActualRecoveredData` (`catalog_test.go`) |
| `declaredLossAllowsActivationTest` | `TestDeclaredLossAllowsActivation` |
| `declaredLossBreaksFormerGuaranteeTest` | `TestDeclaredLossBreaksFormerGuarantee` |
| `declaredLossIsRerunOnceTest` | `TestDeclaredLossIsRerunOnce` |
| `rerunNeedsDeclaredLossTest` | `TestRerunNeedsDeclaredLoss` |
| `noDeclarationWithoutLossTest` | `TestNoDeclarationWithoutLoss`, which also checks `lossesNameAcknowledgedWork` |
| `repairComesBeforeDeclarationTest` | `TestRepairComesBeforeDeclaration`; on real SQLite data, `TestActivationRequiresActualRecoveredData` |
| `lostArchiveLeadsToDeclaredLossTest`, `unavailableArchivePreventsRepairTest` | `TestLostArchiveLeadsToDeclaredLoss` |
| `declaredLossSurvivesControlBackupRestoreTest` | `TestDeclaredLossSurvivesControlBackupRestore` |
| `oldImageDoesNotReviveOffboardedJobTest` | `TestOldImageDoesNotReviveOffboardedJob` |
| `freshBackupKeepsAcknowledgedOutcomeTest` | `TestFreshBackupKeepsAcknowledgedOutcome` |
| `unacknowledgedOutcomeCanBeRecomputedTest` | `TestUnacknowledgedOutcomeCanBeRecomputed` |
| `oldImageReconcilesRevocationsAndOutcomesTest` | `TestOldImageReconcilesRevocationsAndOutcomes` |
| `markerCannotInventRecoveryDataTest` | `TestActivationRequiresActualRecoveredData` (`catalog_test.go`) |
| `earlierDeclarationDoesNotCoverLaterLossTest` | `TestEarlierDeclarationDoesNotCoverLaterLoss` |
| `eachRestoreDeclaresItsOwnLossTest` | `TestEachRestoreDeclaresItsOwnLoss` |
| `backupAfterRerunNeedsNoDeclarationTest` | `TestBackupAfterRerunNeedsNoDeclaration` |
| `forgottenLossTest` (rollback) | `TestDeclaredLossIsNeverWithdrawn`: the catalogue refuses to delete or change a loss or a rerun. It cannot detect a catalogue restored from its own backup, so the catalogue must stay outside the restored domain (D-05). |
| `undeclaredLossTest`, `silentRerunTest` (missing history) | No Go switch turns the guard off. `TestUndeclaredLossPreventsActivation` checks the guard that these runs remove. |

Two more tests cover the code rather than a run.
`TestAuthoritySIGKILLBeforeAndAfterCommit` (`catalog_test.go`) kills the
process before and after the commit of a declaration and of a rerun; a retry
records each one once. `TestVersionOneCatalogueUpgradesOnInitialize` covers
the schema upgrade.

The earlier runs keep the tests they had:

- `activationRechecksNewRevocationTest` and
  `rescanAfterConcurrentRevocationTest`:
  `TestReceiptRevisionAndForgeryCannotPublish` and
  `TestPublicationSerializesConcurrentRevocation`.
- `oldReceiptCannotBindToNewImageTest`:
  `TestConcurrentReservationAndOldReceiptCannotRebind`.
- `sealedStoreCannotBeRestoredTest`:
  `TestReceiptRevisionAndForgeryCannotPublish`.
- `sealedStoreCannotBlockFutureRevocationTest`:
  `TestCurrentFenceAndRevocationPublicationRequireIndependentACKs`.
- `revokedSubjectCannotAcquireNewKeyTest`:
  `TestSubjectKeyGateUsesIndependentIntent`.
- `lostReceiptIsRetriedFromDurableFenceTest`:
  `TestLostGuestFenceACKDoesNotBecomeIndependentReceipt` (`internal/worker`,
  with PostgreSQL).

Some runs have no Go projection:

- The writer runs need a guest that is writing while a fence or a restore
  arrives: `writerBlocksFenceTest`,
  `admittedWriterFinishesBeforeRevocationTest`. The retirement runs are
  covered in part by the coordinator (below):
  `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` refuses to
  install while a VMM is registered or holds the volume lock
  (`physicalRetirementAbortsOldWriterTest`), and a restore needs a LIVE agent
  and its reservation before it installs
  (`sealRetirementCannotInstallUnreservedImageTest`).
- The key runs belong to the key authority (D-05):
  `destructionWaitsForAllCachedCopiesTest`,
  `destructionRequiresPermanentSealTest`,
  `destroyedKeyCannotDecryptOldBackupTest`, `liveKeyDecryptsBackupTest`,
  `oldImageDoesNotReviveDestroyedKeyTest`.
- Three authority runs are covered only in part:
  `authorityOutageBlocksOtherwiseReadyActivationTest`,
  `authorityRecoveryAllowsActivationTest` and
  `authorityStateSurvivesControlBackupRestoreTest`.
  `TestInitializationIdentityAndMissingAuthorityFailClosed` checks an outage
  and a recovery on a key grant, not on an activation.

#### Done: the restore coordinator

November 13, 2026. The worker restores one agent, on its own host, from one
of its archives, into a new incarnation: `agentcapsule-worker -restore-agent`
([recovery.md](../recovery.md#restoring-an-agent-from-an-archive)). Before it
stops anything, it authenticates and hashes the archive, and asks the agent's
harness whether it can report its outcomes.

- **Order.** The steps are the model's:
  1. `beginRestore`: one PostgreSQL transaction records the restore
     (`volume_restores`) and makes the volume `RESTORING` at the next
     incarnation. Then `ReserveIncarnation` reserves the same one in the
     authority.
  2. `retire`: the agent's VMs are removed.
  3. `install`: the archive is written into the registered volume inode, in
     place, and must match its digest.
  4. `launchRestore`: a restricted boot opens the image at the new
     incarnation. The worker fences it with every revocation.
  5. `repairHistory` or `declareLoss`, then `activate`: `Catalog.Activate`,
     with the inspection below. `Publish` records the activation in
     PostgreSQL.
  6. The restricted boot is removed. One transaction copies the declared
     losses into PostgreSQL and makes the volume `READY` again.
- **Inspection.** The guest reports which outcomes its store holds, with the
  digest of each stored result: the new `outcomes` control feature
  ([capsule-control.md](../guest/capsule-control.md)). It reads `capsule_inbox`,
  which `Apply` commits with the effects. The Go harnesses and the Python SDK
  implement it.
- **Repair.** An archive can hold the outcomes that another lacks only by being
  newer. So the worker refuses an archive when a newer nightly archive of the
  agent is in the archive root: before anything stops, and again as the
  activation's `Repair`, which aborts before any declaration. An archive taken
  on demand is not recorded; the operator chose it.
- **Crashes.** Each step commits before the next one starts. Until the end,
  the volume stays `RESTORING`: no ordinary boot, adoption, delivery or archive
  reaches it, so a half-restored image never serves. The same command resumes
  the restore from its last durable step. A new restore ID replaces an
  unfinished restore that has not activated, one incarnation further. A
  restore that stopped between its SQL record and its reservation is reserved
  first.
- **The incarnation in the control plane.** Migration 0029 replaces the
  `enrollment_identity_guard` function. The incarnation moves only one step up,
  to the one that an unfinished restore reserved, while the volume becomes
  `RESTORING`. A `RESTORING` volume becomes `READY` only once its restore is
  activated. Every other rule stands. `store_initializations` records one
  initialization per incarnation: the restricted boot records the new one.
- **The worker.** It already compared every guest's incarnation with
  `store_enrollments`. It now boots, adopts, delivers to and observes the new
  incarnation, and refuses the old one everywhere. The authority refuses the
  old one's fence receipts, bindings and outcomes (`ErrStale`).
- **The guest (build v20).** The restricted boot of a restored image carries
  `X-Capsule-Restore`. The guest then moves the image's marker forward to the
  new incarnation, never back. Without it, the marker must match as before.
- **Losses in PostgreSQL.** `volume_restore_losses` (migration 0029), keyed by
  restore and outcome, with the incarnation and `declared_at`. The rows are
  never changed or deleted. The worker maps each loss to its delivery by
  computing the outcome ID of each of the agent's mailboxes
  (`harnessstore.StoredOutcomeFingerprint`, agent ID and mailbox ID): the row
  names the mailbox and, for an owner instruction, the invocation. A loss
  without a mailbox is work that the restored database lost too (default 1
  below).

Tests: the PostgreSQL tests of `internal/controlplane/volume_restores_test.go`
(the guard, the operation, its atomic steps, the loss mapping); the
coordinator tests of `internal/worker/restore_test.go`, with a fake host and a
real guest protocol (exactly the outcomes after the archive declared lost, a
stop after each step, a copy cut half way, a failure after the declaration, a
superseded restore, refusals before anything stops); and the KVM product test
`TestProductWorkerRestoresAgentFromArchive`, compiled and still to be run as
root.

#### Done: running the lost invocations again

November 13, 2026. When a restore ends, each invocation it lost runs again
under the same mailbox ID, or is skipped with a reason. Code:
`internal/controlplane/invocation_reruns.go`; migration 0030
(`invocation_reruns`).

- **Where it is decided.** In the restore's last transaction
  (`CompleteVolumeRestore`), with the copy of the losses and the return to
  `READY`. No sweep runs after it. At that point nothing has been delivered to
  the new incarnation: the volume was `RESTORING` since the reservation. So
  every declared loss is still `lost` in the authority. The worker passes the
  authority's rerun flag all the same, and a loss whose rerun is recorded is
  not due. The requester check and the requeue are in the same PostgreSQL
  transaction. There is no window where the agent serves while a lost
  invocation is undecided, and none for the input's purge. A sweep would need
  its own marker and job, and would have to ask the authority about each
  candidate while deliveries run.
- **Crash points.** A crash before the commit leaves nothing copied or
  decided: the same command repeats the step. After the commit, the decisions
  are recorded with the losses. Repeating the step returns them and decides
  nothing again. A crash during the rerun's delivery is an ordinary retry: the
  same event ID and envelope, a fresh lease. The authority records the rerun
  once; the same digest again is a no-op. A stale attempt cannot acknowledge.
- **Candidates.** A loss names an invocation, and PostgreSQL recorded its
  delivery (`DELIVERED`): it completed, failed after "working", or is still
  working. An invocation canceled by its requester is not run again. An
  invocation whose delivery is still open runs again through its own retry:
  the authority recorded its outcome, but PostgreSQL never got the ACK. It
  gets no decision. One closed without delivery stays closed.
- **Queued.** The mailbox goes back to `PENDING`, at its place in the queue:
  the lost work runs first, in its first order. It gets fresh attempts and its
  first delivery window again (its TTL, at most 24 hours), counted from the
  decision. The operation is `PENDING` again. The input's purge waits until
  the rerun is delivered.
- **Skipped.** The invocation stays `lost` and does not run again. The reason
  is its `error_code`:
  - `requester_revoked`: the requester can no longer invoke the agent. A
    tenant requester must be an active principal and member of an active
    organization, with the `invoke` permission on the agent. The owner of a
    historical agent must be an active user.
  - `agent_unavailable`: the agent is being deleted.
  - `input_purged`: the instruction's content is no longer stored. Its 7-day
    retention exceeds the volume window, so only an old archive gets there.
  - `attachments_purged`: a file is no longer stored. Files are purged as
    soon as an invocation ends, so this is the usual case for an invocation
    with files. It waits for a product decision (question 5). Its input is
    kept meanwhile; a cancel destroys it.

  The input of the other skipped invocations follows its normal purge: nobody
  may use it.
- **Before the rerun reaches the agent.** The claim of a queued rerun checks
  the requester again, as long as no attempt has reached the agent. A revoked
  requester's rerun is then skipped: its mailbox is closed, its mandate
  revoked, its input's retention starts. Nothing is sent, and the queue moves
  on. Once an attempt may have reached the agent, the rerun finishes.
- **The mandate is reused.** The mailbox ID allows a single mandate
  (`mandate_origin_once`), and the rerun keeps that ID, which the agent
  deduplicates on. The rerun keeps the same mandate, its remaining budget and
  its validity. Only its expiry moves, to the rerun's delivery deadline:
  `AuthorizeInstruction` requires that the two are equal. So the first run and
  its rerun together make at most the requested number of agent requests,
  each run within a window no longer than the first one, and only on behalf of
  a requester who still holds the right to invoke. No rerun gains more
  authority than the original request had. A rerun that repeats a request
  with the same idempotency key gets the first receipt back and consumes
  nothing. A fresh budget was rejected: it would double the requests that the
  requester allowed.
- **The result.** While the invocation is `lost`, the result that the
  database still holds stays readable. The rerun's result replaces it in
  place: the same payload row, sealed again for the same requester, its
  retention clock reset. A later completion over the platform channel
  replaces it the same way. Only a queued rerun can replace a result.
- **Cancel.** A `lost` invocation can be canceled by its requester until its
  rerun reaches the agent. The rerun then never runs: its mailbox is closed,
  its mandate revoked and its input destroyed. A skipped one can be canceled
  too. Both become `canceled` and keep `lost_at`. A rerun being delivered is
  not interrupted (409). A rerun acknowledged "working" is canceled like any
  working invocation.
- **Agent-to-agent requests, replies and statuses** are not run again. Their
  losses stay recorded, with their mailbox and no invocation. Running them
  again is neither cheap nor safe: it reopens requests whose final states are
  immutable, their payloads may be purged, and the other agent's side was not
  lost. See "What remains".

#### Done: the API

- `state: lost`, in the `Invocation` enum and in the `state` filter of the
  list route. The loss is declared and the rerun has not ended: it is queued,
  running, or skipped. Every other filter excludes a lost invocation.
- `lost_at` (date-time): the time of the newest loss, from
  `volume_restore_losses.declared_at`. A `completed` invocation with `lost_at`
  ran again after a restore loss. Its `completed_at` is the rerun's. A lost
  invocation has no `completed_at`.
- `error_code` of a lost invocation: why it will not run again, or nothing.
- The result route reads the result the database still holds while the
  invocation is lost. `/v1/operations/{id}` shows the operation `PENDING` or
  `RUNNING` again during the rerun.
- The cancel route cancels a lost invocation as above.
- The worker's restore receipt counts the reruns: `reruns_queued` and
  `reruns_skipped`.

These names follow the existing schema. States are single lowercase words
(`accepted`, `expired`, `canceled`). Lifecycle times end in `_at`
(`created_at`, `completed_at`, `run_at`, `result_due_at`). One optional time
marks both cases. Unlike a separate boolean, it cannot disagree with the
state. A client that ignores `lost_at` still reads a completed rerun as a
normal completion. The authority's `lost` and `rerun_confirmed` map to `lost`,
and to `completed` with `lost_at`.

Tests: the PostgreSQL tests of
`internal/controlplane/invocation_reruns_test.go` (the queued rerun, its
mailbox, mandate and window; the API state, `lost_at` and the filters; the
old result readable, then replaced; a repeated step; a failure injected before
and after the decisions; a crash during the rerun's delivery; a revoked
requester at the restore and before the claim; purged files and a purged
input; cancel while queued, skipped, delivered and working; a later
completion; the decisions' guard). The KVM product test
`TestProductWorkerRestoresAgentFromArchive` now checks that the two lost
invocations are `lost`, then run again and complete with `lost_at`, and that
the authority's `OutcomeStatus` becomes `rerun_confirmed`. It is compiled and
still to be run as root.

#### What remains

1. **Agent-to-agent losses.** A lost request, reply or status is recorded but
   not delivered again. It needs its own design: which side runs again, how a
   request in a final state reopens, and what happens when its payload is
   purged.
2. **Restores before migration 0030.** A restore that completed earlier made
   no decision: its invocations keep their state. No deployment has one.
3. **Another host.** A restore onto another host needs D-05: the keys,
   secrets and revocations outside the restored domain.
4. **Barriers during a restore.** A revocation barrier that targets a
   restoring agent waits until its image is installed: a fence boot is refused
   before. The model lets a revocation finish without a store that does not
   execute; the barrier code does not use that yet. Likewise, the removal of a
   deleted agent's volume needs it `READY`: a deletion requested during a
   restore ends after the restore.
5. **Measurement.** The KVM test shows a declared loss and its rerun end to
   end, once run. The restore exercise of REC-03 must measure it on the
   standby.

### Questions for the product owner

1. Declarations come from the authority's outcome records, which the model
   assumes survive a disaster. ADR 004 gives PostgreSQL a 15-minute RPO. If
   the authority has the same RPO, a loss in those 15 minutes cannot be
   declared result by result. It can only be announced as a time window. Is
   that acceptable, or must the authority's records reach the standby
   synchronously?
2. The names of the states in the API: "confirmed", "lost in a restore",
   "rerun confirmed"? ADR 003 also suggested "accepted" and "durable".
3. A lost job whose subject was revoked stays "lost". Should it also get a
   final state, such as "cancelled"?
4. Some jobs act outside the agent (an email, a payment). Should a caller be
   able to refuse the automatic rerun of such a job?
5. A lost invocation whose files are already purged cannot be sent again as
   it was. Should it run again without its files, wait for the requester to
   send them again, or end?

### Defaults pending the product owner's confirmation

The code and the plan above use these defaults until the product owner
answers. None is confirmed yet. Each one lives in one place, so that a change
stays small.

1. A loss is declared result by result for the outcomes that the authority
   recorded but the restored image lacks: the volume window, up to 24 hours.
   The database window, up to 15 minutes, is announced as a time window. The
   catalogue is assumed to survive a disaster; where it lives is D-05.
2. In the API, a declared loss whose rerun has not ended has the state
   `lost`. A rerun that ends has the state of its end, such as `completed`,
   and keeps `lost_at` as its marker. Code: `lostCondition` and
   `invocationState`.
3. A lost job whose subject was revoked stays `lost`, with `error_code`
   `requester_revoked`. It is not rescheduled and gets no other state. Code:
   `mayInvokeAgain`, used at the restore and before the claim.
4. The rerun is automatic and keeps the event ID, so the agent can
   deduplicate it. A caller cannot refuse it in advance. It can only cancel it
   before it reaches the agent. An opt-out for jobs that act outside the agent
   is a follow-up. Code: `decideRerun`, `cancelLost`.
5. A lost invocation whose files are purged stays `lost`, with `error_code`
   `attachments_purged`, and does not run again. Its input is kept until a
   decision or a cancel. Code: `attachmentsGone`, `decideRerun`.
