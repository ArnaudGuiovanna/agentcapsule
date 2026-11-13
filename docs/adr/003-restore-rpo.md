# D-03 — RPO, confirmation and restore

Date: November 8, 2026. **Status: option B chosen on November 8, 2026**
(announced loss within the RPO window). The P2 model was revised on November 13,
2026 (see [Model revision (option B)](#model-revision-option-b)). That contract
diff must be reviewed before any incompatible code; REC-02 is unblocked under
this condition.
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

November 13, 2026. **Status: proposed, for review before any code.** This is
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

- The writer and retirement runs need the restore coordinator and the guest:
  `writerBlocksFenceTest`, `admittedWriterFinishesBeforeRevocationTest`,
  `physicalRetirementAbortsOldWriterTest`,
  `sealRetirementCannotInstallUnreservedImageTest`.
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

#### What remains

1. **There is no production restore path.** Nothing in production calls
   `ReserveIncarnation`, `Activate` or `WithActivation`. No coordinator drains
   a store, retires it, installs an image, boots it restricted, inspects it
   and activates it. The control plane cannot hold a restored incarnation
   either:
   - the `enrollment_identity_guard` trigger forbids any change to
     `store_enrollments.incarnation`;
   - the worker requires the guest's incarnation to match that column.

   The code above is ready for the coordinator, but nothing reaches it today.
2. **Control-plane state.** Not added: without the coordinator, it cannot be
   tested end to end. It needs these pieces:
   - After activation, the coordinator copies the declared losses into
     PostgreSQL. A new migration adds a table keyed by operation, with the
     incarnation and the time.
   - The authority stores outcome IDs, not invocation IDs. The control plane
     finds the invocation by computing the outcome ID again: `outcome-v1/`
     followed by a SHA-256 of a domain tag, the agent ID and the event ID
     (`harnessstore.StoredOutcomeFingerprint`). An invocation's event ID is
     its mailbox ID.
   - An outcome ID that matches no invocation comes from work that the
     restored database also lost, in its 15-minute window. That window is
     announced as a whole (default 1 below).
   - Rescheduling reopens a completed invocation. Today `SUCCEEDED` is final:
     the mailbox row becomes `DELIVERED`, the outbox row is deleted, and the
     input's 7-day purge delay starts. The rerun must put the same mailbox ID
     back in the queue, with a mandate that has not expired.
   - The input is still stored, because its 7 days exceed the 24-hour volume
     window. Its purge must wait while the invocation is `lost`.
   - Attachment bytes are purged once an invocation finishes, so a rerun
     cannot send them again. That case needs a product decision. Until then,
     such an invocation should stay `lost`.
   - Agent-to-agent requests and messages also reach the guest with an event
     ID, and can be lost in the same way. The invocation API below does not
     cover them.
3. **API.** `openapi/openapi.yaml` is unchanged, for the same reason. With
   the defaults below, it will expose:
   - `state: lost`, in the `Invocation` enum and in the `state` filter of the
     list route. The loss is declared and the rerun is pending, or will not
     happen because the subject is revoked.
   - `lost_at` (date-time): when the loss was declared. A `completed`
     invocation with `lost_at` was rerun after a restore loss. Its
     `completed_at` is the rerun's.
   - While an invocation is `lost`, a result that the restored database
     still holds stays readable. The rerun's result replaces it.

   These names follow the existing schema. States are single lowercase words
   (`accepted`, `expired`, `canceled`). Lifecycle times end in `_at`
   (`created_at`, `completed_at`, `run_at`, `result_due_at`). One optional
   time marks both cases. Unlike a separate boolean, it cannot disagree with
   the state. A client that ignores `lost_at` still reads a completed rerun
   as a normal completion. The authority's `lost` and `rerun_confirmed` map
   to `lost`, and to `completed` with `lost_at`.
4. **Measurement.** Once the coordinator exists, the restore exercise of
   REC-03 must show a declared loss end to end.

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

### Defaults pending the product owner's confirmation

The code and the plan above use these defaults until the product owner
answers.

1. A loss is declared result by result for the outcomes that the authority
   recorded but the restored image lacks: the volume window, up to 24 hours.
   The database window, up to 15 minutes, is announced as a time window. The
   catalogue is assumed to survive a disaster; where it lives is D-05.
2. In the API, a declared loss whose rerun is pending has the state `lost`.
   A rerun that completes has the state `completed` and keeps `lost_at` as
   its marker (see "What remains").
3. A lost job whose subject was revoked stays `lost`. It is not rescheduled
   and gets no other state.
4. The rerun is automatic and keeps the event ID, so the agent can
   deduplicate it. A caller cannot refuse it for now. An opt-out for jobs that
   act outside the agent is a follow-up.
