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

### What remains for the code (REC-02)

- **Activation path.** `restoreauthority.Catalog.WithActivation` has no
  production caller yet. Its `inspect` callback refuses a missing outcome with
  `ErrHistory`: that is the old guarantee. It must instead compute the missing
  outcomes, record them as declared losses (same transaction, or before), then
  publish `Ready`. A repair from an available archive comes first.
- **Authority catalogue.** A table of declared losses (event, store,
  incarnation) and of reruns, never deleted. The catalogue stays outside the
  restored domain (D-05).
- **Rerun.** The job is rescheduled with the same identifier, unless its
  subject is revoked. `RecordOutcome` rejects a new digest for a known ID
  (`ErrConflict`), so the rerun needs its own record before the external
  success.
- **API.** A distinct result state for a declared loss and for a confirmed
  rerun, with its documentation (product spec §10.4).
- **Conformance.** No Go test reads this model's traces today. The runs above
  are the P2 scenarios to project when REC-02 adds them.

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
