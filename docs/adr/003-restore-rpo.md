# D-03 — RPO, confirmation and restore

Date: November 8, 2026. **Status: option B chosen on November 8, 2026**
(announced loss within the RPO window). The P2 model and its traces remain to be
updated before any incompatible code; REC-02 is unblocked under this condition.
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
  chosen, with the negative checks.
- Write the loss-window policy in product spec §10.4 and in the API (statuses).
- Unblock REC-02 (22 P2 projections) and REC-03 (restore on a second host).
- Handle D-05 (keys, secrets, revocations outside the restored domain) together:
  a backup predating an offboarding must reactivate neither members, nor tokens,
  nor revoked delegations, whichever the option.
