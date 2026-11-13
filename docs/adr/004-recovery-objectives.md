# REC-01 — Failure domains and recovery objectives

Date: November 13, 2026. **Decided by the user on November 13, 2026.**
It completes D-03 ([003-restore-rpo.md](003-restore-rpo.md), option B: a loss
within the announced window is allowed, reported and rescheduled). It sets the
numbers that ADR left open. References: product spec, Operations and recovery
([product.md](../product.md)); REC-02 to REC-04 and D-05 of the
[roadmap](../../ROADMAP.md).

## Failure domains

| Domain | Examples | Promise |
| --- | --- | --- |
| **Local restart** | A process crash, PostgreSQL restarted, the host rebooted | **Nothing confirmed is lost.** PostgreSQL commits synchronously, with `fsync` and full-page writes checked at each transaction. Agent volumes are on the host. VMMs are adopted again or restarted, and durable jobs resume. This is how the platform already works; the crash and WAL-recovery campaigns qualify it. |
| **Disaster** | The host, its disks or its datacenter lost | **Restore on another host from off-host backups**, within the objectives below. Work confirmed after the last backup point may be lost: it is **announced** to the callers and the jobs are **rescheduled** idempotently (D-03, option B). |

## Objectives (disaster)

| Data | RPO (maximum loss) | How |
| --- | --- | --- |
| PostgreSQL: accounts, organizations, agents, invocations, requests, results, audit, receipts | **15 minutes** | Continuous archiving of PostgreSQL's write-ahead log (a WAL segment at least every 15 minutes, `archive_timeout`), plus regular base backups |
| Agent volumes (encrypted: files, sessions, state) | **24 hours** | One archive of each agent per night, taken while the agent sleeps, so that it is never interrupted. An agent that never sleeps is put to sleep briefly, once a day. |

**RTO: 1 hour**, from the decision to fail over to the service answering on
the standby host. Within this hour, the platform must:
- promote the standby's database;
- install the configuration and the authorities;
- adopt the agents;
- move the address that clients use.

The RPO and the RTO must be **measured** by a restore exercise on the standby
host (REC-03), not assumed. The measured values are recorded next to these
objectives.

## Storage

Backups leave the host **encrypted**: neither store ever sees data in clear.
The volume archives are already encrypted LUKS containers; the PostgreSQL
backups are encrypted before upload. There are two copies:

1. **Object storage compatible with S3** (primary), versioned, with a retention
   policy and object lock where the provider offers it.
2. **A second server over SSH**, which is also the **standby host**. A 1-hour
   RTO cannot wait for a new server, so the standby is kept ready at all times:
   - it replays the WAL archive continuously, as a PostgreSQL standby;
   - it holds the latest volume archives;
   - it has the same release of the platform installed.

## Consequences

- **Two loss windows after a disaster.** The database may be up to 15 minutes
  behind, and an agent's memory up to 24 hours behind the database. An
  agent's work recorded in PostgreSQL after its last volume archive is
  therefore missing from its own memory. The restore declares that loss per
  agent: what was lost is shown to the organization, and the jobs are
  rescheduled. It never serves the agent as if nothing had happened.
- **Keys and revocations** (D-05) stay outside the restored domain. The standby
  must reach the key authority and the restore authority without restoring
  them from the same backups. A backup older than an offboarding must not
  reactivate members, tokens, delegations or keys revoked since (product spec).
  D-05 has to be settled before a disaster restore can be qualified.
- **The P2 model** ([restore_authority.qnt](../../spec/restore_authority.qnt))
  was revised on November 13, 2026: `noLostAcknowledgedOutcome` became
  `noUndeclaredLoss` ("no **unannounced** loss"), with an observable
  declared-loss state kept by the restore authority. The contract diff is in
  [ADR 003](003-restore-rpo.md#model-revision-option-b).
- **Callers see the difference.** After a restore, a result lost in the window
  has a distinct state, and the work is run again. The API needs this state and
  its documentation.
- **Work to do**, in this order:
  1. **REC-03, PostgreSQL backups.** WAL archiving to both stores, with base
     backups.
  2. **REC-03, the standby.** Continuous WAL replay on the standby.
  3. **REC-03, freshness.** Metrics and alerts on backup freshness: the age of
     the last archived WAL segment and of each volume archive, with the alert
     rules of OPS-02.
  4. **REC-02, volume archives.** Nightly archives of sleeping agents without
     stopping the maintenance worker. Today a capture requires stopping it.
  5. **REC-02 and D-03, declared loss.** The declared-loss state, in the model,
     then in the code and the API.
  6. **REC-03, the exercise.** A failover exercise on the standby that measures
     the RPO and the RTO. It is repeated regularly.

## Options considered

| Choice | Options | Chosen |
| --- | --- | --- |
| Database RPO | 15 minutes (continuous WAL archiving), 1 hour, 24 hours | 15 minutes |
| Volume RPO | 24 hours (nightly, while asleep), 1 hour, no volume backup | 24 hours |
| RTO | 4 hours (prepared procedure, new server), 24 hours, 1 hour (standby always ready) | 1 hour |
| Storage | S3-compatible object storage, a second server over SSH, both | Both; the second server is the standby |
