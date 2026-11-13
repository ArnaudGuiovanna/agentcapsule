# Observability (OPS-02)

The API and the worker give operators metrics, in the Prometheus text format,
and one structured event per line. Neither carries content, secrets or tenant
data. [internal/telemetry](../internal/telemetry) enforces that by
construction:
- **Closed vocabularies.** Every metric label and every event code declares the
  exact list of its values. Anything else becomes `other` (metrics) or `invalid`
  (events). A filter on characters would not do: a token is made of ordinary
  characters.
- **No free text.** The other event fields are numbers, durations and random
  request IDs.
- **No tenant identifiers.** Metrics name no organization, agent or member, so
  operators see technical metrics only, and the number of series stays bounded.
- **No new dependency.** The package uses only the standard library. Any
  OpenTelemetry collector with a Prometheus receiver can read the same
  endpoints.

## Endpoints

Every endpoint is on loopback only. Run Prometheus or a collector on the same
host ([deploy/prometheus/prometheus.yml](../deploy/prometheus/prometheus.yml)).

| Process | Setting | Example |
| --- | --- | --- |
| API | `agentcapsule-api -metrics-listen <addr>` | `127.0.0.1:9464` |
| Worker | `"metrics_listen"` in its configuration ([worker.md](worker.md)) | `127.0.0.1:9465` |
| Authorities' replica (standby) | `"metrics_listen"` in `agentcapsule-authority serve`'s configuration ([recovery.md](recovery.md#install-the-replica)) | `127.0.0.1:9466` |

A non-loopback address is refused at start (`metrics_listen_must_be_loopback`).

node_exporter, scraped as the job `node`, serves the host's resources and,
through its textfile collector, what three scripts write
([recovery.md](recovery.md)): the base-backup times, the shipping of the
volume archives and, on the standby host, its replay.

## Metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `agentcapsule_api_requests_total` | counter | `route`, `method`, `status_class` | API requests, by route pattern (`/v1/agents/{id}`), never by the IDs in the path |
| `agentcapsule_api_request_duration_seconds` | histogram | `route` | API latency |
| `agentcapsule_worker_jobs_total` | counter | `kind`, `outcome` | Durable jobs processed: `done` or `retried` |
| `agentcapsule_worker_job_retries_total` | counter | `kind`, `reason` | Why a job waits: `wake_budget`, `slim_unavailable`, `capacity`, `error` |
| `agentcapsule_worker_vm_starts_total` | counter | `outcome` | VM boots for work: `started` or `failed` |
| `agentcapsule_worker_vm_start_seconds` | histogram | — | Duration of successful boots |
| `agentcapsule_worker_jobs`, `_jobs_due`, `_jobs_failing` | gauge | `kind` | The host's jobs; those due and not held by a worker; those that failed three times or more |
| `agentcapsule_worker_job_oldest_due_seconds` | gauge | `kind` | How long the oldest due job has waited past its time. A retry's backoff is not delay |
| `agentcapsule_worker_vms_running`, `_vm_capacity` | gauge | — | Running VMs, and `max_active` |
| `agentcapsule_worker_root_disk_used_ratio` | gauge | — | Used share of the runtime root's file system |
| `agentcapsule_worker_directory_publish_retries_total` | counter | — | Directory publication passes that failed |
| `agentcapsule_worker_harness_import_retries_total` | counter | — | Harness imports to try again |
| `agentcapsule_worker_volume_archives_total` | counter | `vm`, `outcome` | Volume archive captures ([worker.md](worker.md#nightly-encrypted-archives)), by the VM's state before the capture (`asleep`, `running`): `captured` or `retried` |
| `agentcapsule_worker_volume_archive_agents` | gauge | — | Live agents of the host whose volume the worker archives |
| `agentcapsule_worker_volume_archive_oldest_seconds` | gauge | — | Age of the oldest among the agents' newest archives. An agent never archived counts from its initialization |
| `agentcapsule_authority_replication_enabled` | gauge | — | 1 when the worker's authorities replicate to the standby; 0 standalone, without disaster protection ([worker.md](worker.md#replica-of-the-authorities)) |
| `agentcapsule_authority_replication_committed_sequence`, `_acknowledged_sequence` | gauge | — | Last authority record committed by the worker, and last one the replica acknowledged |
| `agentcapsule_authority_replication_lag_records`, `_lag_seconds` | gauge | — | Authority records committed and not acknowledged, and the age of the oldest |
| `agentcapsule_authority_replication_last_error` | gauge | `kind` | 1 for the kind of the last replication attempt's error; `none` after a success |
| `agentcapsule_authority_replication_errors_total` | counter | `kind` | Failed replication attempts |
| `agentcapsule_authority_replication_write_seconds` | histogram | — | Time from an authority record's local commit to the replica's acknowledgment |
| `agentcapsule_authority_replica_applied_sequence`, `_epoch`, `_last_apply_timestamp_seconds` | gauge | — | The replica's position, epoch and last apply (`agentcapsule-authority serve`, standby host) |
| `agentcapsule_authority_replica_refusals_total` | counter | `kind` | Requests the replica refused: `gap`, `older_epoch`, `newer_epoch`, `conflict`, `promoted`, `identity`, `invalid`, `unavailable` (standby host) |
| `agentcapsule_telemetry_collect_errors_total` | counter | — | Scrapes whose current values could not be read |
| `agentcapsule_telemetry_series_dropped_total` | counter | — | Samples dropped at a metric's series limit (512) |
| `agentcapsule_postgres_wal_archiving_enabled` | gauge | — | 1 when PostgreSQL archives its WAL: `archive_mode` on and an archive command or library set (worker) |
| `agentcapsule_postgres_wal_archive_timeout_seconds` | gauge | — | PostgreSQL's `archive_timeout`; 0 when off (worker) |
| `agentcapsule_postgres_wal_archive_age_seconds` | gauge | — | Time since PostgreSQL last archived a WAL file (worker). If it archived none since its statistics began, the time since then |
| `agentcapsule_postgres_wal_archive_pending` | gauge | — | 1 when a completed WAL segment waits for archiving (worker) |
| `agentcapsule_postgres_wal_archive_failing` | gauge | — | 1 when the latest archive attempt failed (worker) |
| `agentcapsule_backup_last_success_timestamp_seconds` | gauge | `repo` (`s3`, `standby`), `type` (`full`, `diff`) | When the newest base backup of that type in that repository finished; 0 when it holds none (node_exporter) |
| `agentcapsule_backup_repository_readable` | gauge | `repo` | 1 when pgBackRest could read the repository's list of backups (node_exporter) |
| `agentcapsule_backup_collected_timestamp_seconds` | gauge | — | When the backup times above were last collected (node_exporter) |
| `agentcapsule_archive_ship_last_success_timestamp_seconds` | gauge | `store` (`s3`, `standby`) | When the store last held every complete volume archive the host had, within the store's retention; 0 when it never did (node_exporter) |
| `agentcapsule_archive_ship_pending_archives` | gauge | `store` | Complete volume archives of the host, within the store's retention, that the store lacked after the last run (node_exporter) |
| `agentcapsule_archive_ship_changed_archives` | gauge | `store` | Volume archives complete on the store whose host copy changed after the upload; the store keeps its copy (node_exporter) |
| `agentcapsule_archive_ship_store_readable` | gauge | `store` | 1 when the last run could list the store (node_exporter) |
| `agentcapsule_archive_ship_collected_timestamp_seconds` | gauge | — | When the shipper last wrote these metrics (node_exporter) |
| `agentcapsule_standby_postgres_up` | gauge | — | 1 when the standby's PostgreSQL answered (node_exporter, standby host) |
| `agentcapsule_standby_in_recovery` | gauge | — | 1 while the standby replays the WAL archive; 0 once promoted (node_exporter, standby host) |
| `agentcapsule_standby_replay_timestamp_seconds` | gauge | — | Commit time of the last transaction the standby replayed; its start time if it replayed none since (node_exporter, standby host) |
| `agentcapsule_standby_collected_timestamp_seconds` | gauge | — | When the standby's replay was last collected (node_exporter, standby host) |

The worker reads its gauges at each scrape, from PostgreSQL and the host, with
a 5-second bound.

**WAL archiving** (REC-03) is read from `pg_stat_archiver` and the settings.
Every role may read them, so the worker's database role needs no grant.
PostgreSQL leaves some fields empty, and the worker handles each case:
- **Nothing archived** since the statistics began (the cluster's creation, a
  crash recovery, a reset). The age counts from that start, or from the
  server's start: nothing was archived for at least that long.
- **No failure** recorded. The archiving is not failing. A failure older than
  the last success is over: a retry archived the segment.
- **A pending segment** is a completed one after the last archived file. The
  open segment does not count: `archive_timeout` closes it. So an idle
  database has nothing pending, however old its last archive. A standby has no
  write position, so nothing is pending there.

No WAL file name, command or path is exposed.

**Base backups** run outside the worker, under systemd. Every 15 minutes,
`agentcapsule-backup-metrics.timer` runs
[agentcapsule-backup-metrics.py](../deploy/backup/agentcapsule-backup-metrics.py).
It reads `pgbackrest info` and writes `agentcapsule-backup.prom` for
node_exporter's textfile collector:
- The file is replaced atomically and has mode 0644.
- Its labels take declared values only. No text from pgBackRest is copied:
  no backup label, path, host or message.
- The values are timestamps, so the alerts' ages keep growing even if the
  script stops running.
- A repository that cannot be read has no backup times in the file. Its own
  alert fires instead.

**Volume archives off the host** (REC-02). Every hour,
`agentcapsule-archive-ship.timer` runs
[agentcapsule-archive-ship.py](../deploy/backup/agentcapsule-archive-ship.py),
which ships the archives to both stores, then writes
`agentcapsule-archive-ship.prom`. The same rules hold: atomic replacement,
mode 0644, declared label values, no archive ID, agent ID, path or message. A
store that cannot be listed has no counts in the file. The last successful
ship is a time, kept in the shipper's state directory, so its alert's age
keeps growing if the shipper stops.

**The standby's replay** (REC-03). On the standby host, every minute,
`agentcapsule-standby-metrics.timer` runs
[agentcapsule-standby-metrics.py](../deploy/standby/agentcapsule-standby-metrics.py),
which asks PostgreSQL and writes `agentcapsule-standby.prom`. The primary
commits an empty transaction every minute (`agentcapsule-pg-heartbeat.timer`),
so the age of the last replayed transaction stays a few minutes even on an
idle platform, and measures the replay ([recovery.md](recovery.md#how-far-behind-the-standby-is)).

## Events

Each process writes one JSON object per line, with `time` and `event` first:
- **Progress** goes to standard output.
- **Retries and failures** go to standard error.
- **Startup refusals**, before the process runs, stay single fixed codes
  (`configuration_invalid`, …).

| Process | Event | Fields |
| --- | --- | --- |
| API | `http_request` | `request_id`, `route`, `method`, `status`, `problem` (the problem code, if any), `duration` |
| Worker | `maintenance_started`, `maintenance_complete` | — |
| Worker | `maintenance_retry` | `reason` (as above) |
| Worker | `wake_budget_exhausted`, `harness_import_retry`, `directory_publish_retry`, `slim_callback_stopped` | — |
| Worker | `job_done` (standard output), `job_retried` (standard error) | `kind`, `request_id` of the API request that started the work, if any, and `reason` for a retry |
| Worker | `volume_archive_captured` (standard output) | `vm` (`asleep`, `running`), `bytes`, `seconds`, `removed` (older archives deleted) |
| Worker | `volume_archive_retry` (standard error) | `vm`, `reason`: `placement`, `busy`, `disk_full`, `authority`, `timeout`, `retention`, `error` |

**Correlation.** Every API response carries `X-Request-ID`, a random 128-bit
value. The ID says nothing about the person or the content. It follows the
work:
1. The request's `http_request` event carries it.
2. The operation the request creates (an invocation, an agent, a wake or sleep)
   records it. The API sets it for its database transaction, and the
   operation's column takes it as default (migration 0027).
3. The worker's `job_done` and `job_retried` events carry it for every job that
   work causes:
   - the invocation's delivery;
   - the provisioning or lifecycle operation;
   - the requests, replies and statuses its agent then exchanges with other
     agents under the mandate the invocation granted;
   - their closures and expirations.

So a person's report ("my call failed, request ID …") leads from the API's
log to every job it caused, on the other agents' side included. Work that no
API request started (an agent's own schedule, an expiry) carries no ID.

## Alerts

[deploy/prometheus/alerts.yml](../deploy/prometheus/alerts.yml) holds the rules.
Their annotations are fixed text.

| Alert | When |
| --- | --- |
| `AgentCapsuleTargetDown` | A process does not answer its scrape for 2 minutes |
| `AgentCapsuleAPIServerErrors` | More than 5 % of API requests fail with a 5xx, for 10 minutes |
| `AgentCapsuleQueueDelayed` | A due job has waited more than 5 minutes past its time |
| `AgentCapsuleJobsFailing` | Jobs failed three times or more, for 15 minutes |
| `AgentCapsuleVMBootFailures` | More than 3 failed boots in 15 minutes |
| `AgentCapsuleCapacityExhausted` | The host runs `max_active` VMs for 15 minutes |
| `AgentCapsuleDiskPressure`, `AgentCapsuleDiskCritical` | The runtime root's file system is over 70 % or 80 % full |
| `AgentCapsuleSLIMUnavailable` | Deliveries keep waiting for the SLIM bridge or node |
| `AgentCapsuleDirectoryUnavailable` | Directory publication keeps failing |
| `AgentCapsuleWakeBudgetExhausted` | An organization reached its wake budget (info) |
| `AgentCapsuleMetricsStale` | A process cannot read its current state for its metrics |
| `AgentCapsuleHostMemoryLow`, `AgentCapsuleHostCPUSaturated` | Host memory below 10 %, or CPUs over 90 % busy, from node_exporter |
| `AgentCapsuleWALArchivingMisconfigured` | PostgreSQL does not archive its WAL, or `archive_timeout` is off or above 15 minutes, for 5 minutes (critical) |
| `AgentCapsuleWALArchiveFailing` | The latest WAL archive attempt has failed for 5 minutes (critical) |
| `AgentCapsuleWALArchiveStale` | No WAL archived for 15 minutes while a completed segment waits: the database's RPO is breached (critical) |
| `AgentCapsuleWALArchiveBacklog` | A completed segment has waited at every scrape for 15 minutes: archiving does not keep up |
| `AgentCapsuleBackupStale` | A repository has no base backup that finished in the last 26 hours |
| `AgentCapsuleFullBackupStale` | A repository has no full backup that finished in the last 8 days |
| `AgentCapsuleBackupRepositoryUnreadable` | pgBackRest cannot read a repository, for 30 minutes |
| `AgentCapsuleBackupMetricsStale` | The backup times have not been collected for an hour, or never were |
| `AgentCapsuleVolumeArchiveStale` | An agent of the host has no volume archive from the last 26 hours, for 15 minutes (volume RPO 24 h). It covers the archives on the host only |
| `AgentCapsuleArchiveShipBehind` | A store has lacked some of the host's volume archives for 2 hours, for 15 minutes: two missed hourly runs |
| `AgentCapsuleArchiveStoreUnreadable` | The shipper could not list a store for 90 minutes: two runs in a row |
| `AgentCapsuleArchiveChanged` | A volume archive changed on the host after its upload; the store keeps its copy (critical) |
| `AgentCapsuleArchiveShipMetricsStale` | The shipper has not run for 3 hours, or never ran |
| `AgentCapsuleStandbyReplayBehind` | The standby, in recovery, has replayed no transaction committed in the last 15 minutes, for 2 minutes: it is behind the database's RPO (critical) |
| `AgentCapsuleStandbyNotInRecovery` | The standby is not in recovery for 5 minutes: promoted, or started as a primary (critical) |
| `AgentCapsuleStandbyDown` | The standby's PostgreSQL does not answer for 5 minutes |
| `AgentCapsuleStandbyMetricsStale` | The standby's replay has not been collected for 10 minutes, or never was |

[alerts_test.yml](../deploy/prometheus/alerts_test.yml) holds promtool unit
tests for the disk, queue, scrape, SLIM, backup, shipping and standby alerts.
Each backup, shipping and standby threshold is tested on both sides.
`scripts/verify-alerts.py` checks that every metric the alerts use is
registered by the code or declared by one of the three textfile scripts. For
the scripts' metrics, it also checks each label and value that the rules and
tests match against the script's vocabulary, so a typo fails. With
`--promtool` or `--promtool-image <image@sha256:…>`, it also runs
`promtool check rules` and `promtool test rules`. CI runs it with Prometheus
v3.5.0, pinned by digest. A raised disk threshold, or a raised WAL or backup
threshold, makes the tests fail. So does each of 16 changes to the shipping
and standby rules: a threshold raised or lowered, a longer delay, the standby
alert without its recovery guard (checked on 2026-11-13).

On KVM, the A2A journey of the product campaign wires the worker's telemetry
as its service does. It checks the real metrics: running VMs, boots,
deliveries, the wait at the wake budget, the disk. It also checks that the
request ID of a person's invocation is on the delivery of that invocation and
on the delivery of the request its agent sent to another agent. It passed on
2026-11-13.

## Not yet covered

- Distributed traces (spans and timings across processes). Correlation is by
  request ID only.
- An operator command for diagnostics (API-02).
- Alert thresholds tuned under load (OPS-03).
