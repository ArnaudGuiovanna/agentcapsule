# Observability (OPS-02)

The API and the worker give operators metrics, in the Prometheus text format,
one structured event per line and, on request, [traces](#traces). None carries
content, secrets or tenant data. [internal/telemetry](../internal/telemetry)
enforces that by construction:
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
| Authority service: the primary's service, or the replica on the standby | `"metrics_listen"` in `agentcapsule-authority serve`'s configuration ([recovery.md](recovery.md#install-the-authority-service)), the same port on both hosts | `127.0.0.1:9466` |

A non-loopback address is refused at start (`metrics_listen_must_be_loopback`).

node_exporter, scraped as the job `node`, serves the host's resources and,
through its textfile collector, what three scripts write
([recovery.md](recovery.md)): the base-backup times, the shipping of the
volume archives and, on the standby host, its replay.

## Metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `agentcapsule_api_requests_total` | counter | `route`, `method`, `status_class` | API requests, by route pattern (`/v1/agents/{id}`), never by the IDs in the path |
| `agentcapsule_api_request_duration_seconds` | histogram | `route` | API latency, excluding invocation and corpus build event subscriptions |
| `agentcapsule_api_streams_active` | gauge | — | Open invocation and corpus build event subscriptions. Each events route counts once in `agentcapsule_api_requests_total` and the request log when the subscription closes |
| `agentcapsule_api_access_revocations_pending` | gauge | — | Access revocations recorded with the authority service but not confirmed: the standby does not hold their record yet ([ADR 006](adr/006-authority-service.md) wave 5). Above 0 in degraded mode; it falls once the standby catches up and the API confirms them (every 5 seconds) |
| `agentcapsule_api_access_revocation_oldest_pending_seconds` | gauge | — | How long the oldest pending revocation has waited; 0 when none. Long after degraded mode ended, the standby refuses the records: a standby of an older release ([recovery.md](recovery.md#pending-revocations)) |
| `agentcapsule_worker_jobs_total` | counter | `kind`, `outcome` | Durable jobs processed: `done` or `retried` |
| `agentcapsule_worker_job_retries_total` | counter | `kind`, `reason` | Why a job waits: `wake_budget`, `agent_failed`, `slim_unavailable`, `capacity`, `organization_quota` (its organization's quotas on VMs, vCPUs or RAM, [ADR 021](adr/021-organization-quotas.md)), `storage_pressure`, `error` |
| `agentcapsule_worker_deliveries_dead_total` | counter | `kind`, `reason` | Deliveries that died ([ADR 007](adr/007-delivery-closure-and-priority.md)): `kind` `reply`, `status` or `instruction`; `reason` `attempts_exhausted` or `expired`, the deadline winning when both hold. A delivery that the deletion of an agent cancels is not counted. Every series is served from zero. It says that deliveries died, not whose. A worker that stops between a death's commit and its count loses that count; the dead delivery in PostgreSQL stays the record |
| `agentcapsule_worker_vm_starts_total` | counter | `outcome` | VM boots for work: `started` or `failed` |
| `agentcapsule_worker_vm_start_seconds` | histogram | — | Duration of successful boots |
| `agentcapsule_worker_guest_failures_total` | counter | `kind` | Guests that failed to boot (`boot`), went away without a stop (`crash`), or did not answer the fence of a delivery past its attempts, or of their agent's deletion, and were stopped (`unresponsive`), counted against restart budgets while their agent is live ([ADR 012](adr/012-limits-restart-budgets-egress.md)). Served from zero |
| `agentcapsule_worker_agents_failed_total` | counter | — | Agents that spent their restart budget and became `FAILED`. Served from zero |
| `agentcapsule_worker_agents_failed` | gauge | — | Live agents of the host that are `FAILED` now: they boot again only when woken or cleared |
| `agentcapsule_worker_jobs`, `_jobs_due`, `_jobs_failing` | gauge | `kind` | The host's jobs; those due and not held by a worker; those that failed three times or more |
| `agentcapsule_worker_job_oldest_due_seconds` | gauge | `kind` | How long the oldest due job has waited past its time. A retry's backoff is not delay. An agent's deliveries share one job, its head: a backlog behind it does not show here |
| `agentcapsule_worker_invocations_waiting` | gauge | — | Invocations accepted for the host's agents and not yet delivered |
| `agentcapsule_worker_invocation_oldest_waiting_seconds` | gauge | — | How long the oldest of them has waited since it was accepted, or released for a scheduled one |
| `agentcapsule_worker_vms_running`, `_vm_capacity` | gauge | — | Running VMs, and `max_active` |
| `agentcapsule_worker_agents_queued` | gauge | — | Agents of the host whose work waits for a VM slot (`QUEUED`, [ADR 017](adr/017-capacity-queue-and-dead-letter-replay.md)) |
| `agentcapsule_worker_capacity_oldest_wait_seconds` | gauge | — | How long the oldest of them has waited |
| `agentcapsule_worker_agents_waiting_for_quota` | gauge | — | Agents of the host whose work waits for their organization's quotas (`QUEUED`, `queue_reason` `organization_quota`, [ADR 021](adr/021-organization-quotas.md)); not in the two gauges above |
| `agentcapsule_worker_root_disk_used_ratio` | gauge | — | Used share of the runtime root's file system |
| `agentcapsule_worker_image_disk_used_ratio` | gauge | — | Used share of the file system of the harness images (the registry's cache) |
| `agentcapsule_worker_storage_pressure` | gauge | `filesystem` (`data`, `images`) | 1 while that file system is past `storage_pressure`: new agents (`data`) or imports (`images`) are refused ([worker.md](worker.md#storage-pressure)) |
| `agentcapsule_worker_directory_publish_retries_total` | counter | — | Directory publications deferred because the Directory could not be reached or refused them, and publication passes that could not read PostgreSQL |
| `agentcapsule_worker_harness_import_retries_total` | counter | — | Harness imports to try again |
| `agentcapsule_worker_volume_archives_total` | counter | `vm`, `outcome` | Volume archive captures ([worker.md](worker.md#nightly-encrypted-archives)), by the VM's state before the capture (`asleep`, `running`): `captured` or `retried` |
| `agentcapsule_worker_volume_archive_agents` | gauge | — | Live agents of the host whose volume the worker archives |
| `agentcapsule_worker_volume_archive_oldest_seconds` | gauge | — | Age of the oldest among the agents' newest archives. An agent never archived counts from its initialization |
| `agentcapsule_worker_deletions_unfinished` | gauge | — | Agents of the host whose deletion is requested and not finished: their volume key still exists, so their archives still open ([ADR 018](adr/018-key-lifecycle-and-archive-deletion.md)). On a host without a key authority, a deletion finishes at its seal. Read from PostgreSQL at each scrape |
| `agentcapsule_worker_deletion_oldest_seconds` | gauge | — | Age of the oldest of these deletions, from its request; 0 when none |
| `agentcapsule_worker_streams_open` | gauge | `kind` (`output`, `llm`) | Streams open on the platform channels of the host's VMs: output streams of working invocations ([ADR 022](adr/022-native-streaming.md), [worker.md](worker.md#output-streams)), and model streams. Every series is served from zero |
| `agentcapsule_worker_stream_frames_total` | counter | `outcome` (`stored`, `refused`, `truncated`) | Frames of output streams: stored in a chunk; refused (invalid, after the invocation's outcome, of an old attempt or boot, or still buffered when the stream closed); past the attempt's limits. Every series is served from zero |
| `agentcapsule_worker_stream_first_delta_seconds` | histogram | — | From an invocation's `working` answer to the first stored delta of its attempt, buckets 0.1 to 300 s |
| `agentcapsule_llm_calls_total` | counter | `provider` (`openai_compatible`, `anthropic`), `outcome` (`settled`, `released`, `unknown`) | Model calls through the worker's bridge ([llm.md](api/llm.md#budgets-and-consumption-llm-03)), once their outcome is recorded. Only with the model bridge on |
| `agentcapsule_llm_tokens_total` | counter | `provider`, `direction` (`input`, `output`) | Tokens of settled calls, as the provider reported them |
| `agentcapsule_llm_estimated_cost_micro_total` | counter | `provider` | Estimated cost of settled calls, in micro-units of each organization's own currency: a sum across organizations that price in different currencies has no meaning |
| `agentcapsule_llm_refusals_total` | counter | `reason` (`budget_tokens`, `budget_cost`, `unpriced`, `alias_access`) | Calls refused before any reservation. Every series is served from zero |
| `agentcapsule_llm_budget_soft_exceeded_total` | counter | `unit` (`tokens`, `cost`) | Calls that went past a soft budget; a call past two counts twice. Every series is served from zero |
| `agentcapsule_llm_unresolved_calls` | gauge | — | Calls of unknown outcome, across the installation, that wait for their organization to settle or release them |
| `agentcapsule_llm_stream_first_event_seconds` | histogram | — | Time from a model stream's provider request to its first event ([ADR 022](adr/022-native-streaming.md) §3), buckets 0.1 to 60 s. A stream is a call for `agentcapsule_llm_calls_total` |
| `agentcapsule_authority_service_holds` | gauge | `kind` | Holds the authority service grants now: `binding`, `key`, `fences`, `revocation`, `activation` ([ADR 006](adr/006-authority-service.md#the-hold)) |
| `agentcapsule_authority_service_hold_expired_total` | counter | `kind` | Holds the service ended at their cap (30 seconds for a publish, `max_key_hold` for a key), closing their connection |
| `agentcapsule_authority_service_refused_peers_total` | counter | `socket` | Connections the service closed at accept because of their peer's account: `worker`, `api` |
| `agentcapsule_authority_replication_enabled` | gauge | — | 1 when the authority service's authorities replicate to the standby; 0 standalone, without disaster protection ([worker.md](worker.md#the-authority-service)) |
| `agentcapsule_authority_replication_committed_sequence`, `_acknowledged_sequence` | gauge | — | Last authority record committed by the authority service, and last one the replica acknowledged |
| `agentcapsule_authority_replication_lag_records`, `_lag_seconds` | gauge | — | Authority records committed and not acknowledged, and the age of the oldest |
| `agentcapsule_authority_replication_last_error` | gauge | `kind` | 1 for the kind of the last replication attempt's error; `none` after a success |
| `agentcapsule_authority_replication_errors_total` | counter | `kind` | Failed replication attempts |
| `agentcapsule_authority_replication_write_seconds` | histogram | — | Time from an authority record's local commit to the replica's acknowledgment |
| `agentcapsule_authority_replication_degraded_since_timestamp_seconds` | gauge | — | When the authority service entered degraded mode, without the standby, as a Unix time; 0 outside it ([recovery.md](recovery.md#degraded-mode)) |
| `agentcapsule_authority_replication_degraded_waiting` | gauge | `kind` | Authority operations waiting for the standby in degraded mode: `registration`, `reservation`, `loss`, `activation`, `seal`, `key_create`, `key_destroy`, `revocation_done`; `outcome`, `rerun`, `fence`, `revocation_start`, `access` (an access revocation record) and `read` only behind a waiting write the standby lacks |
| `agentcapsule_authority_replication_degraded_refused_total` | counter | `kind` | Authority operations that waited for the standby in degraded mode until their deadline |
| `agentcapsule_authority_receipt_key_ready` | gauge | `day` (`today`, `tomorrow`) | 1 when the authority service holds that day's receipt key, created ([recovery.md](recovery.md#the-daily-receipt-keys)). Tomorrow's waits for the standby in degraded mode. Primary role |
| `agentcapsule_authority_receipt_keys_overdue` | gauge | — | Daily receipt keys the service still holds after their destruction time (01:00 UTC two days after their day began): their destruction waits for the standby, or fails |
| `agentcapsule_authority_replica_applied_sequence`, `_epoch`, `_last_apply_timestamp_seconds` | gauge | — | The replica's position, epoch and last apply (`agentcapsule-authority serve`, standby host) |
| `agentcapsule_authority_replica_refusals_total` | counter | `kind` | Requests the replica refused: `gap`, `older_epoch`, `newer_epoch`, `conflict`, `promoted`, `identity`, `invalid`, `unavailable` (standby host) |
| `agentcapsule_telemetry_collect_errors_total` | counter | — | Scrapes whose current values could not be read |
| `agentcapsule_telemetry_series_dropped_total` | counter | — | Samples dropped at a metric's series limit (512) |
| `agentcapsule_telemetry_spans_dropped_total` | counter | — | Spans dropped because the queue to the trace file was full or a write failed ([traces](#traces)); only with a trace file |
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
| API | `audit_refusal_unrecorded` (standard output) | — : a refused administrative attempt that its organization's trail could not record ([ADR 014 §10](adr/014-operations-capacity-diagnostics-audit.md#10-refused-attempts-in-the-organizations-trail)); its answer went out |
| Worker | `maintenance_started`, `maintenance_complete` | — |
| Worker | `maintenance_retry` | `reason` (as above) |
| Worker | `wake_budget_exhausted`, `harness_import_retry`, `directory_publish_retry`, `slim_callback_stopped` | — |
| Worker | `job_done` (standard output), `job_retried` (standard error) | `kind`, `request_id` of the API request that started the work, if any, and `reason` for a retry |
| Worker | `agent_failed` (standard error) | `reason` (`boot_failed`, `crashed`, `unresponsive`): an agent spent its restart budget; the event never names it |
| Worker | `delivery_dead` (standard error) | `kind` (`reply`, `status`, `instruction`), `request_id` of the API request that started the work, if any, `reason` (`attempts_exhausted`, `expired`). The job that retired the delivery still ends with `job_done` |
| Worker | `volume_archive_captured` (standard output) | `vm` (`asleep`, `running`), `bytes`, `seconds`, `removed` (older archives deleted) |
| Worker | `volume_archive_retry` (standard error) | `vm`, `reason`: `placement`, `busy`, `disk_full`, `authority`, `timeout`, `retention`, `error`; or, without `vm`, `reason` `purge`: the purge of deleted agents' archives stopped, and runs again an hour later |
| Worker | `volume_archive_purged` (standard output) | `removed`: archives of deleted agents, whose key is destroyed, deleted from the host ([worker.md](worker.md#nightly-encrypted-archives)) |
| Worker | `llm_budget_soft_exceeded` (standard error) | `unit` (`tokens`, `cost`), `period` (`day`, `month`), `scope` (`organization`, `agent`, `alias`, `agent_alias`) of the soft budget a model call went past |
| Worker | `llm_call_refused` (standard error) | `reason` (`budget_tokens`, `budget_cost`, `unpriced`, `alias_access`), and for a budget its `period` and `scope` |
| Worker, API | `authority_service_waiting` (standard error, once) | — : the process waits for the authority service at start |
| Worker, restore command | `restore_paused` (standard error) | `reason`: `authority_unavailable`, `waits_for_replica` |
| Authority service | `service_started` (standard output) | `epoch`, `mode` (`standalone`, `synchronous`, `degraded`, `waiting`) |
| Authority service | `service_stopped` (standard output); `peer_refused`, `hold_expired` (standard error) | `socket` for a refused peer, `kind` for an expired hold |
| Authority service | `receipt_key_created`, `receipt_key_destroyed` (standard output); `receipt_key_failed` (standard error) | `day` (YYYYMMDD, UTC); `step` (`create`, `destroy`) for a failure: a step that waits for the standby fails at its 30 seconds, and runs again a minute later ([recovery.md](recovery.md#the-daily-receipt-keys)) |

**Correlation.** Every API response carries `X-Request-ID`, a random 128-bit
value. The ID says nothing about the person or the content. It follows the
work:
1. The request's `http_request` event carries it.
2. The operation the request creates (an invocation, an agent, a wake or sleep)
   records it. The API sets it for its database transaction, and the
   operation's column takes it as default (migration 0027).
3. The worker's `job_done`, `job_retried` and `delivery_dead` events carry it
   for every job that work causes:
   - the invocation's delivery;
   - the provisioning or lifecycle operation;
   - the requests, replies and statuses its agent then exchanges with other
     agents under the mandate the invocation granted;
   - their closures and expirations.

So a person's report ("my call failed, request ID …") leads from the API's
log to every job it caused, on the other agents' side included. Work that no
API request started (an agent's own schedule, an expiry) carries no ID.

## Traces

The API and the worker record spans (OPR-3) when given a trace file; without
one, nothing is recorded (a default pending the product owner):

| Process | Setting |
| --- | --- |
| API | `agentcapsule-api -trace-file /var/log/agentcapsule/api-traces.jsonl` |
| Worker | `"trace_file": "/var/log/agentcapsule/worker-traces.jsonl"` in its configuration |

Each process appends OTLP/JSON lines to its file: each line is one
`ExportTraceServiceRequest` of the OpenTelemetry protocol, the format of the
OpenTelemetry Collector's `otlpjsonfile` receiver (contrib distribution). The
file is created with mode 0640; rotate it by copying and truncating
(logrotate's `copytruncate`). Nothing is sent over the network: a collector on
the host reads the files and exports where the operator decides.

```yaml
receivers:
  otlpjsonfile:
    include: [/var/log/agentcapsule/*-traces.jsonl]
service:
  pipelines:
    traces:
      receivers: [otlpjsonfile]
      exporters: [otlp]
```

**A trace is the work of one API request.** Its trace ID is the request's
`X-Request-ID`, and the request's span is its root. The worker joins that
trace through PostgreSQL, as the job events do (see Correlation above): the
operation the request created keeps the request ID, and each job finds it.
The job's span names the request's span as its parent, whose span ID is
derived from the request ID. The IDs have the sizes of W3C Trace Context: 16
bytes for a trace, 8 for a span, in lowercase hex. Work that no API request
started has a trace of its own. An incoming `traceparent` header is ignored:
a trace starts at the API.

| Span | Process, kind | Parent | Attributes |
| --- | --- | --- | --- |
| `api.request` | API, server | — | `http.route` (the pattern), `http.request.method`, `http.response.status_code`, `agentcapsule.problem`; pseudonyms `agentcapsule.organization`, `agentcapsule.principal`, `agentcapsule.path.<wildcard>` (never a download link's token) |
| `invocation.admit` | API, internal | `api.request` | `agentcapsule.outcome` (`accepted`, `replayed`, `refused`), `agentcapsule.problem`; pseudonyms `agentcapsule.agent`, `agentcapsule.invocation` |
| `worker.job` | worker, consumer | the request's span | `agentcapsule.job.kind`, `agentcapsule.outcome` (`done`, `retried`), `agentcapsule.retry_reason`, `agentcapsule.job.failures`; pseudonyms `agentcapsule.job`, `agentcapsule.agent` |
| `worker.wake` | worker, internal | `worker.job` | `agentcapsule.outcome` (`running`, `booted`, `capacity`, `organization_quota`, `failed`), `agentcapsule.wake.evicted`; pseudonym `agentcapsule.agent` |
| `worker.boot` | worker, internal | `worker.wake`, or the job | `agentcapsule.boot.purpose` (`work`, `fence`), `agentcapsule.outcome` (`started`, `failed`, `guest_failed`, `capacity`, `organization_quota`); pseudonym `agentcapsule.agent` |
| `worker.deliver` | worker, internal | `worker.job` | `agentcapsule.delivery.kind` (`invocation`, `agent_message`), `agentcapsule.delivery.transport` (`vsock`, `slim`), `agentcapsule.outcome`, `agentcapsule.retry_reason`; pseudonym `agentcapsule.agent` |
| `platform.call` | worker, server | see below | `agentcapsule.platform.call`, `agentcapsule.outcome` (`ok`, or the code the guest receives; for an output stream, `output_stream`, its `closed` reason), `agentcapsule.trace.origin` (`delivery`, `work`, `none`); pseudonym `agentcapsule.agent`. An output stream's span lasts the stream's life |
| `llm.call` | worker, client | `platform.call` | `agentcapsule.llm.provider`, `agentcapsule.llm.entry` (`complete`, `forward`), `agentcapsule.llm.mode` (`unary`, `stream`), `agentcapsule.outcome` (`stream_cut`: a stream cut after the provider's first byte, of unknown outcome), `agentcapsule.llm.attempts`, `agentcapsule.llm.input_tokens`, `agentcapsule.llm.output_tokens` |
| `authority.call` | API and worker, client | the span it runs under | `agentcapsule.authority.op`, `agentcapsule.outcome` (`ok`, `outage`, or the service's error code), `agentcapsule.authority.held` for a hold; the work done under a hold is its child |

A guest's platform call is a child of the delivery to its agent in progress
(`delivery`). After the delivery, a call that names its work (the completion
of an invocation, a request to another agent under a mandate, a reply, a
request's status) joins the trace of the API request behind that work, read
from PostgreSQL (`work`). Any other call begins a trace of its own (`none`).
The guest itself sends no trace context: nothing changes in the guest. A call
to the authority service outside a request or a job, such as the worker's
maintenance, has no span.

**Pseudonyms, not identifiers.** Every span type declares its attributes:
codes with the closed list of their values, numbers, and identifiers. A value
outside its list is written `invalid`, an undeclared key `invalid_key`. An
identifier is written as its pseudonym: the first 64 bits of HMAC-SHA256 of
the identifier under the installation's key, in hex. Migration 0044 creates
that key at random in PostgreSQL (`trace_pseudonym_key`); the API and the
worker read it at start, so an identifier has the same pseudonym in every
span of both. Without the key, a pseudonym tells nothing; with it, the
operator finds the spans of an agent, a member or an organization:

```bash
psql "$AGENTCAPSULE_DATABASE_URL" -Atc "SELECT encode(key,'hex') FROM trace_pseudonym_key" | python3 -c '
import hashlib, hmac, sys
key = bytes.fromhex(sys.stdin.read().strip())
print(hmac.new(key, sys.argv[1].encode(), hashlib.sha256).hexdigest()[:16])' <identifier>
```

The request ID is the trace ID as it is: it is random, names no one, and
leads from a person's report to the trace (a default pending the product
owner: whoever holds an export and a person's request ID can find that
person's trace). No span holds a path, a header, a
body, a token, a prompt, an answer, a model name, a provider's address, a
store or volume, or an error message. The key stays in the database and its
backups, never in a trace, a log or the diagnostic export.

**The cost is bounded.** A finished span waits in a queue of 4,096 for a
background writer, which writes up to 256 spans per line. When the queue is
full, for instance on a stuck disk, the span is dropped and counted
(`agentcapsule_telemetry_spans_dropped_total`): the work never waits for the
file. Recording a span takes a few microseconds; without a trace file,
nothing is recorded and nothing is allocated.

[trace_test.go](../internal/telemetry/trace_test.go) checks the OTLP shape,
that planted identifiers and secrets never reach a span, and the bounds:
`TestSpansAreOTLPJSONLinesThatFollowARequest`,
`TestNoIdentifierOrContentReachesASpan`, `TestTracingOverheadIsBounded`.
`TestTraceFollowsAnInvocationFromTheAPIToItsDelivery` (PostgreSQL) follows
one invocation from the API to its delivery by the worker, and finds none of
the request's identifiers, token, names or content in the spans.

## Alerts

[deploy/prometheus/alerts.yml](../deploy/prometheus/alerts.yml) holds the rules.
Their annotations are fixed text.

| Alert | When |
| --- | --- |
| `AgentCapsuleTargetDown` | A process does not answer its scrape for 2 minutes |
| `AgentCapsuleAPIServerErrors` | More than 5 % of API requests fail with a 5xx, for 10 minutes |
| `AgentCapsuleQueueDelayed` | A due job has waited more than 5 minutes past its time |
| `AgentCapsuleInvocationsDelayed` | An invocation has waited more than 15 minutes to be delivered, for 5 minutes |
| `AgentCapsuleJobsFailing` | Jobs failed three times or more, for 15 minutes |
| `AgentCapsuleDeliveryDead` | A reply or status died in the last 15 minutes: it could not be delivered to the agent that sent the request, which keeps its outcome ([ADR 007](adr/007-delivery-closure-and-priority.md)). A reply stays readable by the sender's agent for 7 days. An instruction's death is counted but does not alert: its requester sees it as a dead letter |
| `AgentCapsuleVMBootFailures` | More than 3 failed boots in 15 minutes |
| `AgentCapsuleAgentFailed` | An agent spent its restart budget in the last 15 minutes: its guest kept failing to boot or crashing, and it boots again only when woken or cleared ([ADR 012](adr/012-limits-restart-budgets-egress.md)) |
| `AgentCapsuleCapacityExhausted` | The host runs `max_active` VMs for 15 minutes |
| `AgentCapsuleWorkWaitingForCapacity` | Work has waited more than 10 minutes for a VM slot: every VM of the host is computing ([ADR 017](adr/017-capacity-queue-and-dead-letter-replay.md)) |
| `AgentCapsuleDiskPressure`, `AgentCapsuleDiskCritical` | The runtime root's file system is over 70 % or 80 % full |
| `AgentCapsuleImageDiskPressure`, `AgentCapsuleImageDiskCritical` | The harness images' file system is over 70 % or 80 % full |
| `AgentCapsuleStoragePressure` | A file system is past `storage_pressure` for 5 minutes: new agents or imports are refused (critical) |
| `AgentCapsuleSLIMUnavailable` | Deliveries keep waiting for the SLIM bridge or node |
| `AgentCapsuleDirectoryUnavailable` | Directory publication keeps failing: the Directory is down or refuses, while there is something to publish |
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
| `AgentCapsuleDeletionUnfinished` | An agent's deletion was requested 6 hours ago and has not finished, for 15 minutes: its volume key still exists, so its archives still open (ADR 018). A store that never fences the deletion, a failing removal, or degraded mode hold it; the worker's `job_retried` events with kind `deletion` give the reason |
| `AgentCapsuleArchiveShipBehind` | A store has lacked some of the host's volume archives for 2 hours, for 15 minutes: two missed hourly runs |
| `AgentCapsuleArchiveStoreUnreadable` | The shipper could not list a store for 90 minutes: two runs in a row |
| `AgentCapsuleArchiveChanged` | A volume archive changed on the host after its upload; the store keeps its copy (critical) |
| `AgentCapsuleArchiveShipMetricsStale` | The shipper has not run for 3 hours, or never ran |
| `AgentCapsuleStandbyReplayBehind` | The standby, in recovery, has replayed no transaction committed in the last 15 minutes, for 2 minutes: it is behind the database's RPO (critical) |
| `AgentCapsuleStandbyNotInRecovery` | The standby is not in recovery for 5 minutes: promoted, or started as a primary (critical) |
| `AgentCapsuleStandbyDown` | The standby's PostgreSQL does not answer for 5 minutes |
| `AgentCapsuleStandbyMetricsStale` | The standby's replay has not been collected for 10 minutes, or never was |
| `AgentCapsuleAuthorityServiceDown` | The authority service does not answer its scrape for 2 minutes: no agent boots, platform calls fail, deliveries wait, a restore pauses, the API's readiness probe answers 503 (critical) |
| `AgentCapsuleAuthorityDegraded` | The authority service has run in degraded mode, without the standby, for a minute: creating, deleting and restoring agents wait, and losing the host loses the outcomes recorded since (critical) |
| `AgentCapsuleAuthorityOperationsRefused` | An authority operation gave up waiting for the standby in degraded mode in the last 15 minutes |
| `AgentCapsuleAuthorityReplicationStopped` | Outside degraded mode, attempts to reach the authorities' replica have kept failing for 5 minutes: an authority service restarted without its standby, or a replica that refuses it. Every authority operation waits or fails (critical) |
| `AgentCapsuleReceiptKeyMissing` | The authority service has held no usable receipt key of the day for 5 minutes: the API refuses every request that takes an `Idempotency-Key` (503). A day started while a restarted service waited for its standby (critical) |
| `AgentCapsuleNextReceiptKeyMissing` | Tomorrow's receipt key has been missing for an hour: the standby is away, and the next day's key will be created on the primary alone if it does not return by midnight UTC (ADR 006, answer 4(b)) |
| `AgentCapsuleReceiptKeyNotDestroyed` | A daily receipt key has outlived its destruction time for an hour: its destruction waits for the standby, or fails. Backups of its day stay readable meanwhile |

[alerts_test.yml](../deploy/prometheus/alerts_test.yml) holds promtool unit
tests for every alert: each has a case where it fires and one where it stays
silent. A single failed attempt to reach the authorities' replica
stays silent.
Each backup, shipping and standby threshold is tested on both sides.
`scripts/verify-alerts.py` checks that every metric the alerts use is
registered by the code or declared by one of the three textfile scripts. For
the scripts' metrics, it also checks each label and value that the rules and
tests match against the script's vocabulary, so a typo fails. It fails when
a rule lacks a case where it fires or one where it stays silent. With
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

## Diagnostic export

`agentcapsule-admin diagnostics` writes an archive for a support request
(API-02, [ADR 014](adr/014-operations-capacity-diagnostics-audit.md)):

```bash
AGENTCAPSULE_DATABASE_URL=... agentcapsule-admin diagnostics -output /root/diagnostics.tar.gz \
  -worker-config /etc/agentcapsule/worker.json \
  -worker-metrics http://127.0.0.1:9465/metrics -api-metrics http://127.0.0.1:9464/metrics \
  -prometheus http://127.0.0.1:9090
```

Every option but `-output` is optional; what cannot be reached is named in
`manifest.json`. The file is created with mode 0600 and never overwritten.
The archive holds:
- `versions.json`: the binary's Go version and source revision, the kernel;
- `worker-config.json`: the configuration's shape, its numbers, durations,
  digests, `host_id` and `metrics_listen`; every other string, paths
  included, is `redacted`;
- `database.json`: PostgreSQL's version, the migrations applied and expected,
  per host its queue, running VMs, unclean stops, storage reservation and
  pressure, then counts of agents by phase, deliveries by kind and state (dead
  letters included), imports by state and error, failed operations of the last
  7 days by kind and error (boots among them), the audit retention;
- `metrics/*.prom`: the platform's own series (`agentcapsule_*`) only; a label
  value that is not a short word or a route is dropped with its sample;
- `*-authority-replication.json`: the authorities' replication, from the
  worker's or the replica's metrics;
- `alerts.json`: each alert's name, state, start and declared labels, no
  annotation.

It holds no content, token, key, organization, member, agent or request
identifier: the database part is counts only. A test plants secrets, content
and personal data in the database, the configuration, a metrics endpoint and
Prometheus's alerts, and checks that none reaches the archive.

## Not yet covered

- Traces inside the guest, and in the authority service's own process: their
  calls show as spans of the worker and the API. The delivery, wake and boot
  spans ran on KVM in the capacity benchmarks of 2026-11-17 and 2026-11-18
  (112 boots, 92 wakes, 72 deliveries each run, no raw identifier); no test
  checks them there.
- Alert thresholds tuned on a real host. The load test
  ([worker.md](worker.md#load-test)) measures the limits on PostgreSQL, without
  VMs; the [capacity benchmark](worker.md#capacity-benchmark) measured boots,
  memory and CPU with idle VMs three times, on the development machine
  shared with other work, not on a server.
- A SLIM or Directory outage shows only while there is work for it: deliveries
  waiting for SLIM, records waiting for publication. Neither is probed while
  idle.
