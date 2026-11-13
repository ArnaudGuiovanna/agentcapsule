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

Both endpoints are on loopback only. Run Prometheus or a collector on the same
host ([deploy/prometheus/prometheus.yml](../deploy/prometheus/prometheus.yml)).

| Process | Setting | Example |
| --- | --- | --- |
| API | `agentcapsule-api -metrics-listen <addr>` | `127.0.0.1:9464` |
| Worker | `"metrics_listen"` in its configuration ([worker.md](worker.md)) | `127.0.0.1:9465` |

A non-loopback address is refused at start (`metrics_listen_must_be_loopback`).

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
| `agentcapsule_telemetry_collect_errors_total` | counter | — | Scrapes whose current values could not be read |
| `agentcapsule_telemetry_series_dropped_total` | counter | — | Samples dropped at a metric's series limit (512) |

The worker reads its gauges at each scrape, from PostgreSQL and the host, with
a 5-second bound.

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

**Correlation.** Every API response carries `X-Request-ID`, a random 128-bit
value. The request's `http_request` event carries the same value, so a
person's report ("my call failed, request ID …") leads to its log line. The ID
says nothing about the person or the content.

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

[alerts_test.yml](../deploy/prometheus/alerts_test.yml) holds promtool unit
tests for the disk, queue, scrape and SLIM alerts.
`scripts/verify-alerts.py` checks that every metric the alerts use is
registered by the code. With `--promtool` or `--promtool-image <image@sha256:…>`,
it also runs `promtool check rules` and `promtool test rules`. CI runs it with
Prometheus v3.5.0, pinned by digest. A raised disk threshold makes the tests
fail.

## Not yet covered

- Traces. Request IDs do not yet follow work from the API into the worker's
  jobs.
- An operator command for diagnostics (API-02).
- Alert thresholds tuned under load (OPS-03).
