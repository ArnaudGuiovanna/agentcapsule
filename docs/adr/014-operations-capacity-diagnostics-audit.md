# Operations: capacity, load, diagnostics, guarded commands, audit retention

Date: November 16, 2026. **Status: built on November 16, 2026, with defaults
pending the product owner** (see [Questions](#questions-for-the-product-owner)).
References: product §3 "Operations and recovery" and §7 "Retention by data
class", TEN-009, EXT-008 and REG-002 ([product.md](../product.md)); OPS-03,
API-02, TEN-06 and REG-02 of the [roadmap](../../ROADMAP.md).

## Context

§3 asks for disk alerts at 70 % and 80 %, imports and new volumes refused past
a pressure threshold, alerts on CPU, memory, queue age, boot failures and
Directory or SLIM outages, and an operator CLI with redacted diagnostics.
TEN-009 asks for an audit of administrative actions; §7 says "audit follows the
legal context". REG-002 asks that the import test pass on GHCR as on a local
registry. What remained: thresholds and load tests (OPS-03), a diagnostic
export and guarded destructive commands (API-02), audit export and retention
(TEN-06), a live GHCR test (REG-02).

## 1. Capacity alerts

| §3 asks | Before | Now |
| --- | --- | --- |
| Disk 70 % and 80 %, data | `AgentCapsuleDiskPressure`, `AgentCapsuleDiskCritical` on the runtime root, which holds the volumes | Unchanged |
| Disk 70 % and 80 %, images | None | `AgentCapsuleImageDiskPressure`, `AgentCapsuleImageDiskCritical` on the registry's cache (`agentcapsule_worker_image_disk_used_ratio`) |
| Imports and new volumes refused | None: only the logical reservation (`configure-host -storage-mib`) | §2; `AgentCapsuleStoragePressure` while refusing |
| CPU, memory | `AgentCapsuleHostCPUSaturated`, `AgentCapsuleHostMemoryLow` (node_exporter), untested | Unchanged rules, now tested |
| Queue age | `AgentCapsuleQueueDelayed` on the worker jobs' delay | Plus `AgentCapsuleInvocationsDelayed` (§3) |
| Boot failures | `AgentCapsuleVMBootFailures`, untested | Unchanged rule, now tested |
| Directory outage | `AgentCapsuleDirectoryUnavailable`, which could not fire (§4) | Fixed, tested |
| SLIM outage | `AgentCapsuleSLIMUnavailable` on deliveries waiting for SLIM | Unchanged |

Every new rule has promtool tests on both sides of its threshold, and raising
a new threshold makes them fail.

## 2. Storage pressure

The worker watches the file system of its volumes (the runtime root) and the
one of its harness images (the registry's cache). Past `storage_pressure`, a
used share from 0.5 to 0.95, **0.80 by default pending the product owner**:
- Each maintenance pass records it in `worker_hosts` (migration 0037).
- The API refuses a new agent on that host and a harness import with `503
  storage_pressure` and `Retry-After`, before any reservation, as the quotas
  do (TEN-007). The API cannot read the host's disks: the worker's record is
  how it learns. A stale record errs on the side of refusing.
- A provisioning already accepted waits before creating its volume (retry
  reason `storage_pressure`); an accepted import waits before downloading,
  and is rejected as `storage_pressure` after its last attempt.

Existing agents keep running and their sparse volumes may grow into the last
fifth. 0.80 is the level of the critical disk alert, so the operator is
warned at 70 % before any refusal.

## 3. Queue age

The load test (§5) found that `agentcapsule_worker_job_oldest_due_seconds`
does not measure how long invocations wait: an agent's deliveries share one
worker job, its head, so thousands of invocations waited while the gauge
stayed under a second. The worker now serves
`agentcapsule_worker_invocations_waiting` and
`agentcapsule_worker_invocation_oldest_waiting_seconds`, the age of the oldest
invocation not yet delivered since its acceptance (or its release, when
scheduled). `AgentCapsuleInvocationsDelayed` fires when it passes **15
minutes, for 5 minutes (default pending the product owner)**: an agent may
legitimately take minutes per invocation, so a shorter wait is not by itself a
fault. Requests between agents keep their own deadlines and dead-delivery
alert; their wait is not served yet.

## 4. Directory outage

The publisher defers a record it cannot publish and returned an error only
when PostgreSQL failed, so `agentcapsule_worker_directory_publish_retries_total`
never counted a Directory outage and `AgentCapsuleDirectoryUnavailable` could
not fire. The publisher now reports each deferred publication. An outage still
shows only while there is something to publish, as a SLIM outage shows only
while deliveries wait for it; neither is probed while idle.

## 5. Load test

`scripts/load-test.py` runs `TestLoad` (`-tags loadtest`) on a private
PostgreSQL, as `verify-postgres.py` does, or on an existing one (`--dsn`). It
sends invocations over HTTP to the real API at each rate in turn; real worker
dispatch passes deliver them to the mock runtime of the PostgreSQL tests (one
SQLite store per agent, a set service time, optional injected failures). It
reports admission latency, the oldest waiting invocation, the jobs' delay, the
backlog, completions, refusals and dead letters, and states the highest rate
sustained. It needs no KVM and no root; [worker.md](../worker.md#load-test) says
how to run it on a real host.

Limits observed on the development machine (WSL2, PostgreSQL 18, fsync on; 8
agents, 20 ms per delivery, 20 s per rate): the API admitted up to 80
invocations per second with a p99 under 130 ms and no refusal. Delivery is the
limit. One dispatch loop, as one worker process runs, sustained 8 per second
and fell behind at 16 (oldest invocation 9 s after 20 s); two loops sustained
10 and fell behind at 20. Each delivery takes several transactions in
sequence; delivering to several agents at once is the lever if real hosts
need more.

## 6. Diagnostic export

`agentcapsule-admin diagnostics -output <file>` writes a tar.gz, mode 0600,
never over an existing file ([observability.md](../observability.md#diagnostic-export)):
versions, the worker's configuration, the migrations, the queues, recent
failures, the platform's metrics, the authorities' replication, the alerts.
What it may contain is decided by allowlists, not by looking for secrets:
- the database part is counts by kind, state and error code, never an
  identifier of an organization, member, agent, request or token;
- the configuration keeps numbers, booleans, durations, digests, `host_id`
  and `metrics_listen`; every other string, paths included (a path may hold a
  person's name), is `redacted`;
- the metrics keep the `agentcapsule_*` series, whose labels take declared
  values; a sample with a label value that is not a short word or a route is
  dropped;
- the alerts keep their name, state, start and declared labels; annotations
  and other labels (`instance`) are dropped.

A test plants tokens, content, an organization's name, a person's name and
address, a provider key, a database password and a private repository in the
database, the configuration, a metrics endpoint and Prometheus's answer, and
checks that none reaches the archive; weakening the filters makes it fail.

## 7. Guarded destructive commands

| Command | `-confirm` repeats | Audited in |
| --- | --- | --- |
| `revoke-credential` | the credential ID | `operator_audit` |
| `abandon-provisioning` | the agent ID | `operator_audit` |
| `set-audit-retention -days N` (new) | N | `operator_audit` |
| `configure-delegation -action rotate` or `revoke-trust` | the issuer | `delegation_audit` (the organization's trail) |
| `configure-delegation -action revoke-token` | the token ID | `delegation_audit` |
| `configure-delegation -action add-key` or `retire-key` | the key ID | `delegation_audit` |

Without `-confirm`, or with another value, a command prints
`confirmation_required` and opens no connection. `-dry-run` checks everything
in a transaction that is rolled back and records nothing. A command that runs
prints its outcome as JSON. `operator_audit` (migration 0037) records who (the
local user ID), when, the action, the target and the outcome: `done`,
`unchanged` or `refused` with its reason. A refusal is recorded in its own
transaction, since the refused change rolls back.
`agentcapsule-admin list-audit` prints it with the operator's other actions
(the platform credential, organizations, trusts). The other admin commands
create or configure and destroy nothing. The worker's `-restore-agent` and
`agentcapsule-authority promote` are not admin commands and are unchanged.

## 8. Audit export and retention

**Export.** `GET /v1/audit/export?from=&to=` gives an organization's auditors
its events of `[from, to)`, at most 366 days and 100,000 events, with the
rights of `GET /v1/audit` (`audit:read`, role owner, admin or auditor), in the
same order, as one JSON document to download. It carries the retention in
force.

**Retention.** **Every audit event is kept until the operator sets a
retention (default pending the product owner).** `set-audit-retention -days N`
sets it for the platform, from 30 to 36,500 days. The worker's dispatch pass
deletes older events of every audit table, tenant, platform and operator
alike, at most every ten minutes and in batches, and records each purge in
`operator_audit`. Shortening the retention deletes events for good, hence
`-confirm` and `-dry-run`, which counts what would go.

## 9. Live GHCR test

`-tags ghcrlive` builds two tests that reach GHCR; without the tag they are
not compiled, so CI and the PostgreSQL campaign stay offline and skip
nothing. `TestLiveGHCRImport` imports the public package that
`AGENTCAPSULE_TEST_GHCR_REFERENCE` names, with the local-registry test's
assertions. The project publishes no harness package on GHCR yet, so it could
not run here. `TestLiveGHCRRejectsAnImageThatIsNotAHarness` passed on
2026-11-16: an anonymous token from GHCR, the manifest of a public image
fetched and checked against its digest, and a rejection as `integrity` before
any layer.

## Questions for the product owner

1. **Storage threshold.** A host's disk reaches 80 %. Should creating agents
   and importing harnesses stop now (a), at 90 % (b), or never, alerting only
   (c)? Existing agents keep running in every case; their volumes grow into
   what is left. Recommended: (a), the default, since a full disk stops every
   agent of the host.
2. **Audit retention.** An organization asks how long its audit trail is
   kept. Options: (a) forever until the operator sets a duration, one
   duration for the whole platform (the default); (b) a fixed duration, for
   example 400 days; (c) a duration per organization, set by its owner within
   bounds the operator sets. Recommended: (a) now, (c) if organizations under
   different laws share a host.
3. **Waiting invocations.** A person's invocation has waited 15 minutes
   because the agent is busy with earlier ones. Should the operator be alerted
   at 15 minutes (the default), sooner, or only when invocations start to
   expire? Recommended: 15 minutes, revised with real hosts' load tests.
4. **Operator actions in an organization's trail.** The operator abandons a
   stuck agent of an organization. Should the organization's auditors see it
   in their trail (a), or only the operator's audit (b, today's behaviour)?
   Recommended: (a), later, with care for what the event says.
5. **Exports.** Should an audit export be itself an audited event, so that an
   organization knows who exported its trail? Recommended: yes, in the next
   iteration; today it is not recorded.
