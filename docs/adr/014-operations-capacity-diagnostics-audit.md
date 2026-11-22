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
| `agentcapsule-worker -collect-garbage` (OPR-5, November 17) | the host ID | `operator_audit` (migration 0045) |

Without `-confirm`, or with another value, a command prints
`confirmation_required` and opens no connection. `-dry-run` checks everything
in a transaction that is rolled back and records nothing. A command that runs
prints its outcome as JSON. `operator_audit` (migration 0037) records who (the
local user ID), when, the action, the target and the outcome: `done`,
`unchanged` or `refused` with its reason. A refusal is recorded in its own
transaction, since the refused change rolls back.
`agentcapsule-admin list-audit` prints it with the operator's other actions
(the platform credential, organizations, trusts, and since §10 harness
imports and the operator's replays of dead letters). The other admin commands
create or configure and destroy nothing. The worker's `-restore-agent` and
`agentcapsule-authority promote` are not admin commands and are unchanged.
The worker's `-collect-garbage` removes files of the host, not rows: it is
recorded once done, `done` if it removed anything, `unchanged` otherwise,
even when it stopped part way. Its `-test-restore` changes nothing and
needs no guard ([worker.md](../worker.md#testing-a-restore)).

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
nothing. `TestLiveGHCRImport` imports the package that
`AGENTCAPSULE_TEST_GHCR_REFERENCE` names, with the local-registry test's
assertions. Both tests passed on 2026-11-19 with a signed private Pi package;
credentials and the trusted publisher key are opt-in environment settings
documented in [registry.md](../registry.md#live-test-on-ghcr). `TestLiveGHCRRejectsAnImageThatIsNotAHarness` passed on
2026-11-16: an anonymous token from GHCR, the manifest of a public image
fetched and checked against its digest, and a rejection as `integrity` before
any layer.

## 10. Refused attempts in the organization's trail

TEN-009 asks for who, when, resource and outcome. An organization's trail
recorded only what happened: a refused attempt left no event, and only the
operator's commands recorded an outcome (§7).

- **What is recorded.** An audited route that refuses a member or a
  technical account of an organization adds an event with outcome `refused`
  to that organization's trail. An audited route is one whose action writes
  an event of the trail (`auditedRoutes` in `internal/api`; a test keeps the
  list in step with the routes). The event holds the actor, the time, the
  action the route would have recorded (`member.created`,
  `assignment.revoked`, …), the target and reference its path named, and
  the refusal's code as its reason (`forbidden`, `not_found`,
  `invalid_json`, `idempotency_key_required`, …). A refusal is one of
  authorization (403, and 404 for what the caller may not see) or of
  validation (400, 409, 413, 415, 422).
- **What is not.** The request's body, its headers, a token. A path value
  is kept only if it has the form of a platform identifier (a prefix and 128
  random bits); otherwise (an alias's name, a malformed guess) the target
  is the organization and the reference is dropped, so that a path cannot
  carry text of the caller's choosing into the trail. Reads, invocations
  and messages are not administrative actions: their refusals leave no
  event. An unauthenticated request (401) names no organization, a method
  the route does not serve (405) is no attempt of its action, and capacity
  (429) and availability (5xx) refuse no one in particular: none is
  recorded. A member's attempt at a platform route (create an organization,
  import a harness) is recorded in the member's organization.
- **When.** After the answer, in its own transaction (migration 0043,
  `tenant_refusal_audit`): the refused change rolled back. A record that
  fails does not change the answer; the API then logs
  `audit_refusal_unrecorded`.
- **The feeds.** Every event of `GET /v1/audit` and of its export carries
  `outcome` (`done` or `refused`) and, for a refusal, `reason`. The replays
  of dead letters (`instruction_replays`, ADR 017) join the trail of their
  agent's organization as `invocation.replayed`, by its administrator or by
  `operator`, with the invocation as reference. `agentcapsule-admin
  list-audit` adds the platform's harness imports and deprecations
  (`harness.import.requested`, `harness.release.deprecated`, from
  `harness_audit`) and the operator's own replays.
- **Retention.** §8 covers `tenant_refusal_audit` like every audit table.
- **Not done.** Nothing bounds how fast one member fills the trail with
  refused attempts, other than the API's own capacity (question 7).

Tests: `TestRefusedAdministrativeAttemptsJoinTheTrail` and
`TestEveryAuditedRouteIsServed` (`internal/api`);
`TestReplaysAndHarnessImportsJoinTheAuditFeeds` and
`TestAuditTrailHoldsNoConversationContent`, which plants text in
invocations, messages, results, a request and its reply between two agents
and a refused attempt, and finds none of it in the trail, its export or the
operator's feed (`internal/controlplane`).

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
6. **What a refused attempt names** (§10). A member of an organization
   tries to assign an agent by an identifier that names nothing in the
   organization, perhaps an agent of another one. Should the trail keep the
   identifier the member sent (a, the default), or name only the
   organization when the identifier is not one of its own (b)? Recommended:
   (a). It is the member's own input, it shows the auditors what was tried,
   and it reveals nothing of another organization: the answer was 404
   either way.
7. **Many refusals** (§10). A misconfigured client is refused a thousand
   times an hour. Should each refusal be an event (a, the default), or one
   event per actor, action and reason each minute, with a count (b)?
   Recommended: (a) now, (b) if trails grow too fast.

## Changes after the v0.1.0 audit

**PERF-1 (S-02, S-03, P-02, P-09, A-04, S-20, L-15, P-12).** §5 measured
one dispatch loop that ran its jobs one after the other, every delivery under
the host's exclusive admission turn and boots and volume copies under the
host registry's lock. Delivering to several agents at once is now built: each
agent has its own admission queue, a delivery holds its recipient's turn only,
and a pass runs up to `dispatch_concurrency` jobs at once (4 by default, 1 to
64), each agent's own jobs in claim order. A boot, a stop, a volume copy or
install holds its agent's lock; `host.lock` guards only short registry
changes, the host-wide capacity count among them. The registry is kept in
memory and written only when it changes, the host keeps its control
connections to each guest open, and one monitor per host replaces a ticker per
VM. The figures of §5 predate this and were not measured again; the load test
still runs one job at a time per loop. The VMM's log is bounded and removed
with its run, and the guest has no serial console in production (S-20).
Details: [worker.md](../worker.md), [ADR 017](017-capacity-queue-and-dead-letter-replay.md#changes-after-the-v010-audit).

**PERF-3A (P-01, P-04).** §5 also found that one loop waited its interval
after every pass. The loop now passes again at once after a full batch, and
PostgreSQL wakes it when new work arrives for its host (`agentcapsule_work`,
the host's ID as the only payload); the shipped `poll_interval` is 5 s, a
fallback that bounds what a lost notification costs. The queries that find
work read partial indexes of the open rows and `agent_activity`, each agent's
last activity kept by triggers, instead of the tables' history (migration
0071); on a seeded schema of 100,000 finished invocations their slowest
statement went from up to 1.2 s to under 5 ms (evidence
`quint/results/audit/audit-perf-3a/explain-*`). Finished invocations, wakes,
sleeps and requests are deleted `finished_retention` after their end (90 days
by default) when nothing needs them; an event of the audit trail that names
one keeps it until §8's retention removes the event, so the audit's retention
still decides alone how long the trail lasts. Settled and released model
calls are deleted `model_call_retention` after their reservation (90 days by
default, PERF-3B), under the same rule: one an audit event names stays.

**Lot SEC-1A (findings S-07, S-09, L-04).**

*Request limits (S-07).* An authenticated request costs about twenty SQL
round trips before its handler's work, and a refused audited one a third
transaction: one noisy caller could starve the others, and nothing but the
API's capacity bounded it. Each API process now keeps token buckets in
memory ([api/README.md](../api/README.md), request limits):
- per principal, 200 requests at once then 20 a second; per organization,
  all its principals together, 1,000 then 100 a second. Past either, `429
  rate_limited` or `429 organization_rate_limited` with `Retry-After`.
  Several principals are needed to spend an organization's bucket;
- per source address (an IPv4 address, an IPv6 /64), 60 failed
  authentications a minute. Past them, an unknown credential from that
  source is refused before its lookup (`429 authentication_rate_limited`);
  a credential that authenticated in the last 15 minutes still passes, so
  an attack from a shared address does not lock out its known callers.
- The limits run before the database work as far as authentication allows.
  What is known before the lookup is the credential and the source: a
  credential that authenticated recently is known by its keyed fingerprint,
  with its principal and organization, and is charged to their buckets
  before any SQL. A credential's first request is charged after its
  lookup, before its handler's work. Knowing a credential never admits a
  request: the database authenticates every request the limits let through,
  so revocation stays fail-closed (ADR 001, ADR 002).
- A rate of 0 turns its limit off. N API processes behind a load balancer
  admit up to N times each rate; behind a proxy the source is the proxy's,
  where the failure limit is turned off and the proxy limits.
- `agentcapsule_api_limited_requests_total{limit}` counts every refusal of a
  limit, by limit; `authentication_failed` events name the source by a
  pseudonym ([observability.md](../observability.md#events), L-19).

*Uploads (S-09).* An upload read its 8 MiB body into memory after
authentication alone, with no bound on uploads at once. The API now checks
an upload's headers, its rights (scope, `invoke` assignment, live agent) and,
unless its key replays a stored answer, the room under the organization's
`max_attachment_bytes` for its declared `Content-Length`, before it reads the
body; the upload checks everything again when it stores the file. It reads
at most 16 bodies at once in the process (`-max-uploads`, `503
upload_capacity`) and 2 per principal (`-max-principal-uploads`, `429
too_many_uploads`). The API's memory bound itself is the unit's (SEC-4).

*Refused attempts (L-04; §10, question 7).* Question 7 is answered (b),
with one refinement. A window opens at an actor's refused attempt at an
action, for one reason, and lasts a minute. In it, the first attempt at each
target is an event in full, up to ten targets; every other attempt is
counted, and at the window's end one event records their number
(`attempts`), with the actor, the action, the reason and the organization as
target. Each refusal carries `attempts`, 1 for an event in full (migration
0074). The refinement keeps §10's isolation: an attempt at another
organization's agent stays recorded exactly as one at an unknown agent (each
is the first at its target), and whether an attempt is recorded in full or
counted depends only on the actor's own earlier attempts. Per actor, action
and reason, a minute adds at most eleven events. The windows live in the
API process's memory: a process that stops abruptly loses the counts of its
open windows; one that stops normally records them first. §10's "Not done"
item is done.

Tests: `TestRequestBucketsAdmitABurstThenTheirRate`,
`TestFailedAuthenticationsLimitTheirSourceBeforeTheDatabase`,
`TestUploadSlotsBoundTheProcessAndEachPrincipal`,
`TestRefusalWindowsCountRepeatedAttempts` (unit);
`TestRequestLimitsRefuseBeforeTheDatabase`,
`TestUploadRightsAndRoomAreCheckedBeforeTheBody`,
`TestRepeatedRefusalsAreCountedInTheTrail`,
`TestRefusalAttemptsMigrationKeepsExistingRefusals`,
`TestASlowDownloadOutlivesTheServerWriteTimeout` (PG; the last one for L-05:
a download now moves its write deadline, as an upload does).

**Lot SEC-1B (finding L-03): an append-only trail, and a feed that skips no late commit.**

Until v0.1.0 nothing kept the 17 audit tables (`auditTables`) from being
changed or deleted by the roles that write them, and the feed
(`GET /v1/audit`) paged on `(created_at, id)` with `created_at` taken at the
insert: a page read while an audited transaction was still open moved its
cursor past later events, and that transaction's event, stamped earlier,
then committed behind the cursor and was never read.

Now (migration `append-only-audit`):

1. **Append-only.** A trigger on each audit table refuses every `UPDATE`,
   every `TRUNCATE`, and every `DELETE` but the retention purge's: an event
   older than the retention in force (§8). The purge (`PurgeAudit`, as the
   worker) deletes as before. Only the schema's owner, which
   `set-audit-retention` runs as, sets the retention: the worker, which reads
   it under a row lock to purge, cannot shorten it. The trigger takes the
   columns that may change as arguments; there are none today: the counted
   refusals (L-04, above) are new rows, never a change of one.
2. **A commit-safe feed.** Each event of the feed's tables is stamped once
   its transaction holds its organization's feed lock, an advisory lock in
   shared mode kept until its commit. A page first takes the time, then the
   lock's holders, waits for those to end, and returns only events stamped
   before that time: each of those has then committed or rolled back, and a
   later event is stamped after it. Writers never wait for each other or for
   a reader, and a reader waits only for that organization's audited
   transactions open when it asked. Order and cursor are unchanged: a cursor
   given before the update goes on.
3. A page waits at most five seconds; past that, an audited transaction of
   the organization is still open, and the answer is 503
   `temporarily_unavailable` with `Retry-After: 1`. Nothing is lost: the next
   page has the event. This assumes the database server's clock does not
   step back, as the order on `created_at` always did.

The export (`GET /v1/audit/export`) reads a closed range at one snapshot, as
before: an event that commits later is in a later export of the same range.

**Lot FIX-2: the feed lock of one schema, and rights before the wait.**

- The feed lock's key named the organization only. Several schemas of one
  database (the tests do this; so would two installations sharing a
  server) shared it: a page waited for another schema's audited
  transactions of an organization with the same ID, then answered 503. The
  key now names the schema with the organization, as the store's gate
  does: the table's schema in the trigger, the store's schema in the
  reader. Migration `append-only-audit` was corrected in place, since no
  release has shipped it.
- A page waited for the horizon before it checked the caller's rights, so
  a caller without audit rights could hold an API connection for five
  seconds. It now checks them first, without a row lock; the wait still
  holds no row lock, and the rights are checked again under the
  organization's row lock before the page is read.
