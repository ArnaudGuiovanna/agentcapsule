# Maintenance and delivery worker

`cmd/agentcapsule-worker` reconciles placements, renews boot certificates and
resumes interrupted replacements, without any incoming request. It also
discovers the deliveries, closures, expirations and deletions to process in
PostgreSQL. With `authority` and `provisioning` configured, it also resumes
creation reservations. The API path with two owners and two VMs, including
provisioning and encrypted wake, is exercised by
`scripts/verify-product-guest.py`. The worker also restores an agent from an
archive, on its own host ([Restoring an agent](#restoring-an-agent)).

Build with the repository's Go version, CGO and the libcryptsetup headers,
and allow the worker's link flag `-l:libcryptsetup.so.12`, which Go refuses
otherwise:

```sh
go env -w CGO_LDFLAGS_ALLOW='-l:libcryptsetup\.so\.12'
go build -trimpath -o bin/agentcapsule-worker ./cmd/agentcapsule-worker
```

Adapt [config.example.json](../runtime/worker/config.example.json) with the
verified paths and digests. `firecracker` must be the variant that keeps the
volume lock. The initrd must provide the trusted harness and the authenticated
protocol; the disposable SQL harness of the test campaigns remains a test tool.
The configuration file must be owned by root, be a regular file and not be
writable by group or others. Boot keys are not parameters of this file.

The process requires root for the jailer, namespaces and cgroups; the VMMs use
their dedicated UIDs. Provide `AGENTCAPSULE_DATABASE_URL` through the service
manager's protected environment, then run:

```sh
/opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json
```

At every start the worker checks KVM, the kernel, cgroups, namespaces, the
runtime root's file system and its free space (a failure from 95% used), and
the pinned artifacts, and does not start when one fails, printing what to fix
(RUN-012, DEP-3). `-preflight` runs every check of the
host and of this configuration, changes nothing, and exits
([install.md](install.md#preflight)). In production, the worker reaches
PostgreSQL over a Unix socket or with `sslmode=verify-full`, refuses a `local`
registry rule and does not call a model provider on plain HTTP
([ADR 010](adr/010-transport-security-and-preflight.md)). In both modes it
calls a provider at an internal address only if `allowed_internal_providers`,
in its `llm` section, allows it ([install.md](install.md#model-providers-on-internal-addresses)).

The schema must be migrated. `-migrate` explicitly applies the migration before
starting; a normal launch does not modify the schema. The `host_id`, the
registry, the images and the capacity must be consistent across all workers of
the same host. Stop older versions before migrating.

For encrypted guests, the worker needs the key authority and the restore
authority. Both belong to the **authority service**, `agentcapsule-authority
serve` ([ADR 006](adr/006-authority-service.md)): one process per host, run
under its own account `agentcapsule-authority`, owns both directories, and
the worker reaches them through its local socket. The worker never opens
their directories. [recovery.md](recovery.md#install-the-authority-service)
installs the service, initializes both authorities and moves an existing
install to it. Then give the worker the service's socket and the two
identities it must hold, and, for local provisioning, a UID/GID range
reserved exclusively for this host registry:

```json
{
  "authority": {
    "socket": "/run/agentcapsule-authority/worker.sock",
    "restore_authority_id": "<PUBLIC_IDENTITY_OF_THE_INDEPENDENT_CATALOG>",
    "key_authority_id": "<PUBLIC_IDENTITY_RETURNED_BY_INITIALIZATION>"
  },
  "provisioning": { "first_uid": 62000, "last_uid": 62999 }
}
```

- The socket admits root only, and the service checks the peer's account on
  each connection.
- The worker pins both identities. It refuses a service that holds other
  authorities (`authority_identity_mismatch`). It checks that its runtime
  root, and its archive root, lie outside both authorities' directories,
  which the service gives (`authority_domain_overlap`).
- A worker that starts before the service answers waits for it, and logs
  `authority_service_waiting` once. Order its unit after the service with
  [agentcapsule-authority-client.conf](../deploy/systemd/agentcapsule-authority-client.conf)
  (`Wants=` and `After=`, never `Requires=`).
- A configuration that still names `key_authority`, `restore_authority` or
  `authority_replica` is refused (`authority_service_required`): those
  sections moved to the service's configuration. No worker may write behind
  the service.
- Without the `authority` section, the worker runs a laboratory host without
  authorities: preprovisioned volumes, no provisioning, no archives.

**When the service restarts** (an upgrade, a crash), the worker's authority
operations fail as outages for a few seconds, and are retried: no agent boots,
platform calls fail with an error the guest can retry, deliveries wait.
Running VMs stay: adoption treats an outage as an outage, never as a stale
binding. After a restart, the service makes restoring or deleting an agent
wait up to `max_key_hold` (2 minutes), and closing a request up to 30 seconds
([ADR 006 §3](adr/006-authority-service.md#the-hold)). **When the worker
restarts**, the service keeps its view of the standby: degraded mode goes on,
and the restarted worker does not wait for the standby.

The authorities refuse an absent directory or one with a different identity;
nothing initializes them at startup. Running `init-restore-authority` again on
an existing catalog keeps its identity and upgrades its schema, with the
service stopped. Version 2 adds the losses that a restore declares
([ADR 003](adr/003-restore-rpo.md)). Before the upgrade, the worker keeps
running; only the loss operations are refused. Version 3 adds the log of the
[replica](#the-authority-service); a version 2 catalogue keeps working
standalone. The UIDs of removed agents stay reserved. This first harness
source accepts the approved local image whose digest is exactly
`sha256:<initrd.sha256>`; OCI import and assembly remain to be built.

New installations register each volume with an initial incarnation of 1. The
worker checks this incarnation before key delivery, confirmation and adoption;
the guest verifies its persistent marker. An old guest or catalog without this
identity must not be relabeled at startup. Only a restore moves a volume to a
new incarnation, one step up; the guest then moves its marker on the restricted
boot of the restored image.

**Adoption.** The worker adopts a running VM again before each use of it: a
delivery, a platform call, a stop, its reuse for new work. Adoption checks the
VM's placement in PostgreSQL and its volume's incarnation while the authority
service holds the binding (`hold_binding`). A stale or sealed binding, or an
obsolete placement, retires the VM there, and the use is refused. An outage
keeps the VM and fails the use, which is retried. The host's other VMs are
checked at its next census: each maintenance pass starts with one, and so
does each boot, archive, sleep, wake and resume. A delivery to a running agent
thus holds its recipient's binding a fixed number of times, whatever the
number of VMs on the host.

Creation goes through the durable LUKS2 container, an immutable host
registration (inode, size and resources), then a restricted boot. The worker
delivers the key over the authenticated channel after checking the SQL lease and
the physical lock held by the VMM. After initialization and catch-up of
revocations, it removes the restricted boot and activates the agent in a
transaction that re-reads the current catalog. A lost response leaves these
steps replayable. The `provision` job uses the same tickets and backoffs as the
other jobs, without monopolizing the head of the queue on error. The API's
wake/sleep commands also go through this queue: only the first open command of
each agent is discovered. The worker re-reads its status after host admission
and does not re-run a finished command. The success of wake follows the durable
publication of the boot; that of sleep follows the physical removal. A deletion
cancels the open commands.
For sleep, the worker keeps the authenticated client of the current boot before
committing `STOPPING`, then requests quiescence under exclusive host admission.
It then removes the VMM and verifies its absence before publishing `STOPPED`.
Only a clean acknowledgment allows `unclean_stop=false`; a lost response, an
error or an exceeded timeout lead to a forced removal reported as unclean. A
recovery after a crash may conservatively classify the stop as unclean. The
forced recovery paths remain available. This wiring is tested in SQL/mTLS and in
the product path on KVM.

The loop performs one pass immediately, then waits `poll_interval` after each
pass. Each attempt has its own `attempt_timeout`; a failure keeps the SQL job
and the other jobs in the list are still attempted. The logs are JSON events
from a closed vocabulary (`maintenance_started`, `maintenance_complete`,
`maintenance_retry` with its reason, …), with no DSN, raw SQL error,
certificate or user content. With `"metrics_listen": "127.0.0.1:9465"`, the
worker serves Prometheus metrics at `/metrics` on that loopback address; see
[observability.md](observability.md). With
`"trace_file": "/var/log/agentcapsule/worker-traces.jsonl"`, it appends its
spans to that file ([traces](observability.md#traces)). `SIGTERM` and `SIGINT`
stop the loop and release its listeners; confirmed VMMs remain adoptable.

A replacement request is committed with `STOPPING`. It stays present after the
SQL confirmation of the new VMM: the durable `RUNNING` publication in the host
registry must precede its acknowledgment. An explicit stop or a deletion cancels
this request in the corresponding transaction. A delayed worker must re-verify
the request under SQL lock before claiming a boot.

A full capacity defers the replacement without evicting another guest. Its
progress therefore assumes that a slot becomes available again. Maintenance does
not automatically wake `fence_only` boots; the barrier manifests carry this
need. It boots again a guest stopped while it held work in progress (below);
the general desire to run remains to be built. The pass interval is not
an availability bound: outages, contention, clock drift and the number of jobs
influence the effective time.

After the renewals, a pass discovers business intents and processes at most
`dispatch_batch` jobs. `worker_hosts` assigns tickets in the same transaction as
the mutations of `worker_jobs`. A claim moves the job to the end of the queue
before its execution; a crash or an error therefore does not reserve the first
place indefinitely. The `work_lease` lease and the exponential backoff
`retry_base` to `retry_max` use the SQL clock. Acknowledgment and resumption
refuse an expired or replaced lease. This coordination lease replaces neither
the delivery lease nor the barriers that neutralize delayed effects.

The dispatcher prepares the recipient under exclusive admission before
consuming a delivery attempt: wake, capacity, certificates and channel health.
The control callback must finish its
local SQL transaction without waiting for a platform call.

**Work that waits for capacity** ([ADR 017](adr/017-capacity-queue-and-dead-letter-replay.md)).
A delivery, a wake or a resume that needs a VM for a stopped agent takes a
free slot, or stops a VM that is not computing: an idle one first, then one
that only waits (for its next delivery, a wake, or another agent's answer),
the least recently active first. It never stops a VM that is computing: an
invocation acknowledged "working" or a request being processed, unless the
agent waits for another agent's answer, or a model call in flight. When no
slot can be had, the agent waits in its host's capacity queue and shows
`QUEUED`. It spends no delivery attempt (retry reason `capacity`). An agent
boots only when every older waiter of its host can boot too, whatever their
organization: new work never overtakes older work that waits. Each pass
offers a freed slot to the oldest waiter at once. Work that waits past its
deadline dies without its agent; an instruction then fails with
`capacity_unavailable`. A barrier is not queued: it may stop any VM, a
computing one last. The operator sees `agentcapsule_worker_agents_queued`,
`agentcapsule_worker_capacity_oldest_wait_seconds` and the alert
`AgentCapsuleWorkWaitingForCapacity`.

**Work past its organization's quotas** ([ADR 021](adr/021-organization-quotas.md)).
The operator may bound an organization's VMs running at once, and their
vCPUs and RAM, on every host. A boot for work past them is refused in the
transaction that reserves it, and the agent waits in the same queue, with
the reason `organization_quota` (retry reason `organization_quota`). Such a
waiter holds no slot against other organizations' work; within its
organization, newer work waits behind older. The organization's oldest
waiter on the host may stop the organization's own VMs there that are not
computing, by the rule above, which frees host slots too; VMs on other hosts
are not stopped for it. A barrier's boot is neither counted nor refused. A
credential renewal the quota refuses waits for the next pass. These waits are
not in `agentcapsule_worker_agents_queued`, its oldest wait or its alert:
`agentcapsule_worker_agents_waiting_for_quota` counts them.

**Interrupted work resumes.** An agent whose VM stopped while it held work in
progress (a barrier stopped it, or it crashed) gets a `resume` job: the worker
boots it again, through the capacity queue, and its harness takes the work up
from its SQLite intents. It is not resumed once that work ended or passed its
deadline, when it is `FAILED`, or when someone asked it to sleep after the work
began (default pending the product owner). A crash spends its restart budget,
so a guest that keeps crashing is not booted again and again. The guest's outgoing
tasks are asynchronous. The host registry v2 uses a common queue for shared and
exclusive calls; only consecutive readers at the head coexist. Migration from v1
keeps the barriers present; stop the old workers before upgrading, as they
cannot read v2.

This first coordination assumes that all manifest stores are on the same host.
It does not prove a real delay or the success of each request: an expiration or
a final failure is possible, and a notification can also exhaust its attempts.

**What follows a dead delivery** ([ADR 007](adr/007-delivery-closure-and-priority.md)).
A reply, status or instruction dies when its three attempts are spent or its
deadline (7 days for a reply or status, the TTL for an instruction) passes. A
delivery past its deadline, or out of attempts, to a live agent is retired
without preparing that agent. Retiring it fences the agent's store only if an
attempt may have reached it. One that no attempt reached dies at once, without
the agent, even behind other deliveries in its mailbox: it never reached the
agent, so it leaves the queue out of order. One to an agent being deleted, or a
reply whose author is being deleted, is canceled by the deletion instead; the
retirement checks this under the agents' locks. For an agent that never boots,
what still waits is:
- a delivery an attempt may have reached: it waits, closing, for the agent to
  boot for its fence (a restricted boot that accepts barriers only), since a
  delayed send could otherwise apply it after its death;
- a request to or from that agent: its closure at its deadline fences the
  request's two parties, so it stays `DELIVERING` or `PROCESSING` until the
  agent boots for that barrier. A closure fences no other agent (ADR 007 §7);
- the delivery of such a request to that agent, which heads its mailbox until
  then: the deliveries behind it wait, except those that die out of order as
  above.

`AgentCapsuleJobsFailing` and `AgentCapsuleVMBootFailures` tell the operator.
When a delivery dies:
- the request keeps its state: a replied request stays `REPLIED`;
- the reply stays readable by the sender's agent for 7 days from the death,
  through the request's status read on the platform channel, then is purged;
- an instruction fails (`delivery_failed`, `capacity_unavailable` when its
  deadline passed while its agent waited for a VM slot, or
  `delivery_outcome_unknown` when an attempt may have reached the agent), and
  its requester sees it as a dead letter. An administrator of its organization
  or the operator may replay it (below);
- the operator is told: `agentcapsule_worker_deliveries_dead_total`, the event
  `delivery_dead` and, for a reply or status, the alert
  `AgentCapsuleDeliveryDead` ([observability.md](observability.md)).

A barrier's eviction can interrupt the guest's computation; the SQLite intent
survives and the resume job boots the agent again, but a sufficient residence
time is not guaranteed. The
FIFO model checks a three-client component, under weak fairness and callback
termination, not the refinement of the Go service.

To deliver owner instructions and keep their encrypted results, add to the
worker configuration file:

```json
"transit": {
  "active_key": "v1",
  "keys": {"v1": "/private/path/transit-v1.key"}
}
```

These private 32-byte files must match the keys explicitly activated with
`agentcapsule-admin activate-transit-keys` and provided to the API. The worker
refuses an unknown or replaced key or a stale active identifier; its startup
activates no key. During a rotation, also provide all the keys needed for the
contents still retained. Each pass purges at most
`min(dispatch_batch * 4, 1000)` expired contents.

The instruction shares the events FIFO. Boot preparation precedes the
consumption of an attempt; the first authorized send creates a stable mandate.
The encrypted result, the success of the operation and the removal of the queue
head are committed together. An old attempt can no longer publish its result.
Abandoning waits for a durable barrier, revokes the mandate and keeps the
uncertainty about an effect whose result was never acknowledged.

To publish the organizations' agents to the private Directory and answer the
agents' searches (INT-02, [deploy/interop](../deploy/interop)), add:

```json
"directory": {
  "address": "127.0.0.1:8443",
  "ca": "/etc/agentcapsule/interop/control-plane/directory-ca.pem",
  "cert": "/etc/agentcapsule/interop/control-plane/directory.crt",
  "key": "/etc/agentcapsule/interop/control-plane/directory.key",
  "publish_interval": "5s"
}
```

The address is the Directory's mutual-TLS edge; the key must be private to the
worker. The worker then runs the publisher (one claim of up to 16 agents per
interval, at once again while work remains, leases of one minute, backoff from 5
seconds to 5 minutes while the Directory is unreachable) and serves
`/v1/directory/find` on the platform channel. Without this section, searches
answer `unavailable` and nothing is published; descriptions are still kept.
See [Directory publication](api/agents-assignments.md#directory-publication-int-02).

To carry deliveries between agents over SLIM (INT-04), run the SLIM bridge
([runtime/slimbridge](../runtime/slimbridge), see
[docs/interop.md](interop.md#the-slim-bridge-int-04)) under its own user, with
the units of [deploy/systemd](../deploy/systemd)
([Running on a host](interop.md#running-on-a-host)), and add:

```json
"slim": {
  "bridge_socket": "/run/agentcapsule-slim/bridge.sock",
  "worker_socket": "/run/agentcapsule-worker/slim.sock",
  "bridge_uid": 990
}
```

`bridge_uid` is the bridge's user (`id -u agentcapsule-slim`). The two
directories come from `agentcapsule-slim.tmpfiles`. The worker's directory
belongs to root, so the bridge can reach the worker's socket but cannot remove
or replace it.

The worker creates `worker_socket` for the bridge's user (mode 0600) and checks
the peer's user on every connection, in both directions; `bridge_uid` cannot be
root. Requests, replies and status events between agents then cross the bridge
and the SLIM node before reaching the recipient's VM over vsock; owner
instructions do not. Once the recipient's VM is ready and before an attempt is
spent, the worker asks the bridge to answer on the recipient's SLIM name: while
the bridge or the node is away, deliveries wait with backoff and spend no
attempt. Without this section, deliveries go straight to the VM.

Harness calls now transmit structured private contents (`payload.content`)
rather than references chosen by the client. When transit is configured, the
worker itself encrypts the request/response before the commit and refuses
references supplied by the client. Delivery decryption requires the current
lease, the dispatch authorization and the parties that are still active. The
outgoing channel is used in the background by the harness, after the commit of
the SQLite intent: no platform call blocks the callback that must first return
its delivery acknowledgment.

## Replaying a dead letter

An instruction that died without reaching its agent can be put back in its
agent's queue ([ADR 017](adr/017-capacity-queue-and-dead-letter-replay.md)):

```sh
agentcapsule-admin replay-dead-letter -operation-id <invocation> -key <key> [-ttl 1h]
```

It keeps its identifier and its event ID, so the agent can deduplicate it,
gets a new attempt budget and goes to the end of the agent's queue. It keeps
its deadline unless `-ttl` gives a new window from now (1 s to 24 h); past its
deadline, `-ttl` is required. It counts in its organization's queue limits.
The command prints the replay as JSON; the same key prints the first replay
again and changes nothing. It refuses, and changes nothing, when an attempt
may have reached the agent (`outcome_unknown`: the agent's store fenced the
event), when the requester can no longer invoke the agent
(`requester_revoked`), when the content or a file is purged (`input_purged`,
`attachments_purged`), past the deadline without `-ttl` (`expired`), when the
agent is being deleted, and for anything but a dead letter. Each replay is
recorded in `instruction_replays`. An organization's owners and administrators
have the same replay through the API
([agents-assignments.md](api/agents-assignments.md#queues-deadlines-and-dead-letters-evt-02)).

## Storage pressure

The worker watches two file systems ([ADR 014](adr/014-operations-capacity-diagnostics-audit.md)):
the one of `root`, which holds the volumes, and the one of the harness images,
the registry's `cache` (`<root>/releases` by default). Past
`"storage_pressure"` (a used share from 0.5 to 0.95, 0.80 by default):
- each maintenance pass records it in PostgreSQL (`worker_hosts`);
- the API then refuses a new agent on this host (its volume) or a harness
  import (its image) with `503 storage_pressure`, before reserving anything;
- a provisioning already accepted waits before creating its volume (retry
  reason `storage_pressure`); an import waits before downloading, and its
  last attempt rejects it as `storage_pressure`.

Agents that exist keep running: their sparse volumes may still grow into the
remaining space. A file system that cannot be read counts as past the
threshold. The disk alerts fire earlier, at 70 % and 80 %
([observability.md](observability.md)).

## Load test

`scripts/load-test.py` drives the API and the worker against PostgreSQL
(OPS-03). It sends invocations over HTTP to the real API at each rate in turn,
and real dispatch passes deliver them to the mock runtime of the PostgreSQL
tests: one SQLite store per agent, written by each delivery after
`--service` (20 ms by default). No KVM and no root are needed. It reports,
per rate, the admission latency, the age of the oldest waiting invocation,
the delay of the worker's jobs, the backlog at the end of the step, the
completions and the refusals, then the dead letters, and states the highest
rate sustained: no refusal, no server error, and a queue that does not keep
growing.

```bash
python3 scripts/load-test.py \
  --pg-bin ~/.local/share/agentcapsule-tools/postgres/usr/lib/postgresql/18/bin \
  --library-path ~/.local/share/agentcapsule-tools/postgres/usr/lib/x86_64-linux-gnu \
  --native-tools ~/.local/share/agentcapsule-tools/guest-build \
  --rates 5,10,20,40 --step 30s --agents 8 --workers 1 \
  --output quint/results/load-<name>
```

`--workers` is the number of dispatch loops: one worker process runs one.
`--fail-every N` fails one delivery in N, to produce dead letters.

On 2026-11-16, on the development machine (WSL2, PostgreSQL 18 with fsync on),
with 8 agents and 20 ms per delivery, the API admitted every rate up to
80 per second with a p99 below 130 ms, without a refusal. Delivery was the
limit. One dispatch loop, as one worker process runs, sustained 8
invocations per second and fell behind at 16: the oldest waiting invocation
reached 9 seconds after 20 seconds. Two loops sustained 10 and fell behind at
20 (4 seconds), then 27 seconds at 80 per second. Each delivery takes several
transactions in sequence (claim, authorization, acknowledgment, the job's
completion), whatever the agents' own speed. The queue limits (100 waiting
per agent, 1,000 per organization) refuse beyond that with `429 queue_full`.

**On a real host.** Run the same script on the host, or on a machine like
it, with the host's PostgreSQL version. To use an existing server instead
of a private one, give `--dsn` a role allowed to create a schema in a
throwaway database: the test creates its own schema and drops it at the end.
Compare the limit with the expected peak rate of invocations, and set the
`AgentCapsuleInvocationsDelayed` and queue limits from it. The load test does
not boot VMs: boots, their memory and their CPU are measured by the capacity
benchmark.

## Capacity benchmark

`TestCapacityBenchmark` (DEP-5, OPS-03) measures the host's starting points
with real VMs. It needs KVM and root, like the product campaign that runs it.
For each number of agents (1, 5, 10 and 20 by default), it creates the agents
it lacks, puts every agent to sleep, then:
1. wakes that many agents at once; one worker boots them in turn;
2. sends each a first invocation, all at once, and waits for every answer;
3. leaves the VMs idle for 5 seconds and reads the host;
4. puts them to sleep, then sends each an invocation in turn: each wakes from
   `STOPPED` to answer.

It measures, per step:

| Field | Meaning |
| --- | --- |
| `boot_seconds` | Each VM's boot, from the worker's `worker.boot` spans |
| `wake_to_running_seconds`, `all_running_seconds` | Each wake request until its operation succeeded, all sent at once; and until the last |
| `vmm_rss_mib`, `vm_cgroup_memory_mib` | Each VMM's resident memory (`VmRSS`), and its cgroup's charge |
| `host_used_by_vms_mib` | The host's available memory with every agent asleep, minus the same with the step's VMs idle |
| `host_cpu_busy_ratio_idle`, `vmm_cpu_seconds_per_second_idle` | The host's busy share of all CPUs, and the VMMs' CPU time per second, while idle |
| `first_answer_seconds` | Each first invocation until its answer |
| `wake_from_stopped_answer_seconds` | Each invocation to a stopped agent until its answer |
| `provision_seconds` | Each agent the step added, created until its first boot |

Durations are in seconds and memory in MiB, each as a count, minimum, p50,
p90, maximum, mean and sum. A step whose VMs would not fit in the host's
available memory, as if each used all of its memory, with 1 GiB to spare, is
recorded as `not_run` with the reason, and nothing boots.

Run it with the product campaign:

```bash
sudo python3 scripts/verify-product-guest.py <the campaign's usual options> \
  --pg-bin ... --pg-user ... --capacity-agents 1,5,10,20 [--capacity-memory-mib 256]
```

It runs last, after the scenarios, and writes `capacity.json` and the
worker's spans, `capacity-traces.jsonl`, in the evidence directory. The
campaign checks that every step is there, and that a measured step has a
value per VM. Each VM has 1 vCPU, the given memory (256 MiB by default) and
a 128 MiB volume, and runs the reference harness.

Without KVM, a dry run checks the configuration and the host's readings, and
says which steps would fit; nothing boots:

```bash
go test -c -tags kvm_integration,kvm_product_integration -o /tmp/worker.test ./internal/worker
AGENTCAPSULE_KVM_CAPACITY_DRY_RUN=1 AGENTCAPSULE_KVM_CAPACITY_REPORT=$PWD/capacity.json \
  AGENTCAPSULE_KVM_CAPACITY_AGENTS=1,5,10,20 /tmp/worker.test -test.run '^TestCapacityBenchmark$'
```

### Measured on 2026-11-17

One run of `verify-product-guest.py`, at b38980c with guest v26, on the
development machine: a WSL2 laptop-class host with 12 CPUs and 15.5 GiB
(kernel 6.18.58.1-microsoft-standard-WSL2), not a server. Other work shared
it: with every agent asleep it had 6.8 GiB available, and its CPUs were
46 % busy. These numbers are starting points for a host like it, not limits
of the platform. Each VM had 1 vCPU and 256 MiB, ran the reference harness,
and stayed idle once it answered. Local evidence:
`quint/results/product-guest-kvm-20261117T141155Z/capacity.json`.

| VMs | Boot p50 / p90 | All running | First answer p50 / p90 | From `STOPPED` to an answer p50 / p90 | VMM resident p50 | Host memory used by the VMs | VMMs' CPU while idle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 2.7 / 2.7 s | 3.0 s | 0.6 / 0.6 s | 3.2 / 3.2 s | 154 MiB | below the noise | 0.01 s/s |
| 5 | 3.2 / 3.4 s | 18.2 s | 4.2 / 5.2 s | 4.2 / 4.6 s | 154 MiB | 589 MiB | 0.10 s/s |
| 10 | 3.4 / 4.4 s | 44.7 s | 15.5 / 19.5 s | 5.0 / 6.4 s | 154 MiB | 1,185 MiB | 0.18 s/s |
| 20 | 3.2 / 3.7 s | 94.0 s | 42.8 / 66.6 s | 4.6 / 6.4 s | 154 MiB | 2,887 MiB | 0.27 s/s |

- A boot takes about 3 s, whatever the number of VMs. The worker boots one
  VM at a time, so 20 wakes sent at once are all running after 94 s.
- An idle VM of 256 MiB keeps about 154 MiB resident, and its cgroup is
  charged about 160 MiB. The host lost about 118 MiB per VM at 5 and 10 VMs,
  and 144 MiB at 20. A VM that works can use all of its memory, and its
  cgroup allows 256 MiB more ([ADR 012](adr/012-limits-restart-budgets-egress.md)).
- Idle VMs cost little CPU: 0.01 to 0.02 CPU-seconds per second each.
- First answers to invocations sent at once wait for the one dispatch loop,
  which delivers in turn. A delivery to a running agent took 0.5 s with one
  VM running and about 3 s with 20: before it, the worker held the binding
  of every running VM with the authority service, 7 times each
  (`hold_binding` in `capacity-traces.jsonl`). The worker now adopts the
  recipient's VM alone (**Adoption** at the top of this page): 7 holds to
  prepare a delivery and 1 to send it, whatever the number of VMs, where 20
  VMs took 140 and 20. The benchmark has not run again since that change.
  The wake of one stopped agent to its answer stays between 3 and 5 s.

**Setting `max_active`.** Count each VM at its cgroup's ceiling, its memory
plus 256 MiB, so that the host keeps more than 10 % of its memory even when
every guest fills its own (`AgentCapsuleHostMemoryLow` fires below 10 %):

```text
max_active = (available memory with every agent asleep - 10 % of the host's memory)
             / (the VM's memory + 256 MiB), rounded down
```

On the benchmark's host: (6,807 - 1,590) / 512 = 10 VMs of 256 MiB, the
starting point of [product.md](product.md) §2. Counted at what idle VMs used,
about 165 MiB each, the same host would hold about 30: an upper bound for
idle agents, not a setting. CPU is not in the rule: each VM may use its whole
vCPU, and the benchmark does not load them. On another host, measure the
available memory the same way before setting `max_active`.

## Limits and restart budgets

Each VM's drives have I/O ceilings, enforced by Firecracker's rate limiter
([ADR 012](adr/012-limits-restart-budgets-egress.md)): by default 64 MiB/s
and 2000 operations a second on the agent's volume, 128 MiB/s and 4000 on a
registry harness image, which a boot may first read whole at full speed. The
VM has no network device and its VMM no network namespace but its own: the
guest's only way out is the platform channel. Each VMM's cgroup bounds its
CPU to the VM's vCPUs (`cpu.max`), its memory to the VM's and 256 MiB more,
without swap (`memory.max`), and its tasks to 32 (`pids.max`); inside the
guest, the harness may run 256 processes. A guest that takes all its memory
is stopped by its own kernel, and a guest's processes are not the host's
(KVM tests of RUN-007, [acceptance](acceptance.md), not yet run). A guest
whose harness exits or dies restarts once `capsule-init` has closed the
agent's store, and its kernel's restart ends its VMM (`reboot=k`), which
frees the VM's slot and memory. Before the guest is ready, that is a failed
boot; once it is ready, a crash, counted at the next census: the next
maintenance pass or the next work for the agent. The agent reads `READY`
until then, then `STOPPED`, and its next work boots it again
([ADR 012](adr/012-limits-restart-budgets-egress.md), question 6). A sleep
is never counted: its guest quiesces and stays up until the worker removes
the VMM.

An agent whose guest fails to boot, or crashes, too often stops being booted.
A boot counts when its VMM ran and then exited, stopped answering, or
answered with an incompatible contract before it was ready; a crash is a
confirmed VM gone without a stop. A full host, a refused lease or an
authority outage does not count. After 5 such failures within an hour, the
agent is `FAILED`: no work, barrier or credential replacement boots it, its
open wake ends `FAILED` (`restart_budget_exhausted`), and its work waits
until a wake or its deadline. A wake requested for the agent gives it a new
budget, and so does:

```sh
agentcapsule-admin clear-agent-failure -agent-id <id>
```

A restore of its volume still boots it, restricted. To change the defaults,
add to the configuration (every worker of a host the same):

```json
"drive_limits": {
  "volume": { "bandwidth_mib_per_second": 64, "iops": 2000 },
  "harness": { "bandwidth_mib_per_second": 128, "iops": 4000 }
},
"restart_budget": { "failures": 5, "window": "1h" }
```

A number left out keeps its default. Ceilings go from 1 MiB/s to 4 GiB/s
and from 10 to 1,000,000 operations a second; a budget from 1 to 100
failures within 1 minute to 24 hours. The operator sees
`agentcapsule_worker_agents_failed`, the event `agent_failed` and the alert
`AgentCapsuleAgentFailed` ([observability.md](observability.md)).

## The authority service

D-05 ([ADR 005](adr/005-keys-outside-restored-domain.md)) keeps both
authorities on the standby host too, in a replica. Since
[ADR 006](adr/006-authority-service.md), the authority service holds the link
to the replica, degraded mode, the barrier that keeps every write behind the
replica, and their metrics. The worker runs none of it. It sees degraded mode
only through the errors of the writes that wait ("degraded mode: this
authority operation waits for the replica"), and the service's `status`.

- The link's section, `authority_replica`, is in the service's configuration
  `/etc/agentcapsule/authority.json`, unchanged
  ([recovery.md](recovery.md#install-the-replica)): the standby's address,
  this host's certificate and key, the standby's pinned certificate, and
  `degraded_after` (30 seconds by default, from 5 seconds to 10 minutes).
- **Without it, the authorities are standalone.** That gives no protection
  against the host's loss: its keys and its catalogue exist on this host only.
  Once a snapshot has armed the authorities, the service refuses to start
  without the section (`authority_replica_required`). With the section and
  authorities never armed, it refuses too (`authority_replica_not_armed`).
- **After a failover**, the service on the standby runs on the promoted
  authorities, standalone, under the next epoch
  ([recovery.md](recovery.md#promote-the-replica)). The worker there keeps the
  same `authority` section: the identities do not change. Fence receipts carry
  the epoch that signed them: a receipt of the old primary is refused, and
  every boot and restore scans under the new epoch.

**What a write does.** The restore authority's catalogue holds the log. A
write commits its record in the same SQLite transaction as its effect. Then
the service sends the record and waits for the replica's acknowledgment.
Every transaction, a read too, first checks that the replica holds every
record already committed. A replicated write costs one round trip and the
replica's fsync, on top of the local commit.

### Degraded mode

ADR 005 (question 2) decides what happens when the standby does not answer;
[recovery.md](recovery.md#degraded-mode) says what the operator does.

**For the first `degraded_after`** (30 seconds), every authority write
waits for the standby, and fails when its attempt times out. Deliveries,
boots, provisioning and removals retry.

**Then the service enters degraded mode.** Some writes continue without the
standby; the others still wait:

| Continue: they return once committed on this host | Wait for the standby |
| --- | --- |
| Outcome records, so deliveries | Registering a new store, and its new volume key: creating an agent |
| Reruns of an outcome declared lost | Sealing a store, and destroying its volume key: deleting an agent |
| Fence revisions, so boots | Reserving an incarnation, declaring losses, activating the image: restoring an agent |
| The start of a revocation: new key grants and fences stop at once on this host | The completion of a revocation, published in PostgreSQL |
| Reads | — |

A write that waits fails at its deadline with "degraded mode: this
authority operation waits for the replica", and its job retries. A restore
pauses ([Restoring an agent](#restoring-an-agent)). The completion of a
revocation waits: ADR 005's finding 1 was decided as option (a) on November
15, 2026.

**When the standby answers again**, the service sends it what it lacks, in
order, then leaves degraded mode by itself. Until then, those writes exist on
this host only.

**A worker restart does not touch degraded mode**: the service keeps it. A
restart of the service does: the restarted service cannot tell a standby
that is down from one that was promoted (ADR 005, finding 2), so it runs no
authority operation, reads included, until it reaches the standby.

The metrics and alerts of the replica are the service's, on its
`metrics_listen` (`127.0.0.1:9466`, the scrape job `agentcapsule-authority`):
[observability.md](observability.md#metrics). The alerts are
`AgentCapsuleAuthorityServiceDown`, `AgentCapsuleAuthorityDegraded`,
`AgentCapsuleAuthorityOperationsRefused` and
`AgentCapsuleAuthorityReplicationStopped`
([observability.md](observability.md#alerts)).

## Deleting a product volume

After all distributed barriers, the worker seals execution on the host: no new
boot, no remaining VMM and the file identity verified. With product
provisioning configured, it then records the seal and destroys the key through
the authority service, which refuses to destroy the key of a store it has not
sealed, then removes the single provisioned inode. A permanent journal keeps the
`REMOVING/REMOVED` steps; it forbids reformatting or recreating this identity
after an interruption. A replaced file, an extra link or a busy lock makes the
operation fail. The registries, tombstones and reserved UIDs are kept.

The final SQL receipt publishes `DELETED` and the `SUCCEEDED` operation
together. A crash between the physical removal and this receipt leaves a
resumable operation; a simple seal keeps `CLEANUP_PENDING`. Until that
receipt, `agentcapsule_worker_deletions_unfinished` counts the deletion, and
`AgentCapsuleDeletionUnfinished` fires after 6 hours: the key still exists
([observability.md](observability.md)). The next barrier
acknowledgments on this agent re-check the absence of the file and the permanent
seal. Older hosts with manually supplied volumes and without a
provisioner/key authority attest only the execution seal.

These operations apply to the volume and key managed by this installation. They
do not destroy external copies, backups or the raw blocks of the medium.
Rollback-resistant restore remains the D5 workstream. The local journal/crash
and SQL publication tests run; the deletion scenarios in a real VM
(`TestProductWorkerTwoOwnersPrivateExchange`,
`TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord`)
passed on KVM on 2026-11-17 (26 of 26 worker tests, guest v26), the worker
reaching its authorities through the authority service, whose seal check
the second test makes.

## Nightly encrypted archives

The maintenance worker archives each agent's encrypted volume about once a day
(REC-02, [ADR 004](adr/004-recovery-objectives.md)). It does it itself,
between its passes: it is never stopped for it. Add to its configuration:

```json
"archives": {
  "root": "/var/lib/agentcapsule-archives",
  "every": "24h",
  "sleep_window": "2h",
  "keep": 7
}
```

This section needs `provisioning` and the `authority` section. The worker checks
it at start, and checks the root against the authorities' directories at each
capture:

| Field | Default | Allowed | Meaning |
| --- | --- | --- | --- |
| `root` | (required) | absolute path | A private directory (root, mode 0700), outside the runtime and both authorities. Created if absent. |
| `every` | `24h` | 1 hour to 7 days | The age that each agent's newest archive must not pass: the volume RPO. |
| `sleep_window` | `every`/12 (2 hours) | 0 to `every`/2 | How long before `every` the worker starts taking the archive when the agent sleeps. |
| `keep` | 7 | 1 to 365 | Archives kept per agent on this host. |
| `per_pass` | 1 | 1 to 8 | Captures in one maintenance pass. |
| `timeout` | `30m` | 1 minute to 6 hours, below `every` | Bound on one capture, the copy included. |

**Which agents, and when.** The worker considers the LIVE agents of its host
whose volume is provisioned and initialized:
- **An agent that sleeps** is captured as it is: nothing stops. It is captured
  at once if it has no archive yet, and otherwise once its newest archive is
  older than `every` minus `sleep_window` (22 hours by default).
- **An agent that runs** is left alone until its newest archive reaches
  `every`; an agent without an archive counts from the initialization of its
  volume. The worker then stops it briefly for the capture: authenticated
  quiescence, then the copy. The agent **stays asleep** afterwards, and wakes
  on its next delivery or wake, like after any sleep.
- Sleeping agents come first, then the oldest archive.
- An agent whose last stop was not clean (a forced or uncertain stop) is not
  captured: a capture needs a clean stop. It is captured after its next clean
  sleep.

**Cost for the host.** A capture holds the agent's barrier, which is the host's
exclusive admission, and the host registry while it copies the volume.
Deliveries and boots on this host wait for it. A capture takes about the
volume's size divided by the disk's speed: a few seconds for a small volume.
This is why a pass takes `per_pass` captures at most (1 by default), after its
deliveries. A pass with nothing due costs one query.

**Failures.** A capture that fails leaves no partial archive: the files are
written in a hidden staging directory and published in one rename. The agent
is tried again later: after 30 minutes (`every`/48), then twice as long each
time, up to 6 hours (`every`/4). The other agents go on meanwhile. A failure
can leave a running agent stopped; it wakes on its next delivery.

**Records.** Each capture is recorded in PostgreSQL (`volume_archives`,
migration 0028): the agent, the archive ID, the volume and its incarnation, when
the capture started and ended, the size, and when retention removed it. No
content and no key. The row is written before the capture starts. After a crash,
the agent's next capture settles it: an archive that was published is recorded
as of the start of its capture; otherwise the row is dropped. A later capture
deletes the staging directories that a crash left, once they are an hour old.

**Retention.** After each capture, the worker deletes the agent's archives
beyond the `keep` newest ones. An archive is first renamed out of its ID, then
deleted: it is either whole or gone. The newest archive, just captured, is
always kept, so an agent never loses its only archive.

**A deleted agent's archives.** Deleting an agent destroys its volume key
([Deleting a product volume](#deleting-a-product-volume)): from then on, none
of its archives opens, here or on a store. The worker then deletes them from
this host, at its first pass and then once an hour: the recorded ones and those
taken on demand, found by their manifest. It waits for the key's destruction,
recorded in PostgreSQL (`store_removals`), and leaves an archive whose manifest
it cannot read for the operator. The copies on the stores expire by age
([recovery.md](recovery.md#deleting-an-agent-its-keys-and-its-archives-adr-018)).

**Events and metrics.** `volume_archive_captured`, `volume_archive_purged` and
`volume_archive_retry`, with a reason, and the `agentcapsule_worker_volume_archive*` metrics: see
[observability.md](observability.md). The worker keeps its archives on this
host. A separate service ships them off the host every hour, to the S3 store
and the standby ([recovery.md](recovery.md#volume-archives-off-the-host-rec-02)).

## Archive on demand

The operator can also capture one agent by hand, with the same worker
configuration and the same protected PostgreSQL environment. This mode requires
product provisioning and the authority service, which it reaches like the
maintenance worker. It is a separate process: first stop the maintenance
worker so that it releases its listeners, not for the authorities; its VMs may
stay present and will be reconciled by this command. Restart
maintenance after the capture. The targeted agent stays stopped on exit and can
be woken through the usual paths. Nightly archives do not need this.

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -archive-agent "$AGENT_ID" \
  -archive-id arc_0123456789abcdef0123456789abcdef \
  -archive-root /var/lib/agentcapsule-archives
```

Choose a new `arc_` identifier followed by 32 lowercase hexadecimal digits for
each new backup point. Reuse exactly that identifier after a lost response: an
already published archive is verified and returned, never replaced by a more
recent state. The identifier above is an example. A failure after quiescence has
started can leave the agent stopped. An archive taken by hand is not recorded
in PostgreSQL: it does not count for the nightly schedule, and retention never
removes it. Once the agent is deleted, the maintenance worker deletes it like
the others, if it is in the root of its `archives` section.

Both ways capture the same way. The worker waits for the authenticated
quiescence of a running agent, physically removes the VMM and checks the SQL
observation of a clean stop. A forced or uncertain stop is
refused for capture; restore a startup followed by a clean stop before retrying.
It checks the registered inode and its exclusive lock, copies the encrypted LUKS
container, then atomically publishes `volume.luks` and `manifest.json` in a
directory named after the archive ID. The output manifest binds the authority,
the agent, the volume, the source incarnation, the release, the size and the
digest of the captured bytes.

The directory must be private and located outside the runtime and both
authorities. No decryption key is copied into the archive. The files and the
manifest are verified on read; a signature never exempts you from inspecting the
recovered data or from respecting the restore barriers.

This local storage is the encrypted source of a restore (next section). It is
not an off-VPS backup, a restore test on a second host or a proof of erasure of
all key copies.

## Restoring an agent

The operator can restore one agent of this host from one of its archives, into
a new incarnation, with the same worker configuration and protected PostgreSQL
environment. Like the archive on demand, it is a separate process: stop the
maintenance worker first, for its listeners, and restart it after. It needs
product provisioning, the authority service, and a restore authority catalogue
at version 2.

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -restore-agent "$AGENT_ID" \
  -restore-id rst_0123456789abcdef0123456789abcdef \
  -archive-id "$ARCHIVE_ID" \
  -archive-root /var/lib/agentcapsule-archives
```

Choose a new `rst_` identifier followed by 32 lowercase hexadecimal digits. The
restore is recorded in PostgreSQL under it before anything stops; until the
command succeeds, the agent stays out of service. Run the same command again,
with the same identifier, to resume it after a crash or an error. A new
identifier replaces an unfinished restore that has not activated. The worker
prints a receipt with the new incarnation, the number of declared losses and
the number of lost invocations and agent-to-agent events that run again, or
`restore_failed_<reason>`.
While the authorities do not answer (the service restarts, or waits for the
standby in degraded mode), the restore pauses: it logs `restore_paused` with
the reason, then resumes by itself from its last durable step. A refusal of
the authorities still ends it. `SIGINT` stops a paused restore; the same
command resumes it later.
See
[Restoring an agent from an archive](recovery.md#restoring-an-agent-from-an-archive)
for the steps, the losses, their reruns and the crashes.

With `-archive-fetch /opt/agentcapsule/agentcapsule-archive-ship.py`, an
archive missing from the archive root is fetched from the standby's copy, or
from S3 if the standby has none, and verified against the restore authority
before the restore uses it. The receipt's `archive_store` says where it came
from: `local`, `standby` or `s3`.

### Restoring a lost host's agents

After a disaster, the worker of the host that took a lost host over
(`agentcapsule-admin take-over-host`,
[ADR 020](adr/020-restoring-a-lost-hosts-agents.md)) restores every agent of
the lost host, each from its newest archive that a store holds, and moves it
to this host:

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -restore-host "$LOST_HOST_ID" \
  -archive-root /var/lib/agentcapsule-archives \
  -archive-fetch /opt/agentcapsule/agentcapsule-archive-ship.py
```

It prints one JSON line per agent as it goes (`restored`, `skipped` or
`failed`, with a reason), then the totals, and exits 1 if an agent failed. Run
the same command again to resume: it reports restored agents again and
resumes unfinished restores first. A worker whose `host_id` names a lost host
refuses to start (`host_taken_over`).
[The procedure](recovery.md#the-procedure) gives the whole failover.

## Testing a restore

The operator can check that an agent can be restored, without restoring it
and without stopping anything (OPR-5). The maintenance worker keeps running:

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -test-restore "$AGENT_ID" \
  -archive-root /var/lib/agentcapsule-archives \
  -scratch /var/lib/agentcapsule-restore-tests \
  [-archive-id "$ARCHIVE_ID"] [-archive-fetch /opt/agentcapsule/agentcapsule-archive-ship.py]
```

It takes the agent's newest archive that PostgreSQL records, the one a
restore after a host's loss would take, or the one `-archive-id` names. It
needs product provisioning and the authority service, which it reaches like
the maintenance worker. `-scratch` is a directory of root, not writable by
group or others, outside the runtime root, the archive root and both
authorities, with room for one volume. What it checks, in order:
1. the manifest is the one the restore authority signed, for a store that is
   not sealed, and the bytes have the manifest's size and SHA-256 digest;
2. the archive is of the agent's current volume, and of its size;
3. a copy in a new private directory under `-scratch` has the same digest;
4. the key the key authority lends for the agent opens the copy's key slot.
   The payload is never unlocked: a volume opens only in its guest.

It prints what it checked, then removes its directory:

```json
{"agent_id":"agt_…","archive_id":"arc_…","archive_store":"local","captured_at":"2026-11-17T02:10:00Z","archive_incarnation":1,"incarnation":1,"size":134217728,"checked":["manifest","digest","volume","copy","key"],"seconds":1.4}
```

On failure, it prints `restore_test_failed_<reason>` and exits 1:
`no_archive` (PostgreSQL records none), `archive_unavailable` (not in the
archive root, and not fetched), `archive` (incomplete, altered, unsigned or of
another volume), `key` (the agent's key does not open it), `authority` (a
refusal: a deleted agent's store is sealed), `state` (the agent has no volume
on this host), `error`.

With `-archive-fetch`, an archive missing from the archive root is fetched
from the standby's copy, or from S3, into the test's own directory, and
`archive_store` says from where. The archive root is never written.

**What it changes: nothing.** It reads PostgreSQL, the archive root and the
authorities' records; it asks the authorities to validate the manifest and to
lend the key, which reserves nothing and records nothing. It takes no barrier
and starts no VM, so the agent keeps running and its deliveries go on. While
it holds the key, a restore or a deletion of that agent waits for it, for the
time of one key check (about 0.1 s). It skips the mandatory preflight: it
runs on a host without KVM, or with a full runtime disk. What it does not
prove: that the guest's file system inside is sound, or that the harness
boots; a restore proves those
([recovery.md](recovery.md#test-a-restore)).

## Collecting garbage on demand

The maintenance worker cleans up on its own: the archives past `keep` after
each capture, the archives of deleted agents and the cached harness packages
no agent of the host can boot once an hour, and what interrupted captures,
removals and downloads left. `-collect-garbage` runs the same cleanup now, on
this host, for example when a disk fills up (OPR-5):

```sh
/opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json -collect-garbage -dry-run
/opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json -collect-garbage -confirm "$HOST_ID"
```

It takes the guards of the operator's destructive commands
([ADR 014](adr/014-operations-capacity-diagnostics-audit.md) §7):
- without `-dry-run`, `-confirm` must repeat the configuration's `host_id`;
  otherwise it prints `confirmation_required` and opens no connection;
- `-dry-run` prints what it would remove and removes nothing;
- a run is recorded in `operator_audit` (`garbage.collected`, the host,
  `done` or `unchanged`), which `agentcapsule-admin list-audit` prints. A dry
  run is not recorded.

It prints one JSON object: under `archives`, the archives beyond the `keep`
newest of their agent on this host (`retention`), the archives of deleted
agents whose key is destroyed (`deleted_agents`), the leftovers, and their
bytes; under `images`, the digests of the packages no agent can boot
(`unused`), the leftovers of downloads, and their bytes. A part is absent
when its section (`archives`, `registry`) is not configured.

```json
{"action":"garbage.collected","target":"host-1","outcome":"done","dry_run":false,"archives":{"retention":["arc_…"],"deleted_agents":[],"leftovers":0,"bytes":134221824},"images":{"unused":["sha256:…"],"leftovers":1,"bytes":52428800}}
```

It keeps what the worker keeps: each agent's `keep` newest archives, an
agent's only archive, the archives taken on demand of live agents, an
archive whose manifest it cannot read, the approved releases, the packages
an agent of this host is pinned to or may boot, and imports in progress. It
runs beside the maintenance worker: each removal is one the worker may make
too, and repeating one is harmless. A leftover goes only once untouched for
an hour, so a capture or a download in progress is left alone; the worker's
own pass removes a download's leftovers at once. It skips the mandatory
preflight, so that a full disk does not stop it, and never creates the
runtime root, the archive root or the cache. After an error, it prints what it
removed so far, records the run, and prints
`collect_garbage_interrupted_run_again`.
