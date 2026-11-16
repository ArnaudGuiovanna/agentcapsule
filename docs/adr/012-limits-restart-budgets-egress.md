# CAP-03 — Disk ceilings, restart budgets and egress

Date: November 16, 2026. **Status: built on November 16, 2026**, with
defaults pending the product owner (see [Questions](#questions-for-the-product-owner)).
The KVM tests that prove the ceilings and the budget on a real VM have not
run yet (see [Tests](#tests)).
References: RUN-007, RUN-008, RUN-011 and §6 of the
[product spec](../product.md), CAP-03 and TEN-07 of the
[roadmap](../../ROADMAP.md), [worker.md](../worker.md),
[observability.md](../observability.md).

## Context

RUN-007 asks that a hostile agent stay within its CPU, RAM, I/O, time and
process ceilings. RUN-011 asks for a usable status, `FAILED` or `QUEUED`, when
a boot fails, and no spawn loop. §6 asks that a guest's egress go through the
platform only; an internet profile with allow or deny lists is a separate,
riskier profile.

What the host enforced before this record (lines of `mvp-integration`):

| Limit | Enforced by | Where |
|---|---|---|
| CPU | cgroup v2 `cpu.max`, `vcpus` × 100 ms per 100 ms, and the VM's vCPU count | `internal/runtime/firecracker_linux.go:913`, `:902` |
| RAM | the VM's memory, plus `memory.max` = memory + 256 MiB for the VMM, and `memory.swap.max` = 0 | `firecracker_linux.go:902`, `:913`, `:921` |
| Processes | `pids.max` = 32 for the VMM's cgroup; 256 for the harness's cgroup inside the guest; 256 open files for the VMM | `firecracker_linux.go:913`, `cmd/capsule-init/main.go:90`, `firecracker_linux.go:765` |
| Planned resources | vCPUs 1–8, memory 128–8192 MiB, volume 64–32768 MiB, immutable once registered | `internal/runtime/firecracker_provisioning_linux.go:46-48`, `:130` |
| Disk size | the volume file has exactly its planned size; the host's storage reservation bounds the sum | `firecracker_provisioning_linux.go:123`, `internal/controlplane/tenant_agents.go:136` |
| Disk bandwidth and IOPS | **nothing**: the drives had no rate limiter, and the host's cgroups enable no `io` controller | `firecracker_linux.go:890`, `:189` |
| Time | boot timeout (30 s by default), each job's `attempt_timeout`, an invocation's `work_timeout`, a delivery's deadline and three attempts | `firecracker_linux.go:145`, `internal/controlplane/invocation_completion.go:165`, `internal/controlplane/delivery.go:336` |
| Running VMs | `max_active` per host | `firecracker_linux.go:696` |
| Isolation (RUN-008) | one UID per agent, never reused; jail, PID namespace and cgroup per boot; the attempt's cgroup killed, its jail, credentials and platform socket removed at cleanup | `firecracker_linux.go:364-405`, `firecracker_provisioning_linux.go:135-147`, `firecracker_linux.go:431-469`; checked on KVM by `scripts/verify-vm-isolation.py` |
| Network | no network device in the VM's configuration; the VMM in a network namespace of its own (`CLONE_NEWNET`), loopback only; the guest brings up `lo` only | `firecracker_linux.go:902`, `:766`, `docs/guest/README.md` |
| Boot retries | **unbounded**: a failed boot is retired and its job retried with backoff (`retry_base` to `retry_max`, 1 s to 30 s by default) for as long as the job exists; a crashed guest was reconciled `STOPPED` and booted again by the next work | `internal/worker/placements_linux.go:277-280`, `:189-202`, `internal/worker/dispatch_linux.go:21`, `internal/controlplane/work.go:182` |
| Wake budget | an organization's requests between its agents wake at most 60 sleeping agents an hour; a failed boot gives its wake back | `internal/controlplane/peer_wakes.go:57`, `internal/worker/control_linux.go:90-106` |

So a guest could saturate the host's disk, and a guest that failed at boot,
or crashed soon after, was booted again by every retry of every job that
needed it: a wake retried every 30 seconds forever, a delivery until its
deadline (7 days for a reply), a credential replacement at each maintenance
pass.

## Decision

### 1. Disk ceilings per VM

Every drive of every VM gets a Firecracker rate limiter, a token bucket for
bytes and one for operations, refilled every second
(`internal/runtime/firecracker_limits_linux.go`). Firecracker enforces it in
the VMM, so it needs no `io` controller in the host's cgroups, works on a
volume that is a file, and counts reads and writes together.

| Drive | Bandwidth | Operations | One-time burst |
|---|---|---|---|
| The agent's volume | 64 MiB/s | 2000/s | none |
| A registry harness image | 128 MiB/s | 4000/s | the image's size, so a boot can read it whole at full speed |

These are defaults, **pending the product owner**. The operator sets others
per host in the worker's configuration (`drive_limits`), from 1 MiB/s to
4 GiB/s and from 10 to 1,000,000 operations a second. A guest also reads and
writes its tmpfs `/tmp` and `/run`, which live in its RAM and stay within it.

Not done:
- **cgroup `io.max`.** It was not wired. It would need the `io` controller on
  the host's hierarchy and the volume's block device numbers; the volume is a
  file on the host's file system, and buffered writeback is charged to the
  writer only when the memory and io controllers cooperate. The rate limiter
  covers the same need from inside the VMM.
- **Ceilings per agent** from the harness manifest within the organization's
  quotas. The manifest (`harness.yaml`, `internal/harnesspkg/package.go`)
  declares no resources today, and organizations have no physical quotas
  (TEN-07). Each VM has its own buckets, so one agent cannot take another's
  share; every agent of a host has the same ceilings. Per-agent ceilings are
  P1 (question 1).

### 2. Restart budgets

**What counts.** A *guest failure* is either:
- a **failed boot**: the VMM ran, holding the agent's volume, then, before the
  guest was ready, the VMM exited, or nothing answered on its control channel
  after a 3-second grace, or the guest answered with an incompatible
  contract (`runtime.ErrBootFailed`, `firecracker_limits_linux.go`);
- a **crash**: a confirmed VM whose VMM went away without a stop, found by
  reconciliation.

A failed start is *not* the guest's failure when the host is full, the volume
is busy, a lease is refused, an authority or the database is unavailable, the
caller gave up, or the VMM never started (a jailer or host fault): a guest
that still answers was refused by the platform. Only failures of a live
agent whose volume is not being restored count.

**The budget.** Each failure is recorded once, keyed by its boot generation,
in the transaction that publishes the retired generation `STOPPED`
(migration 0031, `ObserveGuestFailure`). When an agent has had **5 failures
within an hour** (default, **pending the product owner**; `restart_budget`
in the worker's configuration, 1 to 100 within 1 minute to 24 hours), it is
**`FAILED`**. Boot failures and crashes count together. The reason is the
kind of the last failure: `boot_failed` or `crashed`. The agent views show
`state: FAILED` and `failure_reason`.

**What a FAILED agent does.** Nothing boots it: no work boot, no credential
replacement, no barrier boot is claimed (`bootAllowed` in `claimPlacement`).
- A wake already open ends `FAILED`, error `restart_budget_exhausted`.
- Invocations and deliveries wait without spending an attempt (retry reason
  `agent_failed`), until a wake or their deadline. A delivery dies at its
  deadline as before (ADR 007).
- A barrier that needs the agent's store waits too; so does what waits for
  that barrier (a request's closure, another agent's deletion), as it did
  when the agent could not boot, but without a boot every 30 seconds.

Two things still boot it, restricted: a **restore** of its volume, the
operator's own act, whose failures do not count; and a **deletion**, which
moves the agent out of `LIVE`, so the hold no longer applies.

**What clears it.** An explicit act gives a new budget, in one transaction:
- a **wake** requested for the agent (`POST /v1/agents/{id}/wake`), by its
  owner, its organization's administrators or operators, or a service with
  `agent:manage`; a replayed request does not clear again;
- the operator's **`agentcapsule-admin clear-agent-failure -agent-id <id>`**.

Automatic wakes do not clear it: deliveries, requests between agents, idle
schedules, an `auto_start` after creation.

**No double counting.** The wake budget counts an organization's wakes for
requests between agents; a boot that fails gives its wake back
(`releaseWake`), so a failing agent spends restart budget, not wake budget.
The dispatcher prepares an agent once per attempt of a job, and a boot
counts once per generation, whichever job or retry caused it.

**For the operator.** `agentcapsule_worker_guest_failures_total{kind}`,
`agentcapsule_worker_agents_failed_total`, the gauge
`agentcapsule_worker_agents_failed`, the event `agent_failed` with its reason
and never the agent, and the alert `AgentCapsuleAgentFailed`
([observability.md](../observability.md)). `AgentCapsuleVMBootFailures` still
counts every failed boot for work.

### 3. Egress

The default, and only, profile denies egress except through the platform:
- the VM's configuration has no network device (no `network-interfaces`);
- the VMM runs in a network namespace of its own, with no interface but
  loopback (`jailerCommand`, `CLONE_NEWNET`), so even an escaped VMM has no
  route out;
- the guest brings up its loopback only, for an adapted agent's model
  endpoint;
- its only channel out is the vsock to its own jail's socket, which the
  worker serves with the platform channel's typed API: model calls through
  the gateway, peers, the Directory, attachments.

`TestGuestsHaveNoNetwork` pins the configuration and the namespace flag; the
KVM test below checks the namespace of a real VMM.

The **internet profile** (a NIC, allow or deny lists, a proxy outside the
guest) is not built. It needs a tap device per VM in a network namespace the
worker owns, an egress proxy or nftables rules per agent, a policy per
organization and per harness (the manifest's "egress" of the product spec),
and a decision on which secrets such a guest may still hold. It is **P1**.

## Consequences

- A guest that fails at boot boots at most 5 times an hour, whatever the
  number of jobs and retries waiting for it, then stops booting until someone
  acts. A crash loop is bounded the same way.
- A platform fault misclassified as a guest failure would hold an agent
  until a wake. The classification counts only what a guest controls; a
  host reboot counts one crash for each running agent, within budget.
- While an agent is `FAILED`, barriers that need its store wait. A request's
  closure fences every store of the installation, so one `FAILED` agent
  delays the closure of every expiring request until it is woken. Before
  this record, the same wait happened with a boot every 30 seconds.
- `FAILED` is a state of a live agent; the placement stays `STOPPED`. A
  restored agent stays `FAILED` until woken or cleared.

## Tests

Unit tests (`go test -race`):
- `internal/runtime`: `TestDrivesHaveIOCeilings`, `TestDriveLimitsAreBounded`,
  `TestGuestsHaveNoNetwork`, `TestBootFailureIsTheGuestsOnlyWhenTheGuestFailed`,
  `TestControlAnswers`.
- `internal/worker`: `TestRestartBudgetAndDriveLimitsConfiguration`,
  `TestRetryReasons`.
- `cmd/capsule-echo`: `TestTestBehaviours`, `TestFloodStaysWithinItsSpan`.

PostgreSQL tests:
- `internal/controlplane`: `TestAnAgentWhoseGuestKeepsFailingIsFailed`,
  `TestCrashesSpendTheRestartBudget`, `TestRestoresAndDeletionsAreNotHeld`,
  `TestAWakeOfAFailedAgentFails`, `TestAPersonsFailedAgent`.
- `internal/worker`: `TestGuestFailuresAreCountedAndLogged`.

KVM tests, not run yet (they need root and the next guest build, whose
`capsule-echo` has the test behaviours `crash-at-boot` and `flood-volume`):
- `TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest`: a guest writing
  1 MiB at a time stays under 8 MiB/s, one writing 4 KiB at a time with
  `fdatasync` under 200 operations a second, measured from the VMM's
  `/proc/<pid>/io`; each VMM's network namespace has loopback only.
- `TestProductWorkerStopsBootingAGuestThatCrashesAtBoot`: the wake of a guest
  that crashes at boot ends `FAILED` after a budget of 3; further passes boot
  nothing while an invocation waits; a wake after the fix answers it.

## Questions for the product owner

1. **Disk ceilings.** An agent's volume is capped at 64 MiB/s and 2000
   operations a second, a harness image at 128 MiB/s and 4000. A data-heavy
   agent (a large SQLite index, a model's files) would be slowed. Options:
   (a) the same ceilings for every agent of a host, set by the operator;
   (b) the harness declares what it needs in `harness.yaml`, within an
   organization quota and the host's ceiling; (c) an administrator sets it per
   agent. Recommendation: (a) for the MVP, (b) with the organization quotas of
   TEN-07.
2. **Restart budget.** An agent whose guest fails to boot or crashes 5 times
   within an hour becomes `FAILED` and stops booting until someone wakes it.
   Options: (a) 5 per hour; (b) fewer (3 per 15 minutes), stopping a broken
   release sooner but holding an agent that hit a passing fault; (c) more.
   Recommendation: (a).
3. **Who clears it.** Today a wake by anyone allowed to wake the agent clears
   it, and so does the operator. Options: (a) as built; (b) the operator only,
   so an organization cannot boot a broken release again and again (5 boots
   per wake); (c) also an automatic retry after a long delay (a day).
   Recommendation: (a), since each wake is a person's act and costs at most
   one budget.
4. **Work for a FAILED agent.** An invocation to a `FAILED` agent is accepted
   and waits until a wake or its deadline. Options: (a) as built; (b) refuse
   it at once with `agent_failed`. Recommendation: (a): a wake after a fix
   answers it, as the KVM test shows; the person sees the agent's state.
5. **Internet profile.** Not built. Recommendation: P1, with a policy per
   organization and per harness, and a proxy outside the guest.
