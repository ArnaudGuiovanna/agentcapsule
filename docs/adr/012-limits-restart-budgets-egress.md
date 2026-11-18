# CAP-03 — Disk ceilings, restart budgets and egress

Date: November 16, 2026. **Status: built on November 16, 2026**, with
defaults pending the product owner (see [Questions](#questions-for-the-product-owner)).
The KVM tests that prove the drive ceilings and the budget on a real VM
passed on November 17, 2026, after a first run that day failed on faults of
the tests (see [Tests](#tests)). The KVM tests of the CPU, memory, process
and time ceilings against a hostile guest were written on November 18, 2026
and have not run.
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
  declares no resources today. Organizations had no physical quotas (TEN-07)
  until [ADR 021](021-organization-quotas.md), which bounds their agents,
  storage, VMs, vCPUs and RAM, not their disk throughput. Each VM has its
  own buckets, so one agent cannot take another's share; every agent of a
  host has the same ceilings. Per-agent ceilings are P1 (question 1).

### 2. Restart budgets

**What counts.** A *guest failure* is either:
- a **failed boot**: the VMM ran, holding the agent's volume, then, before the
  guest was ready, the VMM exited, or nothing answered on its control channel
  after a 3-second grace, or the guest answered with an incompatible
  contract (`runtime.ErrBootFailed`, `firecracker_limits_linux.go`);
- a **crash**: a confirmed VM whose VMM went away without a stop, found by
  reconciliation.

A guest whose harness exits or dies, at any time, ends its VMM (question 6,
decided on November 18, 2026). `capsule-init` stops the harness's
descendants and, once none remains, whatever the harness's exit status,
closes the agent's store (`syncfs`, unmounts, dm-crypt); a harness whose
processes cannot be confirmed gone leaves the store mounted. It then
synchronizes what is left and restarts the guest (`guestinit.End`). The guest's kernel is booted with `reboot=k`, so it
restarts by resetting the CPU through the keyboard controller, and
Firecracker exits on that reset (its `docs/api_requests/actions.md`:
"Firecracker exits on CPU reset"). Before the guest is ready, the start
finds the VMM gone: a failed boot. Once it is ready, the next
census finds the VMM gone: a crash. The census is the next maintenance
pass, or the next work for that agent, whichever comes first. A stop the
platform asks for (sleep, eviction) is not counted: the placement is
`STOPPING` before the guest quiesces, the guest stays up to acknowledge,
and the host removes the VMM.

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
- A guest that stops on its own once ready crashes (question 6). When its
  harness dies (the guest's kernel kills it for taking all its memory, for
  example), the guest restarts, which ends its VMM and frees its VM slot and
  memory. The agent reads `READY` until the next census counts the crash,
  then `STOPPED`; its next work boots it again, and 5 such crashes within an
  hour make it `FAILED` with `failure_reason` `crashed`. A guest that stays
  up but whose control channel stops answering is still not counted: it
  keeps its VM until it is put to sleep (option (c) of question 6, a later
  item).
- A harness that never returns from an invocation holds its store's write
  transaction. Each attempt ends at the host's 20-second timeout, but ending
  the invocation after its third attempt needs a fence on that store, which
  the held transaction refuses: the invocation stays open, and the agent's
  next deliveries wait behind it, until its VM is stopped (question 7).

## Tests

Unit tests (`go test -race`):
- `internal/runtime`: `TestDrivesHaveIOCeilings`, `TestDriveLimitsAreBounded`,
  `TestGuestsHaveNoNetwork`, `TestBootFailureIsTheGuestsOnlyWhenTheGuestFailed`,
  `TestControlAnswers`.
- `internal/worker`: `TestRestartBudgetAndDriveLimitsConfiguration`,
  `TestRetryReasons`, `TestPassesOfAGuestThatFailsAtBoot`,
  `TestProcIOMovedCountsReadsAndWrites`.
- `cmd/capsule-echo`: `TestTestBehaviours`, `TestFloodStaysWithinItsSpan`,
  `TestFloodWritesDirectlyToTheDrive`; for the hostile behaviours,
  `TestHostileActsStopWithTheirContext`,
  `TestHostileBehavioursStartAfterTheFirstAnswer`,
  `TestBurnKeepsItsGoroutinesBusy`, `TestEatMemoryWritesEveryPage`,
  `TestForkHolderWaitsUntilKilled`, `TestForkBombKeepsTryingWhenRefused`,
  `TestNeverFilesAnswersWorkingAndLoops`.
- `internal/worker`, for the hostile-guest KVM tests: `TestCgroupFilesParse`,
  `TestCPUCeilingOfAWindow`.
- For question 6: `internal/guestinit`:
  `TestTheGuestEndsWithARestartAfterItsCleanup` (the guest ends with a
  restart, after `capsule-init`'s cleanup and a sync); `internal/runtime`:
  `TestAGuestThatEndsEndsItsVMM` (the kernel's `reboot=k` and `panic=1`).

PostgreSQL tests:
- `internal/controlplane`: `TestAnAgentWhoseGuestKeepsFailingIsFailed`,
  `TestCrashesSpendTheRestartBudget`, `TestRestoresAndDeletionsAreNotHeld`,
  `TestAWakeOfAFailedAgentFails`, `TestAPersonsFailedAgent`.
- `internal/worker`: `TestGuestFailuresAreCountedAndLogged`.

KVM tests, which need root and a guest whose `capsule-echo` floods with
direct writes; both passed on November 17, 2026, with guest v26:
- `TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest`: a guest writes
  its volume with `O_DIRECT` as fast as it can, so that each write reaches
  the drive as requests of its own bytes, with no flush. Writing 1 MiB at a
  time, on a host capped at 4 MiB/s with room for 100,000 operations a
  second, its VMM moves at most 4 MiB/s. Writing 4 KiB at a time, on a host
  capped at 200 operations a second with room for 64 MiB/s, it makes at
  most 200 operations a second. Each check allows one second of bucket and a
  tenth more, and wants half the ceiling at least. Both are measured from the
  VMM's `/proc/<pid>/io`: the bytes it read and wrote (`rchar` and `wchar`),
  divided by 4096 for the operations. Each VMM's network namespace has
  loopback only. On November 17, 2026, the VMM moved 42,032,256 bytes in
  10 seconds writing 1 MiB at a time (4.0 MiB/s), and 2,000 operations in
  10 seconds writing 4 KiB at a time.
  Its first run counted the write calls (`syscw`) of a VMM whose guest wrote
  4 KiB through the page cache, each followed by `fdatasync`. That count is
  not the drive's operations: the VMM serves a flush with `fsync`, which is
  no write call, and signals each completed request with a write call to an
  eventfd. At 200 operations a second, half of them writes, that is about
  3000 calls in 10 seconds; the run found 3130, against a bound of 2640.
- `TestProductWorkerStopsBootingAGuestThatCrashesAtBoot`: the wake of a guest
  that crashes at boot ends `FAILED` after a budget of 3; further passes boot
  nothing while an invocation waits; a wake after the fix answers it. The
  passes that boot the crashing guest may fail only with the guest's boot
  failures, and those over the `FAILED` agent only with its held delivery.
  Its first run stopped at the first boot failure, which its passes did not
  accept.

KVM tests of the other ceilings of RUN-007, written on November 18, 2026,
never run (`internal/worker/product_hostile_integration_test.go`). Each
packs `capsule-echo` with a hostile behaviour, which turns 2 seconds after
the harness's first answer, and boots a well-behaved agent beside it, which
must still answer within 30 seconds from the same VMM:
- `TestProductWorkerCPUCeilingHoldsAgainstABurningGuest`: a guest burning
  its 2 vCPUs uses, over 10 seconds, at most its cgroup's `cpu.max` for the
  window, with one quota and a tenth more allowed, and at least half of it.
- `TestProductWorkerMemoryCeilingHoldsAgainstAGuestThatEatsMemory`: a guest
  of 256 MiB that eats memory is stopped by its own kernel ("Out of memory"
  on its console). Its VMM's cgroup records no OOM, and peaks under
  `memory.max` (512 MiB) and above 224 MiB. The guest then restarts, never
  halts: its VMM exits, the worker counts a crash of that boot, the agent
  reads `STOPPED`, and its next invocation boots it again and is answered.
- `TestProductWorkerProcessCeilingsHoldAgainstAForkBomb`: a fork bomb
  reaches the 256 processes of the guest's harness cgroup (its kernel
  refuses a fork in `/capsule-harness`), while the VMM's cgroup gets no new
  task, the agent's UID no new process on the host, and the VMM never
  reaches its own `pids.max`.
- `TestProductWorkerWorkTimeoutBoundsAGuestThatNeverFiles`: an invocation
  acknowledged "working" and never filed, with `work_timeout_seconds` 60,
  fails with `work_timeout` once its `result_due_at` has passed, not before,
  and has no result; the guest loops on within its `cpu.max`, and keeps its
  VM.

For question 6, written on November 18, 2026, never run, in the same file:
- `TestProductWorkerFailsAnAgentWhoseGuestKeepsCrashing`: an agent whose
  harness eats memory after each boot's first answer, with a budget of 2
  within an hour, answers, crashes, is booted again by its next invocation,
  answers and crashes again; each crash is counted for its own boot, and
  the agent is then `FAILED` with `failure_reason` `crashed`.

No guest halts in these tests: a console that shows `reboot: System
halted` fails them, and a VMM that went away must be counted as a crash.

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
6. **A guest that stops once ready.** An agent's harness takes all the
   guest's memory and the guest's kernel kills it. Before the decision the
   guest halted, its VM kept its slot and memory, the agent read `READY`
   then `STARTING`, its work waited until its deadline, and no failure was
   counted. Options: (a) as built, until someone puts the agent to sleep;
   (b) the guest reboots instead of powering off, which ends its VMM: the
   worker counts a crash, the next work boots it again, and 5 such crashes
   an hour make it `FAILED`; (c) (b), and the worker also treats a running
   VM whose control channel stops answering as crashed. Recommendation: (b)
   now, (c) later. **Decided: (b), product owner, November 18, 2026; built
   the same day** (see [What counts](#2-restart-budgets)). (c) stays a later
   item.
7. **A harness that never answers an invocation.** Its three attempts end
   at the host's timeout, but the invocation then waits for a fence the
   harness refuses, and the agent's other work waits behind it. Options:
   (a) as built, until someone puts the agent to sleep; (b) when a fence of
   a running VM fails past the attempts, the worker stops the VM, counts a
   guest failure and fences through a restricted boot. Recommendation: (b).
8. **A VM after its work timeout.** An agent answers "working" and never
   files. Its invocation fails with `work_timeout`, but its VM keeps
   running, and computing, until someone puts it to sleep, since no idle
   timeout is set by default. Options: (a) as built; (b) stop the VM at the
   work timeout; (c) a default idle timeout for every agent.
   Recommendation: (a) for the MVP, with the CPU ceiling bounding its cost;
   (c) later.
