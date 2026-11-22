# CAP-03 — Disk ceilings, restart budgets and egress

Date: November 16, 2026. **Status: built on November 16, 2026**, with
defaults pending the product owner (see [Questions](#questions-for-the-product-owner)).
The KVM tests that prove the drive ceilings and the budget on a real VM
passed on November 17, 2026, after a first run that day failed on faults of
the tests (see [Tests](#tests)). The KVM tests of the CPU, memory, process
and time ceilings against a hostile guest, written on November 18, 2026,
passed on KVM that day at 5906a12 with guest v27, on their first run. The
KVM tests of a guest that keeps crashing (question 6) and of a guest that
never answers (question 7) failed in their first run, with guest v28, on
faults fixed since; they passed on KVM later that day at 0ff9ec2 with guest
v29, and so did the test of deleting an agent whose harness never answers
(question 7, sub-question 2), on its first run.
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
| A corpus image ([ADR 023](023-corpora.md)) | 128 MiB/s | 4000/s | the image's size, at most 256 MiB: a corpus of several GiB is read on demand |
| A corpus build's drives (the builder's source, LFS objects and output) | the volume's | the volume's | none |

These are defaults, **pending the product owner**. The operator sets others
per host in the worker's configuration (`drive_limits`: `volume`, `harness`
and `corpus`), from 1 MiB/s to
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

**An unresponsive guest** is a third guest failure (question 7, decided on
November 18, 2026, option (b), built the same day). A harness that never
returns from an invocation holds its store's write transaction: each of the
invocation's three attempts ends at the host's 20-second timeout, or when
the guest answers that its store is busy, and the fence that must precede
the invocation's death cannot commit. Before, the invocation never ended and
the agent's later deliveries waited behind it. Now:
- *Past the attempts* means that the agent's mailbox is held by its head
  delivery: pending, an attempt may have reached it, no attempt is under way
  (no live lease), and it can no longer be attempted (its three attempts are
  spent, its deadline passed, or its retirement began). These are the
  delivery's own counters (`attempts`, `attempt_limit`, `expires_at`,
  `may_have_reached`, `closing`); no timer is added
  (`deliveryStuck`, `internal/controlplane/unresponsive_guests.go`).
- When the retirement of such a delivery (an invocation, a reply or a
  status), or the closure of a request, fences that agent's store and the
  guest of its running VM refuses, the worker stops that VM the way a sleep
  does: a quiesce, then the VMM's forced removal
  (`StopUnresponsiveGuest`, `internal/worker/unresponsive_linux.go`). It
  records a guest failure of kind `unresponsive` for that boot, which counts
  against the restart budget like the others. The fence is then tried
  again: with no VM running, it goes through a restricted boot, whose
  harness serves fences and refuses work. The invocation ends with its
  documented state, `failed`, `delivery_outcome_unknown`, and the agent's
  next delivery boots it again for work.
- *The guest refuses* only when, while the worker still waits, the guest
  answered that it could not fence (its error codes, a busy store's
  `unavailable` among them) or nothing answered before the RPC's own
  20-second timeout. A refusal is never inferred from the platform: the
  worker's own deadline, a connection the host could not open or that a VMM
  gone refused (reconciliation counts that as a crash), an authority or
  PostgreSQL, which fail with other errors, nor a restricted boot
  (`unresponsiveGuest`). A guest that refuses while an attempt is under way,
  or while its mailbox holds nothing past its attempts, is not stopped: the
  fence is tried again later, as before.
- If this failure makes the agent `FAILED`, the restricted boot is not
  claimed either: the invocation waits, closing, until a wake gives the
  agent a new budget, as for any barrier of a `FAILED` agent.
- *Deleting such an agent* (sub-question 2 of question 7, decided (b) on
  November 18, 2026, built the same day). The deletion fences the subject
  `agent/<id>` in every store, the agent's own among them. Before, its
  guest refused that fence, the deletion's job failed and tried again,
  forever: the retirement above leaves a delivery to an agent being deleted
  to the deletion, and nothing else stopped the VM. Now, when the deleted
  agent's own running guest refuses the deletion's fence, the worker stops
  its VM in the same way and the fence goes through a restricted boot
  (`fenceDeletion`, `internal/controlplane/unresponsive_guests.go`). No
  delivery need be past its attempts: the deletion cancels all of the
  agent's work, and no attempt begins once it is requested. The deletion
  then goes on as any other: the seal, the key destroyed, the volume
  removed, `DELETED`; the held invocation ends `canceled`
  (`agent_unavailable`). The stop records no guest failure: the agent is
  not live, so the restart budget is moot, and the agent is never `FAILED`
  by its deletion; the worker's metric still counts the stop as
  `unresponsive`. A platform fault stops nothing, and the deletion tries
  again. The deletion's fence of another agent's store is unchanged: that
  agent is live, and its guest is stopped only past a delivery's attempts.
- A guest whose control channel no longer answers its health probe is not
  covered: it is question 6 (c).

**The budget.** Each failure is recorded once, keyed by its boot generation,
in the transaction that publishes the retired generation `STOPPED`
(migration 0031, `ObserveGuestFailure`). When an agent has had **5 failures
within an hour** (default, **pending the product owner**; `restart_budget`
in the worker's configuration, 1 to 100 within 1 minute to 24 hours), it is
**`FAILED`**. Boot failures, crashes and unresponsive guests count
together. The reason is the kind of the last failure: `boot_failed`,
`crashed` or `unresponsive` (migration 0047 adds the third). The agent
views show `state: FAILED` and `failure_reason`.

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
  transaction. Each attempt ends at the host's 20-second timeout, and the
  fence that ends the invocation after its third attempt is refused: the
  worker stops the VM, counts an `unresponsive` failure, and fences through
  a restricted boot (question 7, option (b)). The invocation fails with
  `delivery_outcome_unknown` about two minutes after it was sent, with the
  default 30-second delivery lease, and the agent's next delivery boots it
  again. What the held handler wrote is lost with its transaction. A guest
  starved by its host could be counted wrongly; the budget allows 5 an hour.
  The harness keeps running meanwhile: its background work waits out the
  held store instead of ending the harness, which would end the guest and
  count a crash (question 6). Its owner can delete the agent at any time:
  the deletion stops the VM the same way, without counting a failure.

## Tests

Unit tests (`go test -race`):
- `internal/runtime`: `TestDrivesHaveIOCeilings`, `TestDriveLimitsAreBounded`,
  `TestGuestsHaveNoNetwork`, `TestBootFailureIsTheGuestsOnlyWhenTheGuestFailed`,
  `TestControlAnswers`, `TestCorpusDrivesFollowTheHarnessInBindingOrder`,
  `TestTheCorpusBurstIsCapped`, `TestDriveLimitsHaveACorpusRate`.
- `internal/worker`: `TestRestartBudgetAndDriveLimitsConfiguration`, `TestCorpusDriveLimitsConfiguration`,
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
- For an unresponsive guest (question 7): `internal/worker`:
  `TestOnlyAGuestThatDoesNotAnswerItsFenceIsUnresponsive`,
  `TestPassesOfAGuestThatNeverAnswers`; `cmd/capsule-echo`:
  `TestNeverReturnsHoldsItsStoreUntilTheHarnessStops` (a real store: a
  fence cannot commit while the handler holds it, past the request's own
  deadline); `internal/harnessstore`: `TestBusyTellsAHeldStore`;
  `internal/referenceharness` and `internal/agentadapter`:
  `TestRunWaitsOutABusyStore` (the background loop outlives a store held
  past its busy timeout; it ended there before).

PostgreSQL tests:
- `internal/controlplane`: `TestAnAgentWhoseGuestKeepsFailingIsFailed`,
  `TestCrashesSpendTheRestartBudget`, `TestRestoresAndDeletionsAreNotHeld`,
  `TestAWakeOfAFailedAgentFails`, `TestAPersonsFailedAgent`.
- `internal/worker`: `TestGuestFailuresAreCountedAndLogged`.
- For an unresponsive guest (question 7), each failing before the change:
  `internal/controlplane`:
  `TestAHarnessThatNeverAnswersIsStoppedAndItsInvocationEnds` (a handler
  holds a real SQLite store; three attempts; the invocation behind waits; a
  platform fault on the fence stops nothing; the refused fence stops the
  VM, records `unresponsive` for its generation, fences through a
  restricted boot; the invocation fails with `delivery_outcome_unknown`;
  the held effect never committed; the next invocation is answered by a
  new boot), `TestAnUnresponsiveGuestSpendsTheRestartBudget` (`FAILED`,
  reason `unresponsive`, the invocation waits for a wake),
  `TestAReplyPastItsAttemptsStopsTheGuestThatRefusesItsFence`,
  `TestARequestPastItsAttemptsStopsOnlyTheGuestItHolds`,
  `TestOnlyAFencePastTheAttemptsStopsAGuest`; `internal/worker`:
  `TestAnUnresponsiveGuestIsStoppedAndCounted`.
- For deleting a stuck agent (sub-question 2), in `internal/controlplane`:
  `TestDeletingAnAgentWhoseHarnessHoldsItsStoreCompletes` (a handler holds
  a real SQLite store; a platform fault on the deletion's fence stops
  nothing; the refused fence stops the VM and fences through a restricted
  boot; the deletion is tombstoned; the held invocation is canceled; no
  guest failure, with a budget of one) and
  `TestADeletionStopsOnlyTheGuestOfTheAgentItDeletes` (another agent's
  refusal stops nothing and the deletion waits for it), both failing
  before the change; `TestOnlyTheDeletedAgentsRefusedFenceStopsItsGuest`
  (unit, new with `fenceDeletion`); `TestAnOrdinaryDeletionStopsNoGuest`
  (unchanged behaviour, passing before too). In `internal/worker`:
  `TestAGuestStoppedForItsAgentsDeletionSpendsNoBudget` (the stop of an
  agent being deleted records no failure, the restricted boot can be
  claimed, the metric counts it; the rule of `ObserveGuestFailure`, which
  passed before too).

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

KVM tests of the other ceilings of RUN-007, written on November 18, 2026
(`internal/worker/product_hostile_integration_test.go`), passed on KVM that
day, on their first run, at 5906a12 with guest v27
(`quint/results/product-guest-kvm-20261118T090505Z`). Each packs
`capsule-echo` with a hostile behaviour, which turns 2 seconds after the
harness's first answer, and boots a well-behaved agent beside it, which
must still answer within 30 seconds from the same VMM:
- `TestProductWorkerCPUCeilingHoldsAgainstABurningGuest`: a guest burning
  its 2 vCPUs uses, over 10 seconds, at most its cgroup's `cpu.max` for the
  window, with one quota and a tenth more allowed, and at least half of it.
  On November 18, 2026, it used 19.99 s of CPU in 10.0 s against a ceiling
  of 22.2 s, and 2 periods were throttled; the neighbour answered in 0.72 s
  beside an idle agent and in 0.58 s beside the burning one.
- `TestProductWorkerMemoryCeilingHoldsAgainstAGuestThatEatsMemory`: a guest
  of 256 MiB that eats memory is stopped by its own kernel ("Out of memory"
  on its console). Its VMM's cgroup records no OOM, and peaks under
  `memory.max` (512 MiB) and above 224 MiB. The guest then restarts, never
  halts: its VMM exits, the worker counts a crash of that boot, the agent
  reads `STOPPED`, and its next invocation boots it again and is answered.
  On November 18, 2026, at 5906a12, the cgroup peaked at 263 MiB, with
  `oom` and `oom_kill` at 0. That version of the test only logged what
  followed, the behaviour before question 6: the guest halted, its VMM kept
  running, the agent read `READY`, and no failure was counted. In the run at
  03eaf46 with guest v28 (`product-guest-kvm-20261118T102825Z`), the test as
  written here passed: the guest restarted, its VMM exited, one crash was
  counted, and a new boot answered.
- `TestProductWorkerProcessCeilingsHoldAgainstAForkBomb`: a fork bomb
  reaches the 256 processes of the guest's harness cgroup (its kernel
  refuses a fork in `/capsule-harness`), while the VMM's cgroup gets no new
  task, the agent's UID no new process on the host, and the VMM never
  reaches its own `pids.max`. On November 18, 2026, the VMM kept its 3 tasks
  and the agent's UID its 1 process.
- `TestProductWorkerWorkTimeoutBoundsAGuestThatNeverFiles`: an invocation
  acknowledged "working" and never filed, with `work_timeout_seconds` 60,
  fails with `work_timeout` once its `result_due_at` has passed, not before,
  and has no result; the guest loops on within its `cpu.max`, and keeps its
  VM. On November 18, 2026, it failed 47 ms after its `result_due_at`.

For question 6, written on November 18, 2026, in the same file:
- `TestProductWorkerFailsAnAgentWhoseGuestKeepsCrashing`: an agent whose
  harness eats memory after each boot's first answer, with a budget of 2
  within an hour, answers, crashes, is booted again by its next invocation,
  answers and crashes again; each crash is counted for its own boot, and
  the agent is then `FAILED` with `failure_reason` `crashed`. Its first
  run, with guest v28 at 03eaf46, failed at a census during the first
  crash: `VMM does not own the required writable-volume flock`. Firecracker
  closes the volume, and so releases its lock, 59 to 110 ms before its
  process ends, and the census took it for a VMM that writes without its
  lock. A census now finds a VMM with no descriptor of its volume gone
  (8e61c85, [worker.md](../worker.md#limits-and-restart-budgets)). Passed
  on KVM on November 18, 2026, at 0ff9ec2 with guest v29.

No guest halts in these tests: a console that shows `reboot: System
halted` fails them, and a VMM that went away must be counted as a crash.

The KVM test of an unresponsive guest (question 7), written on November 18,
2026 (`internal/worker/product_unresponsive_integration_test.go`), packs
`capsule-echo` with `never-returns`, which holds any invocation whose text
says "never return" and answers the others. Its first run, that day with
guest v28, failed: the guest failures were `crash` for three boots, not
`unresponsive`. Each boot that held the store ended on its own 5 seconds
later: the reference harness's background loop, refused by the held store
after SQLite's busy timeout, ended the harness, and the guest ended with it
(question 6), so the census rightly counted a crash, and the retirement's
fence went to a new boot that answered it. The harness, not the
classification, was wrong: a store held by a slow or stuck handler is
transient, and the background loops of `capsule-echo` and `capsule-adapter`
now wait it out (`harnessstore.Busy`). Passed on KVM on November 18,
2026, at 0ff9ec2 with guest v29:
- `TestProductWorkerStopsAGuestThatNeverAnswersAnInvocation`: the agent
  answers an ordinary invocation, then gets one it holds and one more
  behind it. The passes may fail only with the held invocation's attempts,
  its live lease and the invocation waiting behind it. The held invocation
  fails with `delivery_outcome_unknown` and `attempts_exhausted` within 4
  minutes; one `unresponsive` failure is recorded for the boot that held
  it; its VMM is gone; the next invocation is answered by the release
  booted again, after one restricted boot; the agent reads `READY`.
  At 0ff9ec2, the held invocation failed after 1 min 55 s, and 10 passes
  failed on its attempts.

The KVM test of deleting a stuck agent (sub-question 2), written on
November 18, 2026
(`internal/worker/product_stuck_deletion_integration_test.go`), uses the
same behaviour, already in guest v29. It passed on KVM on its first run,
on November 18, 2026, at 0ff9ec2 with guest v29:
- `TestProductWorkerDeletesAnAgentWhoseHarnessNeverAnswers`: the agent
  answers an ordinary invocation, then holds one whose first attempt ends
  at the host's timeout. The owner deletes it: new work is refused and its
  Directory record is withdrawn (through the publisher, to records the
  test keeps; the private Directory is the deletion test's). The passes
  may fail only with the held delivery, refused for an agent being
  deleted. Within 2 minutes the deletion completes: one restricted boot
  after the stop, no VMM, no volume, the key revoked and destroyed under
  the seal the authority service holds, no record; the held invocation
  is `canceled` (`agent_unavailable`); no guest failure is recorded.
  At 0ff9ec2, the deletion completed 7.8 s after its request.

The campaign at 0ff9ec2 with guest v29
(`quint/results/product-guest-kvm-20261118T134036Z`) passed every KVM test
of this section, on the development machine (WSL2). Its numbers for the tests
of the other ceilings: the burning guest used 19.99 s of CPU in 10.0 s
against a ceiling of 22.2 s, 9 periods throttled, and the neighbour
answered in 0.42 s beside an idle agent and 0.41 s beside the burning one;
the memory test's cgroup peaked at 262 MiB, with `oom` and `oom_kill` at 0,
then its guest restarted, its VMM exited, one crash was counted and a new
boot answered; the fork bomb left the VMM its 3 tasks and the agent's UID
its 1 process; the invocation never filed failed 27 ms after its
`result_due_at`; the agent whose guest keeps crashing was `FAILED`
(`crashed`) after its two crashes.

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
   the same day** (see [What counts](#2-restart-budgets)); passed on KVM the
   same day, at 0ff9ec2 with guest v29 ([Tests](#tests)). (c) stays a later
   item.
7. **A harness that never answers an invocation.** Its three attempts end
   at the host's timeout, but the invocation then waits for a fence the
   harness refuses, and the agent's other work waits behind it. Options:
   (a) as built, until someone puts the agent to sleep; (b) when a fence of
   a running VM fails past the attempts, the worker stops the VM, counts a
   guest failure and fences through a restricted boot. Recommendation: (b).
   **Decided: (b), product owner, November 18, 2026**; built the same day
   (§2, "An unresponsive guest"), with the failure kind `unresponsive`;
   passed on KVM the same day, at 0ff9ec2 with guest v29.
   Its sub-question 2, **deleting a stuck agent**: an owner deletes an
   agent whose harness holds its store. Options: (a) as built then, the
   deletion waits; (b) the same stop for the deletion's fence.
   Recommendation: (b) later, with its own test. **Decided: (b), product
   owner, November 18, 2026** (the product owner asked to follow the
   recommendations); built the same day (§2, "Deleting such an agent");
   passed on KVM the same day, at 0ff9ec2 with guest v29.
8. **A VM after its work timeout.** An agent answers "working" and never
   files. Its invocation fails with `work_timeout`, but its VM keeps
   running, and computing, until someone puts it to sleep, since no idle
   timeout is set by default. Options: (a) as built; (b) stop the VM at the
   work timeout; (c) a default idle timeout for every agent.
   Recommendation: (a) for the MVP, with the CPU ceiling bounding its cost;
   (c) later.

## Changes after the v0.1.0 audit

**Lot SEC-2 (finding S-11).** The guest's model calls went through the
platform, but a forwarded request could ask the organization's provider to
run a tool of its own (web search or fetch, code execution, an MCP
connector): the provider then reached addresses the guest chose, outside
§3's closed profile. The gateway now refuses such tools, and the options that
change a call's price, before any reservation, unless the organization allows
them on an alias ([ADR 011](011-llm-access-and-cost-budgets.md#changes-after-the-v010-audit),
[api/llm.md](../api/llm.md#request-policy)). An organization that allows one
accepts that its provider fetches on its agents' behalf.

**PERF-1 (S-20).** The VMM's standard output and error went to
`<root>/logs/<run>.log` with the guest's serial console, unbounded and never
removed. The host now cuts that log once it passes 1 MiB (within a second),
removes it with its run, and the census and `-collect-garbage` remove the
logs of runs that are gone. In production the guest has no serial console
(`8250.nr_uarts=0`, no `console=ttyS0`): nothing it prints reaches the host.
`vm_serial_console`, or development mode, gives it one for debugging, and the
host then keeps the logs of the 16 runs that ended last. The KVM campaigns
enable it, since the tests above read what a guest printed; the jail test
runs as production.
