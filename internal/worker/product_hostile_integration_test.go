//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// The KVM tests of RUN-007 beyond the drive ceilings: a guest whose harness
// turns hostile (cmd/capsule-echo/hostile.go) pushes against its VM's CPU,
// memory and process ceilings, or never files the outcome of its work. Each
// test reads what the host enforces from the hostile VMM's cgroup and the
// guest's console, and checks that a well-behaved agent beside it still
// answers. A guest whose harness dies crashes: it restarts, which ends its
// VMM, and its crashes spend its agent's restart budget (RUN-011).

const (
	// neighbourBound bounds how long the well-behaved agent may take to
	// answer beside a hostile one. With one VM on the host, a delivery to a
	// running agent took about half a second (docs/worker.md, capacity
	// benchmark).
	neighbourBound = 30 * time.Second
	// hostileTurn is how long after its first answer a hostile harness
	// turns (capsule-echo's hostileDelay).
	hostileTurn = 2 * time.Second
	// guestHalted is what a guest's kernel prints when it halts, which leaves
	// its VMM running. capsule-init never halts a guest: it restarts it,
	// which ends its VMM (guestinit.EndCommand, ADR 012 question 6). A
	// console that shows it fails the test.
	guestHalted = "reboot: System halted"
	// guestRestarted is what it prints when capsule-init restarts it.
	guestRestarted = "reboot: Restarting system"
)

// hostileScene is a registry lab with two agents, each in its own VM: a
// well-behaved neighbour on echo-oci 1.0.0, and a hostile agent on echo-oci
// 2.0.0, capsule-echo with a hostile behaviour.
type hostileScene struct {
	*registryLab
	neighbour, hostile string
	neighbourRun, run  runtime.VMRun
	// group is the hostile VMM's cgroup, and console its output, where the
	// guest's console is written.
	group, console string
}

func newHostileScene(t *testing.T, behaviour string, vcpus, memoryMiB int) *hostileScene {
	t.Helper()
	l := newRegistryLab(t)
	l.publish("1.0.0", "opt/echo")
	l.publishBehaviour("2.0.0", "opt/hostile", behaviour)
	s := &hostileScene{registryLab: l}
	s.neighbour = l.create("neighbour", "1.0.0").AgentID
	s.hostile = l.createSized("hostile", "echo-oci", "2.0.0", vcpus, memoryMiB).AgentID
	runs := l.runs(2)
	s.neighbourRun, s.run = runs[s.neighbour], runs[s.hostile]
	s.group = vmmCgroup(t, s.run.PID)
	s.console = filepath.Join(l.root, "logs", s.run.ID+".log")
	return s
}

// vmmCgroup is the directory of a running VMM's cgroup.
func vmmCgroup(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal("the VMM's cgroup", err)
	}
	dir, err := cgroupDir(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// cgroupFile reads one file of a cgroup.
func cgroupFile(t *testing.T, group, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(group, name))
	if err != nil {
		t.Fatal("the VMM's cgroup", name, err)
	}
	return strings.TrimSpace(string(raw))
}

// cgroupKeys reads a cgroup file of "key value" lines.
func cgroupKeys(t *testing.T, group, name string) map[string]int64 {
	t.Helper()
	keys, err := cgroupKeyed(cgroupFile(t, group, name))
	if err != nil {
		t.Fatal(name, err)
	}
	return keys
}

// cgroupValue reads a cgroup file of one number.
func cgroupValue(t *testing.T, group, name string) int64 {
	t.Helper()
	n, err := cgroupNumber(cgroupFile(t, group, name))
	if err != nil {
		t.Fatal(name, err)
	}
	return n
}

// cpuUsed is how much CPU a cgroup used over a window, and the window.
func cpuUsed(t *testing.T, group string, window time.Duration) (used, elapsed time.Duration, throttled int64) {
	t.Helper()
	before, start := cgroupKeys(t, group, "cpu.stat"), time.Now()
	time.Sleep(window)
	after, elapsed := cgroupKeys(t, group, "cpu.stat"), time.Since(start)
	return time.Duration(after["usage_usec"]-before["usage_usec"]) * time.Microsecond, elapsed, after["nr_throttled"] - before["nr_throttled"]
}

// placementGeneration is the generation of the agent's placement.
func (l *productPeerLab) placementGeneration(agent string) uint64 {
	l.t.Helper()
	var g int64
	if err := l.db.QueryRow(l.t.Context(), "SELECT generation FROM agent_placements WHERE agent_id=$1", agent).Scan(&g); err != nil {
		l.t.Fatal(err)
	}
	return uint64(g)
}

// guestFailures lists the guest failures recorded for the agent (ADR 012),
// as kind/generation.
func (l *productPeerLab) guestFailures(agent string) []string {
	l.t.Helper()
	rows, err := l.db.Query(l.t.Context(), "SELECT kind, generation FROM guest_failures WHERE agent_id=$1 ORDER BY generation", agent)
	if err != nil {
		l.t.Fatal(err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var kind string
		var generation int64
		if err = rows.Scan(&kind, &generation); err != nil {
			l.t.Fatal(err)
		}
		found = append(found, fmt.Sprintf("%s/%d", kind, generation))
	}
	if err = rows.Err(); err != nil {
		l.t.Fatal(err)
	}
	return found
}

// turn has the hostile agent answer its first invocation, from the VM under
// test; its harness turns hostileTurn later.
func (s *hostileScene) turn() {
	s.t.Helper()
	s.answers(s.hostile, "first-answer", "before turning")
	if g := s.placementGeneration(s.hostile); g != s.run.Generation {
		s.t.Fatal("the hostile agent answered from another boot", g, s.run.Generation)
	}
}

// neighbourAnswers checks that the well-behaved agent answers within
// neighbourBound, from the VMM it had: nothing on the host stopped it.
func (s *hostileScene) neighbourAnswers(key string) time.Duration {
	s.t.Helper()
	start := time.Now()
	s.answers(s.neighbour, key, "still answering")
	took := time.Since(start)
	if took > neighbourBound {
		s.t.Fatalf("the neighbour answered in %s; bound %s", took, neighbourBound)
	}
	if !sameProcess(s.neighbourRun.PID, s.neighbourRun.StartTicks) || s.placementGeneration(s.neighbour) != s.neighbourRun.Generation {
		s.t.Fatal("the neighbour's VM did not survive its hostile neighbour")
	}
	return took
}

// output is the hostile VMM's output so far: Firecracker's log and the
// guest's console.
func (s *hostileScene) output() string {
	s.t.Helper()
	raw, err := os.ReadFile(s.console)
	if err != nil {
		s.t.Fatal("the hostile VMM's output", err)
	}
	return string(raw)
}

// awaitConsole waits until the guest's console shows text, sampling the
// host meanwhile, for at most bound.
func (s *hostileScene) awaitConsole(text string, bound time.Duration, sample func()) {
	s.t.Helper()
	deadline := time.Now().Add(bound)
	for {
		if sample != nil {
			sample()
		}
		gone := !sameProcess(s.run.PID, s.run.StartTicks)
		out := s.output()
		switch {
		case strings.Contains(out, text):
			return
		case gone:
			s.t.Fatalf("the hostile VMM exited before its guest's console showed %q; its output ends with:\n%s", text, tail([]byte(out), 30))
		case time.Now().After(deadline):
			s.t.Fatalf("the guest's console did not show %q within %s; its output ends with:\n%s", text, bound, tail([]byte(out), 30))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// refuseHalt fails the test if a guest's console shows that it halted.
func refuseHalt(t *testing.T, console []byte) {
	t.Helper()
	if strings.Contains(string(console), guestHalted) {
		t.Fatalf("the guest halted, which leaves its VMM running; its output ends with:\n%s", tail(console, 30))
	}
}

// awaitVMMExit waits until the hostile VMM exits, for at most bound: its
// guest restarted, which ends the VMM. A guest that halts fails at once.
func (s *hostileScene) awaitVMMExit(bound time.Duration, sample func()) {
	s.t.Helper()
	for deadline := time.Now().Add(bound); sameProcess(s.run.PID, s.run.StartTicks); {
		out := []byte(s.output())
		refuseHalt(s.t, out)
		if time.Now().After(deadline) {
			s.t.Fatalf("the hostile VMM did not exit within %s; its output ends with:\n%s", bound, tail(out, 30))
		}
		if sample != nil {
			sample()
		}
		time.Sleep(50 * time.Millisecond)
	}
	out := s.output()
	s.t.Logf("the hostile VMM exited; its guest restarted: %v; capsule-init reported a failure: %v; its output ends with:\n%s",
		strings.Contains(out, guestRestarted), strings.Contains(out, "CAPSULE_INIT_FAILED"), tail([]byte(out), 12))
}

// aftermath checks what became of a hostile VM whose guest may have stopped.
// No guest halts: one that stops restarts, which ends its VMM, and a VMM
// that went away is a crash (crashed).
func (s *hostileScene) aftermath() {
	s.t.Helper()
	refuseHalt(s.t, []byte(s.output()))
	if sameProcess(s.run.PID, s.run.StartTicks) {
		s.t.Log("the hostile VMM still runs; agent state:", s.agentState(s.hostile), "; guest failures recorded:", s.guestFailures(s.hostile))
		return
	}
	s.crashed()
}

// crashed checks that the worker, at its next census, counts the exit of
// the hostile VMM as a crash of its boot, against the agent's restart
// budget, and that the agent is STOPPED (ADR 012).
func (s *hostileScene) crashed() {
	s.t.Helper()
	if _, err := s.worker.Reconcile(s.t.Context()); err != nil {
		s.t.Fatal(err)
	}
	if got := s.guestFailures(s.hostile); len(got) != 1 || got[0] != fmt.Sprintf("%s/%d", controlplane.GuestCrashed, s.run.Generation) {
		s.t.Fatal("the hostile VMM went away; guest failures recorded:", got)
	}
	if state := s.agentState(s.hostile); state != "STOPPED" {
		s.t.Fatal("the agent whose VMM went away reads", state)
	}
}

// A guest that keeps every vCPU busy stays within its plan's CPU ceiling
// (RUN-007): cpu.max, the VM's vCPUs times 100 ms every 100 ms (ADR 012).
// The VM has 2 vCPUs and its guest burns both. Over floodWindow, once the
// guest burns, its VMM's cgroup uses at most its ceiling for the window
// (cpuCeiling: one quota and a tenth more are allowed), and at least half
// its vCPUs' time, so that a guest that does not burn fails. A well-behaved
// agent beside it answers within neighbourBound, from the same VMM, and the
// burning VM is not stopped: the ceiling slows it, nothing else.
func TestProductWorkerCPUCeilingHoldsAgainstABurningGuest(t *testing.T) {
	const vcpus = 2
	s := newHostileScene(t, "burn-cpu", vcpus, 256)
	cpuMax := cgroupFile(t, s.group, "cpu.max")
	if cpuMax != fmt.Sprintf("%d 100000", vcpus*100000) {
		t.Fatal("the VMM's cpu.max is not its plan's", cpuMax)
	}
	idle := s.neighbourAnswers("beside-an-idle-agent")
	s.turn()
	time.Sleep(hostileTurn + floodWarmup)
	used, elapsed, throttled := cpuUsed(t, s.group, floodWindow)
	ceiling, err := cpuCeiling(cpuMax, elapsed)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a guest burning %d vCPUs: %s of CPU in %s, ceiling %s, %d periods throttled", vcpus, used, elapsed, ceiling, throttled)
	if used > ceiling || used < elapsed*vcpus/2 {
		t.Fatalf("a guest burning %d vCPUs used %s of CPU in %s; ceiling %s, and at least %s expected",
			vcpus, used, elapsed, ceiling, elapsed*vcpus/2)
	}
	busy := s.neighbourAnswers("beside-a-burning-agent")
	t.Log("the neighbour answered in", idle, "beside an idle agent, and in", busy, "beside a burning one")
	if !sameProcess(s.run.PID, s.run.StartTicks) {
		t.Fatal("the burning VM stopped")
	}
}

// A guest that takes memory without end cannot take the host's (RUN-007):
// its VM has its plan's memory, and its VMM's cgroup allows 256 MiB more
// for the VMM, with no swap (memory.max, ADR 012). The guest's own kernel
// kills the harness (its console shows "Out of memory"). The host's ceiling
// never acts: the cgroup records no OOM, and its peak stays under
// memory.max while reaching 7/8 of the VM's memory, so that a guest that
// does not fill its memory fails. A well-behaved agent beside it answers,
// from the same VMM.
//
// The guest then crashes (ADR 012, question 6): capsule-init restarts it,
// which ends its VMM, never halts it. The worker counts a crash of that
// boot, the agent is STOPPED, and its next work boots it again: it answers.
func TestProductWorkerMemoryCeilingHoldsAgainstAGuestThatEatsMemory(t *testing.T) {
	const memoryMiB = 256
	s := newHostileScene(t, "eat-memory", 1, memoryMiB)
	ceiling := cgroupValue(t, s.group, "memory.max")
	if ceiling != (memoryMiB+256)<<20 {
		t.Fatal("the VMM's memory.max is not its plan's memory and 256 MiB", ceiling)
	}
	// memory.peak, where the kernel has it, keeps the highest charge; the
	// samples are for a kernel without it.
	var sampled int64
	sample := func() {
		if raw, err := os.ReadFile(filepath.Join(s.group, "memory.current")); err == nil {
			if n, err := cgroupNumber(string(raw)); err == nil {
				sampled = max(sampled, n)
			}
		}
	}
	s.turn()
	s.awaitConsole("Out of memory", 90*time.Second, sample)
	s.awaitVMMExit(60*time.Second, sample)
	// The VMM's cgroup stays until the worker retires its boot, at its next
	// census, which no step has run yet.
	peak := sampled
	if raw, err := os.ReadFile(filepath.Join(s.group, "memory.peak")); err == nil {
		if n, err := cgroupNumber(string(raw)); err == nil {
			peak = max(peak, n)
		}
	}
	events := cgroupKeys(t, s.group, "memory.events")
	t.Logf("a guest eating memory: its VMM's cgroup peaked at %d MiB (memory.max %d MiB); events %v", peak>>20, ceiling>>20, events)
	if events["oom"] != 0 || events["oom_kill"] != 0 {
		t.Fatal("the host's memory ceiling had to act on the VMM", events)
	}
	if peak > ceiling || peak < (memoryMiB<<20)*7/8 {
		t.Fatalf("the VMM's cgroup peaked at %d MiB; expected between %d MiB and its memory.max, %d MiB", peak>>20, memoryMiB*7/8, ceiling>>20)
	}
	s.neighbourAnswers("beside-a-crashed-agent")
	s.crashed()
	// The next work boots the agent again, and it answers from a new boot.
	s.answers(s.hostile, "after-the-crash", "booted again")
	if g := s.placementGeneration(s.hostile); g <= s.run.Generation {
		t.Fatal("the agent answered from the boot that crashed", g, s.run.Generation)
	}
}

// A guest whose harness dies each time it is ready crashes each time (ADR
// 012, question 6): capsule-init restarts the guest, which ends its VMM, the
// worker counts a crash of that boot at its next census, and the next work
// boots the agent again. Once its crashes spend the agent's restart budget,
// here 2 within an hour, the agent is FAILED with failure_reason crashed.
// The harness eats memory 2 seconds after each boot's first answer, until
// the guest's kernel kills it.
func TestProductWorkerFailsAnAgentWhoseGuestKeepsCrashing(t *testing.T) {
	l := newRegistryLab(t)
	if err := l.worker.SetRestartBudget(controlplane.RestartBudget{Failures: 2, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	l.publishBehaviour("1.0.0", "opt/hostile", "eat-memory")
	agent := l.create("crashing", "1.0.0").AgentID
	var crashes []string
	for i := range 2 {
		// The first boot is the agent's wake; the second, this work's.
		l.answers(agent, fmt.Sprintf("before-crash-%d", i), "answers before its harness dies")
		var generation int64
		var vm string
		if err := l.db.QueryRow(t.Context(), "SELECT generation,vm_id FROM agent_placements WHERE agent_id=$1 AND state='RUNNING'",
			agent).Scan(&generation, &vm); err != nil {
			t.Fatal("the boot that answered", err)
		}
		crashes = append(crashes, fmt.Sprintf("%s/%d", controlplane.GuestCrashed, generation))
		console := filepath.Join(l.root, "logs", vm+".log")
		for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(250 * time.Millisecond) {
			if _, err := l.worker.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			got := l.guestFailures(agent)
			if slices.Equal(got, crashes) {
				break
			}
			out, _ := os.ReadFile(console)
			refuseHalt(t, out)
			if len(got) >= len(crashes) || time.Now().After(deadline) {
				t.Fatalf("guest failures recorded %v, expected %v; the guest's output ends with:\n%s", got, crashes, tail(out, 30))
			}
		}
		if state := l.agentState(agent); i == 0 && state != "STOPPED" {
			t.Fatal("the agent after its first crash reads", state)
		}
	}
	var v controlplane.TenantAgent
	l.request(l.owner(), "GET", "/v1/agents/"+agent, "", nil, 200, &v)
	if v.State != "FAILED" || v.FailureReason == nil || *v.FailureReason != "crashed" {
		t.Fatal("the agent after its budget", v.State, v.FailureReason)
	}
}

// A fork bomb inside a guest creates no process on the host (RUN-007): the
// guest's processes are its kernel's, and the host bounds the VMM's own
// tasks with pids.max = 32 (ADR 012). Inside the guest, the harness's cgroup
// allows 256 processes (capsule-init), and the guest's console shows its
// kernel refusing a fork in /capsule-harness: the bomb reached the guest's
// ceiling. Until then, and for 5 seconds after, the VMM's cgroup has no
// more tasks than before the bomb, and the agent's UID runs no more
// processes on the host; the VMM never reached its own pids.max. A
// well-behaved agent beside it answers, from the same VMM.
func TestProductWorkerProcessCeilingsHoldAgainstAForkBomb(t *testing.T) {
	s := newHostileScene(t, "fork-bomb", 1, 256)
	if got := cgroupValue(t, s.group, "pids.max"); got != 32 {
		t.Fatal("the VMM's pids.max", got)
	}
	tasks := cgroupValue(t, s.group, "pids.current")
	uid := s.hostAgentUID(s.hostile)
	processes := len(runsAs(t, uid))
	if tasks < 1 || processes < 1 {
		t.Fatal("the running VMM has", tasks, "tasks and", processes, "processes")
	}
	check := func() {
		if n := cgroupValue(t, s.group, "pids.current"); n > tasks {
			t.Fatalf("the VMM's cgroup has %d tasks, %d before the fork bomb", n, tasks)
		}
		if n := len(runsAs(t, uid)); n > processes {
			t.Fatalf("the agent's UID runs %d processes on the host, %d before the fork bomb", n, processes)
		}
	}
	s.turn()
	s.awaitConsole("fork rejected by pids controller in /capsule-harness", 60*time.Second, check)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		check()
	}
	if events := cgroupKeys(t, s.group, "pids.events"); events["max"] != 0 {
		t.Fatal("the VMM reached its own pids.max", events)
	}
	t.Log("a fork bomb at the guest's ceiling: the VMM kept", tasks, "tasks and its UID", processes, "processes")
	s.neighbourAnswers("beside-a-fork-bomb")
	s.aftermath()
}

// An agent that answers "working", then loops forever on its invocation and
// never files the outcome, is bounded by the invocation's work_timeout
// (docs/api/agents-assignments.md, the "working" state): once its
// result_due_at, the acknowledgment plus work_timeout_seconds, has passed,
// and not before, the invocation fails with work_timeout and has no result.
// The guest goes on looping, within its CPU ceiling. The platform does not
// stop its VM for it, nor count a guest failure: no document says it does.
func TestProductWorkerWorkTimeoutBoundsAGuestThatNeverFiles(t *testing.T) {
	l := newRegistryLab(t)
	l.publishBehaviour("1.0.0", "opt/loop", "never-files")
	agent := l.create("looping", "1.0.0").AgentID
	run := l.runs(1)[agent]
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "never-files", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "work on this forever"}}, "work_timeout_seconds": 60}, 202, &inv)
	read := func() controlplane.Invocation {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		return v
	}
	var v controlplane.Invocation
	l.await("the working acknowledgment", true, func() bool {
		v = read()
		if v.State != "accepted" && v.State != "working" {
			t.Fatal("the invocation before its acknowledgment", v.State, v.ErrorCode)
		}
		return v.State == "working"
	})
	if v.ResultDueAt == nil {
		t.Fatal("a working invocation without result_due_at")
	}
	due := *v.ResultDueAt
	if wait := due.Sub(v.CreatedAt); wait < time.Minute || wait > 2*time.Minute {
		t.Fatal("result_due_at is not the acknowledgment plus 60 s", wait)
	}
	l.awaitFor("the work timeout", true, time.Until(due)+time.Minute, func() bool {
		v = read()
		switch v.State {
		case "working":
			return false
		case "failed":
			return true
		}
		t.Fatal("the invocation never filed", v.State, v.ErrorCode)
		return false
	})
	if v.ErrorCode != "work_timeout" || v.CompletedAt == nil || v.CompletedAt.Before(due) || v.ResultAvailable {
		t.Fatal("the invocation after its work timeout", v.ErrorCode, v.CompletedAt, due, v.ResultAvailable)
	}
	t.Log("failed with work_timeout", v.CompletedAt.Sub(due), "after its result_due_at")
	group := vmmCgroup(t, run.PID)
	used, elapsed, _ := cpuUsed(t, group, 3*time.Second)
	ceiling, err := cpuCeiling(cgroupFile(t, group, "cpu.max"), elapsed)
	if err != nil {
		t.Fatal(err)
	}
	if used > ceiling || used < elapsed/2 {
		t.Fatalf("the guest looping on its invocation used %s of CPU in %s; ceiling %s, and at least %s expected", used, elapsed, ceiling, elapsed/2)
	}
	if !sameProcess(run.PID, run.StartTicks) || l.placementGeneration(agent) != run.Generation {
		t.Fatal("the VM of the agent that never filed was stopped")
	}
	if got := l.guestFailures(agent); len(got) != 0 {
		t.Fatal("guest failures recorded", got)
	}
}
