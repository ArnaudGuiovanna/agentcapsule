//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// labProvisioning, when set, adjusts the UID range of the next product lab's
// worker: the benchmark needs one UID per agent.
var labProvisioning func(*ProvisioningConfig)

// userHZ is the unit of the CPU times in /proc: USER_HZ, 100 on Linux.
const userHZ = 100

// TestCapacityBenchmark measures the capacity starting points (DEP-5,
// OPS-03) on a KVM host: for each number of agents of
// AGENTCAPSULE_KVM_CAPACITY_AGENTS (1,5,10,20 by default), it boots that many
// VMs of the reference harness and measures each boot, each VMM's resident
// memory, the host's memory and CPU with the VMs idle, the time to each
// first answer, and the wake from STOPPED to an answer. It writes the JSON
// report to AGENTCAPSULE_KVM_CAPACITY_REPORT after every step, and the
// worker's spans beside it. scripts/verify-product-guest.py runs it with
// --capacity-agents. A step whose VMs would not fit in the host's available
// memory, with 1 GiB to spare, is recorded as not run. With
// AGENTCAPSULE_KVM_CAPACITY_DRY_RUN=1 nothing boots: the report says which
// steps would fit, so that a run can be prepared without KVM.
func TestCapacityBenchmark(t *testing.T) {
	path := os.Getenv("AGENTCAPSULE_KVM_CAPACITY_REPORT")
	if path == "" {
		// Run on demand only (scripts/verify-product-guest.py --capacity-agents).
		return
	}
	sizes, err := capacitySizes(os.Getenv("AGENTCAPSULE_KVM_CAPACITY_AGENTS"))
	if err != nil {
		t.Fatal(err)
	}
	memory := 256
	if v := os.Getenv("AGENTCAPSULE_KVM_CAPACITY_MEMORY_MIB"); v != "" {
		if memory, err = strconv.Atoi(v); err != nil || memory < 128 || memory > 8192 {
			t.Fatal("AGENTCAPSULE_KVM_CAPACITY_MEMORY_MIB: 128 to 8192")
		}
	}
	idleWindow := 5 * time.Second
	if v := os.Getenv("AGENTCAPSULE_KVM_CAPACITY_IDLE"); v != "" {
		if idleWindow, err = time.ParseDuration(v); err != nil || idleWindow < time.Second || idleWindow > 5*time.Minute {
			t.Fatal("AGENTCAPSULE_KVM_CAPACITY_IDLE: 1s to 5m")
		}
	}
	host, err := readHostSample()
	if err != nil {
		t.Fatal(err)
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	report := capacityReport{Schema: capacitySchema, Started: time.Now().UTC(),
		Host:   capacityHost{CPUs: goruntime.NumCPU(), MemTotalMiB: round(host.totalMemoryMB), Kernel: strings.TrimSpace(string(kernel))},
		Config: capacityConfig{Sizes: sizes, VCPUs: 1, MemoryMiB: memory, DataVolumeMiB: 128, Harness: "reference 1.0.0", IdleWindow: idleWindow.String()},
		Steps:  []capacityStep{}}
	save := func() {
		if err := writeCapacityReport(path, report); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("AGENTCAPSULE_KVM_CAPACITY_DRY_RUN") == "1" {
		// Without KVM: the configuration, the host's readings and the
		// report, each step saying whether it would fit. Nothing boots.
		for _, n := range sizes {
			step := capacityStep{Agents: n, Status: "not_run", Reason: "dry run"}
			if !enoughMemory(host.available, n, memory) {
				step.Reason = fmt.Sprintf("dry run; %.0f MiB available, %d needed", host.available, n*memory+capacityHeadroomMiB)
			}
			report.Steps = append(report.Steps, step)
		}
		finished := time.Now().UTC()
		report.Finished = &finished
		save()
		return
	}
	save()
	most := sizes[len(sizes)-1]
	labRuntimeOptions = func(o *runtime.FirecrackerOptions) { o.MaxActive = most }
	labProvisioning = func(p *ProvisioningConfig) { p.FirstUID, p.LastUID = 62600, 62600+uint32(most)+9 }
	t.Cleanup(func() { labRuntimeOptions, labProvisioning = nil, nil })
	l := newRegistryLab(t)
	ctx := t.Context()
	if err = l.store.ConfigureHostStorage(ctx, "local", int64(most*128+512)); err != nil {
		t.Fatal(err)
	}
	// The worker's spans give each boot's own duration.
	key, err := l.store.TraceKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	traces := strings.TrimSuffix(path, ".json") + "-traces.jsonl"
	tracer, err := telemetry.NewFileTracer(traces, "agentcapsule-worker", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tracer.Close)
	if err = l.worker.EnableTracing(tracer); err != nil {
		t.Fatal(err)
	}
	var agents []string
	for _, n := range sizes {
		step := capacityStep{Agents: n, Status: "measured"}
		// Every agent asleep: the host as it stands without VMs.
		l.lifecycleAll(agents, "sleep", fmt.Sprintf("sleep-before-%d", n))
		asleep, err := readHostSample()
		if err != nil {
			t.Fatal(err)
		}
		if !enoughMemory(asleep.available, n, memory) {
			step.Status = "not_run"
			step.Reason = fmt.Sprintf("%.0f MiB available, %d needed", asleep.available, n*memory+capacityHeadroomMiB)
			report.Steps = append(report.Steps, step)
			save()
			continue
		}
		// The agents this step adds, each provisioned until its first boot.
		var provision []float64
		for len(agents) < n {
			began := time.Now()
			agents = append(agents, l.createWith(fmt.Sprintf("capacity-%02d", len(agents)), "reference", "1.0.0", memory).AgentID)
			provision = append(provision, time.Since(began).Seconds())
		}
		step.Provision = summarize(provision)
		l.lifecycleAll(agents, "sleep", fmt.Sprintf("sleep-%d", n))
		if asleep, err = readHostSample(); err != nil {
			t.Fatal(err)
		}
		step.HostAvailableAsleepMiB = round(asleep.available)

		// Wake the step's agents at once; one worker boots them in turn.
		waking := time.Now()
		woken := l.lifecycleAll(agents[:n], "wake", fmt.Sprintf("wake-%d", n))
		step.AllRunning = round(time.Since(waking).Seconds())
		step.WakeToRunning = summarize(woken)
		booted := time.Now()

		// Then a first invocation to each, sent at once.
		sent := map[string]time.Time{}
		pending := map[string]string{}
		for i, agent := range agents[:n] {
			id := l.invoke(agent, fmt.Sprintf("first-%d-%d", n, i), fmt.Sprintf("first answer %d", i))
			sent[id], pending[id] = time.Now(), fmt.Sprintf("first answer %d", i)
		}
		var first []float64
		l.awaitFor(fmt.Sprintf("first answers of %d agents", n), true, 15*time.Minute, func() bool {
			for id, text := range pending {
				if l.answered(id, text) {
					first = append(first, time.Since(sent[id]).Seconds())
					delete(pending, id)
				}
			}
			return len(pending) == 0
		})
		step.FirstAnswer = summarize(first)

		// The VMs, idle: their memory, and the host's CPU and memory.
		runs, err := l.worker.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var rss, charged []float64
		before := map[int]uint64{}
		for _, agent := range agents[:n] {
			run, ok := runs[agent]
			if !ok || run.PID <= 0 {
				t.Fatal("a woken agent has no VMM", n)
			}
			if v, err := readProc(run.PID, "status", processRSS); err == nil {
				rss = append(rss, v)
			}
			if v, err := vmCgroupMemory(run.PID); err == nil {
				charged = append(charged, v)
			}
			if ticks, err := vmmTicks(run.PID); err == nil {
				before[run.PID] = ticks
			}
		}
		step.VMMRSS, step.CgroupMemory = summarize(rss), summarize(charged)
		idleFrom, err := readHostSample()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(idleWindow)
		idleTo, err := readHostSample()
		if err != nil {
			t.Fatal(err)
		}
		if spent := idleTo.total - idleFrom.total; spent > 0 {
			busy := round(1 - float64(idleTo.idle-idleFrom.idle)/float64(spent))
			step.HostCPUBusyRatio = &busy
		}
		var vmmTicksSpent uint64
		for pid, ticks := range before {
			if now, err := vmmTicks(pid); err == nil && now >= ticks {
				vmmTicksSpent += now - ticks
			}
		}
		perSecond := round(float64(vmmTicksSpent) / userHZ / idleTo.at.Sub(idleFrom.at).Seconds())
		step.VMMCPUPerSecond = &perSecond
		step.HostAvailableRunningMiB = round(idleTo.available)
		step.HostUsedByVMsMiB = round(asleep.available - idleTo.available)
		if raw, err := os.ReadFile(traces); err == nil {
			if boots, err := bootSeconds(raw, waking, booted); err == nil {
				step.Boot = summarize(boots)
			}
		}

		// The wake from STOPPED: each agent asleep, asked in turn.
		l.lifecycleAll(agents[:n], "sleep", fmt.Sprintf("sleep-after-%d", n))
		var cold []float64
		for i, agent := range agents[:n] {
			text := fmt.Sprintf("cold answer %d", i)
			began := time.Now()
			id := l.invoke(agent, fmt.Sprintf("cold-%d-%d", n, i), text)
			l.awaitFor("wake from STOPPED "+strconv.Itoa(i), true, 5*time.Minute, func() bool { return l.answered(id, text) })
			cold = append(cold, time.Since(began).Seconds())
		}
		step.WakeFromStopped = summarize(cold)
		report.Steps = append(report.Steps, step)
		save()
	}
	finished := time.Now().UTC()
	report.Finished = &finished
	save()
}

// lifecycleAll requests kind (sleep, wake) for every agent not already in
// that state, at once, and dispatches until each succeeded. It returns each
// operation's time from its request to its success.
func (l *registryLab) lifecycleAll(agents []string, kind, key string) []float64 {
	l.t.Helper()
	want := map[string]string{"sleep": "STOPPED", "wake": "RUNNING"}[kind]
	requested := map[string]time.Time{}
	for _, agent := range agents {
		var placement string
		if err := l.db.QueryRow(l.t.Context(), "SELECT state FROM agent_placements WHERE agent_id=$1", agent).Scan(&placement); err != nil {
			l.t.Fatal(err)
		}
		if placement == want {
			continue
		}
		var op controlplane.AgentCreation
		l.request(l.owner(), "POST", "/v1/agents/"+agent+"/"+kind, key+"-"+agent, map[string]any{}, 202, &op)
		requested[op.OperationID] = time.Now()
	}
	var took []float64
	l.awaitFor(kind+" "+key, true, 15*time.Minute, func() bool {
		for op, at := range requested {
			var v controlplane.PlatformOperation
			l.request(l.owner(), "GET", "/v1/operations/"+op, "", nil, 200, &v)
			if v.Status == "FAILED" || v.Status == "CANCELED" {
				l.t.Fatal(kind, "ended badly", v.Status, v.ErrorCode)
			}
			if v.Status == "SUCCEEDED" {
				took = append(took, time.Since(at).Seconds())
				delete(requested, op)
			}
		}
		return len(requested) == 0
	})
	return took
}

func readProc[T any](pid int, name string, parse func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		var zero T
		return zero, err
	}
	defer f.Close()
	return parse(f)
}

// vmmTicks is a VMM's CPU time, in clock ticks.
func vmmTicks(pid int) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	return processCPU(string(raw))
}

// vmCgroupMemory is the memory charged to a VMM's cgroup, in MiB.
func vmCgroupMemory(pid int) (float64, error) {
	group, err := readProc(pid, "cgroup", cgroupPath)
	if err != nil {
		return 0, err
	}
	raw, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "memory.current"))
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	return v / (1 << 20), err
}
