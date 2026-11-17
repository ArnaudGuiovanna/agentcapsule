//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// labRuntimeOptions, when set, adjusts the host options of the next product
// lab (newProductPeerLab), such as its drive ceilings.
var labRuntimeOptions func(*runtime.FirecrackerOptions)

// publishBehaviour packs capsule-echo with a test behaviour (its entrypoint
// arguments, cmd/capsule-echo/behaviour.go) and imports it as echo-oci:version.
func (l *registryLab) publishBehaviour(version, dir string, args ...string) ociregistry.Reference {
	t := l.t
	t.Helper()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, filepath.Join(filepath.Dir(config(t).Initrd), "capsule-echo"), filepath.Join(src, dir, "harness"))
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "echo-oci", Version: version, Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: append([]string{"/" + dir + "/harness"}, args...)}
	pkg := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(pkg, harnesspkg.RootfsFile), 64); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(pkg, m); err != nil {
		t.Fatal(err)
	}
	return l.importPackage(pkg, "acme/echo", version)
}

// vmmMoved reads the bytes a VMM process has moved through read and write
// system calls (procIOMoved).
func vmmMoved(t *testing.T, pid int) int64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		t.Fatal(err)
	}
	moved, err := procIOMoved(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return moved
}

// floodingVMM boots one agent whose harness floods its volume, chunk bytes
// per direct write (capsule-echo's flood-volume), on a host whose volume
// drives have rate as ceiling, and returns its VMM's PID. The VMM runs in a
// network namespace of its own, with loopback only (product.md §6).
func floodingVMM(t *testing.T, rate runtime.DriveRate, chunk string) int {
	t.Helper()
	labRuntimeOptions = func(o *runtime.FirecrackerOptions) {
		o.DriveLimits = runtime.DriveLimits{Volume: rate, Harness: runtime.DefaultDriveLimits.Harness}
	}
	t.Cleanup(func() { labRuntimeOptions = nil })
	l := newRegistryLab(t)
	labRuntimeOptions = nil
	l.publishBehaviour("1.0.0", "opt/flood", "flood-volume", chunk)
	agent := l.create("flood", "1.0.0").AgentID
	run := l.runs(1)[agent]
	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", run.PID))
	if err != nil || ns == host {
		t.Fatal("the VMM shares the host's network namespace", err)
	}
	dev, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", run.PID))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(dev), "\n")[2:] {
		if name, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && name != "lo" {
			t.Fatal("the VMM's namespace has an interface", name)
		}
	}
	return run.PID
}

// A flood is measured during floodWindow, after floodWarmup, by when it has
// spent the full bucket it started with.
const floodWindow, floodWarmup = 10 * time.Second, 3 * time.Second

// movedDuringFlood is what the VMM moved during floodWindow.
func movedDuringFlood(t *testing.T, pid int) int64 {
	t.Helper()
	time.Sleep(floodWarmup)
	before := vmmMoved(t, pid)
	time.Sleep(floodWindow)
	return vmmMoved(t, pid) - before
}

// A guest that writes its volume as fast as it can stays under its drive's
// ceilings (RUN-007, ADR 012). The guest writes with O_DIRECT, so each write
// reaches the drive as requests of its own bytes, with no flush. The VMM's
// Sync engine moves each request's bytes with one read or write call, and
// moves little else: 8 bytes for each interrupt it signals or notification
// it reads. So the bytes the VMM moved bound the bytes the drive served and,
// for writes of 4 KiB, the drive's operations.
//
// Each ceiling is checked on a host whose other ceiling leaves room, so that
// only the one under test can hold the flood, whatever the size of the
// requests the guest's kernel sends. Each check also wants half the ceiling
// at least, so that a flood stalled for another reason does not pass. One
// second of bucket is allowed on top of the rate, and a tenth for what else
// the VMM moved.
func TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest(t *testing.T) {
	seconds := int64(floodWindow / time.Second)
	t.Run("bandwidth", func(t *testing.T) {
		// 4 MiB/s, and room for 100,000 operations a second.
		rate := runtime.DriveRate{BandwidthMiBPerSecond: 4, IOPS: 100_000}
		moved := movedDuringFlood(t, floodingVMM(t, rate, "1048576"))
		perSecond := int64(rate.BandwidthMiBPerSecond) << 20
		if moved > perSecond*(seconds+1)*11/10 || moved < perSecond*seconds/2 {
			t.Fatalf("a guest writing 1 MiB at a time moved %d bytes through its VMM in %s; ceiling %d MiB/s",
				moved, floodWindow, rate.BandwidthMiBPerSecond)
		}
	})
	t.Run("operations", func(t *testing.T) {
		// 200 operations a second, and room for 64 MiB/s: one operation
		// for each write of 4 KiB.
		rate := runtime.DriveRate{BandwidthMiBPerSecond: 64, IOPS: 200}
		operations := movedDuringFlood(t, floodingVMM(t, rate, "4096")) / 4096
		perSecond := int64(rate.IOPS)
		if operations > perSecond*(seconds+1)*11/10 || operations < perSecond*seconds/2 {
			t.Fatalf("a guest writing 4 KiB at a time made %d drive operations (bytes its VMM moved / 4096) in %s; ceiling %d a second",
				operations, floodWindow, rate.IOPS)
		}
	})
}

// awaitPasses is await for stages whose passes fail as the stage expects: a
// pass may fail only with failures that expected accepts (onlyFailures). It
// returns how many passes failed so.
func (l *productPeerLab) awaitPasses(stage string, bound time.Duration, expected func(error) bool, check func() bool) (failed int) {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(l.t.Context(), bound)
	defer cancel()
	opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
	for !check() {
		if err := l.worker.DispatchPass(ctx, opts, 90*time.Second); err != nil {
			if !expected(err) {
				l.t.Fatal(stage, "worker dispatch", err)
			}
			failed++
		}
		select {
		case <-ctx.Done():
			l.t.Fatal(stage, "did not reach expected state", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	return failed
}

// A guest that crashes at boot is not booted again and again (RUN-011, ADR
// 012): its wake ends FAILED once the agent spends its budget, the agent is
// FAILED with the reason, and further passes boot nothing, even with an
// invocation waiting. A wake after a fix gives it a new budget: it boots and
// answers the invocation that waited.
func TestProductWorkerStopsBootingAGuestThatCrashesAtBoot(t *testing.T) {
	l := newRegistryLab(t)
	if err := l.worker.SetRestartBudget(controlplane.RestartBudget{Failures: 3, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	l.publish("1.0.0", "opt/echo")
	l.publishBehaviour("2.0.0", "opt/crash", "crash-at-boot")
	agent := l.create("crashing", "1.0.0").AgentID
	release := func(version, key string) {
		l.request(l.owner(), "POST", "/v1/agents/"+agent+"/release", key,
			controlplane.ReleaseChange{Harness: controlplane.HarnessReference{Name: "echo-oci", Version: version}}, 200, nil)
	}
	release("2.0.0", "to-crash")
	l.lifecycle(agent, "sleep", "sleep-1")
	var wake controlplane.AgentCreation
	l.request(l.owner(), "POST", "/v1/agents/"+agent+"/wake", "wake-crash", map[string]any{}, 202, &wake)
	// Each boot the guest fails is the wake job's failure, and the pass's.
	l.awaitPasses("the wake of a guest that crashes at boot", 5*time.Minute, onlyBootFailures, func() bool {
		var op controlplane.PlatformOperation
		l.request(l.owner(), "GET", "/v1/operations/"+wake.OperationID, "", nil, 200, &op)
		if op.Status == "SUCCEEDED" || op.Status == "CANCELED" {
			t.Fatal("wake of a guest that crashes at boot", op.Status)
		}
		return op.Status == "FAILED" && op.ErrorCode == "restart_budget_exhausted"
	})
	var v controlplane.TenantAgent
	l.request(l.owner(), "GET", "/v1/agents/"+agent, "", nil, 200, &v)
	if v.State != "FAILED" || v.FailureReason == nil || *v.FailureReason != "boot_failed" {
		t.Fatal("agent after its budget", v.State, v.FailureReason)
	}
	generation := func() (g int64) {
		if err := l.db.QueryRow(t.Context(), "SELECT generation FROM agent_placements WHERE agent_id=$1", agent).Scan(&g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	var failures int
	if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM guest_failures WHERE agent_id=$1", agent).Scan(&failures); err != nil || failures != 3 {
		t.Fatal("boot failures recorded", failures, err)
	}
	// An invocation waits; passes boot nothing. Its delivery is put back to
	// wait for the FAILED agent (retry reason agent_failed), without a boot.
	before := generation()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "waits", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "after the fix"}}}, 202, &inv)
	deadline := time.Now().Add(30 * time.Second)
	held := l.awaitPasses("passes over a FAILED agent", 2*time.Minute, onlyAgentFailed, func() bool { return time.Now().After(deadline) })
	if after := generation(); after != before {
		t.Fatal("a FAILED agent was booted", before, after)
	}
	if held == 0 {
		t.Fatal("no delivery waited for the FAILED agent")
	}
	l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &inv)
	if inv.State == "completed" || inv.State == "failed" {
		t.Fatal("the waiting invocation", inv.State)
	}
	// The fix, then a wake: a new budget, and the invocation is answered.
	release("1.0.0", "fixed")
	l.lifecycle(agent, "wake", "wake-fixed")
	l.request(l.owner(), "GET", "/v1/agents/"+agent, "", nil, 200, &v)
	if v.State != "READY" || v.FailureReason != nil {
		t.Fatal("agent after the wake", v.State, v.FailureReason)
	}
	l.await("the invocation that waited", true, func() bool {
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &inv)
		return inv.State == "completed"
	})
}
