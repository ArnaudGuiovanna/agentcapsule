//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// vmmIO reads the write counters of a VMM process: bytes written and write
// system calls, the virtio-blk writes of its guest among them.
func vmmIO(t *testing.T, pid int) (wchar, syscw int64) {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			t.Fatal(line, err)
		}
		switch name {
		case "wchar":
			wchar = n
		case "syscw":
			syscw = n
		}
	}
	return wchar, syscw
}

// A guest that writes its volume as fast as it can stays under its drive's
// ceilings (RUN-007, ADR 012): one guest writes 1 MiB at a time and is held
// to the bandwidth ceiling, the other writes 4 KiB at a time, each made
// durable, and is held to the operations ceiling. Each VMM also runs in a
// network namespace of its own, with loopback only (product.md §6).
func TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest(t *testing.T) {
	ceiling := runtime.DriveLimits{Volume: runtime.DriveRate{BandwidthMiBPerSecond: 8, IOPS: 200}, Harness: runtime.DefaultDriveLimits.Harness}
	labRuntimeOptions = func(o *runtime.FirecrackerOptions) { o.DriveLimits = ceiling }
	t.Cleanup(func() { labRuntimeOptions = nil })
	l := newRegistryLab(t)
	l.publishBehaviour("1.0.0", "opt/bytes", "flood-volume", "1048576")
	l.publishBehaviour("2.0.0", "opt/ops", "flood-volume", "4096")
	bytesAgent := l.create("flood-bytes", "1.0.0").AgentID
	opsAgent := l.create("flood-ops", "2.0.0").AgentID
	runs := l.runs(2)
	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for id, run := range runs {
		ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", run.PID))
		if err != nil || ns == host {
			t.Fatal("the VMM shares the host's network namespace", id, err)
		}
		dev, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", run.PID))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(dev), "\n")[2:] {
			if name, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && name != "lo" {
				t.Fatal("the VMM's namespace has an interface", id, name)
			}
		}
	}
	// Let both floods pass their bucket's first second.
	time.Sleep(3 * time.Second)
	const window = 10 * time.Second
	bytes0, _ := vmmIO(t, runs[bytesAgent].PID)
	_, ops0 := vmmIO(t, runs[opsAgent].PID)
	time.Sleep(window)
	bytes1, _ := vmmIO(t, runs[bytesAgent].PID)
	_, ops1 := vmmIO(t, runs[opsAgent].PID)
	seconds := int64(window / time.Second)
	// One second of bucket on top of the rate, and a tenth for the VMM's
	// own writes (its log, the vsock).
	maxBytes := (int64(ceiling.Volume.BandwidthMiBPerSecond) << 20) * (seconds + 1) * 11 / 10
	if wrote := bytes1 - bytes0; wrote > maxBytes || wrote < 4<<20 {
		t.Fatalf("a guest writing 1 MiB at a time wrote %d bytes in %s; ceiling %d MiB/s", wrote, window, ceiling.Volume.BandwidthMiBPerSecond)
	}
	maxOps := int64(ceiling.Volume.IOPS) * (seconds + 1) * 12 / 10
	if calls := ops1 - ops0; calls > maxOps || calls < 100 {
		t.Fatalf("a guest writing 4 KiB at a time made %d write calls in %s; ceiling %d operations a second", calls, window, ceiling.Volume.IOPS)
	}
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
	l.awaitFor("the wake of a guest that crashes at boot", true, 5*time.Minute, func() bool {
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
	// An invocation waits; passes boot nothing.
	before := generation()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "waits", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "after the fix"}}}, 202, &inv)
	deadline := time.Now().Add(30 * time.Second)
	l.await("passes over a FAILED agent", true, func() bool { return time.Now().After(deadline) })
	if after := generation(); after != before {
		t.Fatal("a FAILED agent was booted", before, after)
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
