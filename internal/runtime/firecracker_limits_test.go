//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

type tokenBucket struct {
	Size         int64  `json:"size"`
	OneTimeBurst *int64 `json:"one_time_burst"`
	RefillTime   int64  `json:"refill_time"`
}

type vmConfig struct {
	Drives []struct {
		ID          string `json:"drive_id"`
		RateLimiter *struct {
			Bandwidth *tokenBucket `json:"bandwidth"`
			Ops       *tokenBucket `json:"ops"`
		} `json:"rate_limiter"`
	} `json:"drives"`
	Network []any `json:"network-interfaces"`
}

// preparedConfig runs prepare for one boot of a over an ordinary test
// directory and returns the Firecracker configuration it wrote, raw and parsed.
func preparedConfig(t *testing.T, h *FirecrackerHost, a *HostAgent) (map[string]any, vmConfig) {
	t.Helper()
	if err := h.prepare(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h.jail(a.Run), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	var parsed vmConfig
	if err = json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	return raw, parsed
}

func limitsFixture(t *testing.T) (*FirecrackerHost, *HostAgent, int64) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"bin", "volumes", "groups", "credentials", "platform", "releases"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"kernel", "initrd"} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte("configuration fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	volume := filepath.Join(root, "volumes", "data")
	if err := os.WriteFile(volume, []byte("configuration fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, "releases", "harness.ext4")
	const imageSize = 3 << 20
	if err := os.WriteFile(image, make([]byte, imageSize), 0444); err != nil {
		t.Fatal(err)
	}
	h := &FirecrackerHost{root: root, cgroup: filepath.Join(root, "groups"), opts: FirecrackerOptions{AuthenticatedControl: true}}
	a := &HostAgent{ID: "a", UID: 60000, Volume: volume, Resources: VMResources{VCPUs: 1, MemoryMiB: 256, VolumeMiB: 64},
		Harness: &HarnessImage{Path: image, Digest: "sha256:" + fmt.Sprintf("%064d", 0), Entrypoint: []string{"/harness"}},
		Run:     &VMRun{Incarnation: 1, ID: "0123456789abcdef", Generation: 1, Phase: "STARTING"}}
	return h, a, imageSize
}

// Every drive of every VM has an I/O ceiling, the defaults when the operator
// sets none (CAP-03, ADR 012). The harness image may be read whole once at
// full speed at boot.
func TestDrivesHaveIOCeilings(t *testing.T) {
	h, a, imageSize := limitsFixture(t)
	_, config := preparedConfig(t, h, a)
	want := map[string]struct {
		bytes, ops int64
		burst      int64
	}{
		"data":    {64 << 20, 2000, 0},
		"harness": {128 << 20, 4000, imageSize},
	}
	if len(config.Drives) != 2 {
		t.Fatal("drives", config.Drives)
	}
	for _, d := range config.Drives {
		w, ok := want[d.ID]
		if !ok || d.RateLimiter == nil || d.RateLimiter.Bandwidth == nil || d.RateLimiter.Ops == nil {
			t.Fatal("drive without both buckets", d.ID)
		}
		bw, ops := d.RateLimiter.Bandwidth, d.RateLimiter.Ops
		if bw.Size != w.bytes || bw.RefillTime != 1000 || ops.Size != w.ops || ops.RefillTime != 1000 {
			t.Fatal("ceiling", d.ID, *bw, *ops)
		}
		if w.burst == 0 && (bw.OneTimeBurst != nil || ops.OneTimeBurst != nil) {
			t.Fatal("the volume has no burst", d.ID)
		}
		if w.burst != 0 && (bw.OneTimeBurst == nil || *bw.OneTimeBurst != w.burst || ops.OneTimeBurst == nil || *ops.OneTimeBurst != w.burst/4096) {
			t.Fatal("the image's one-time burst", d.ID, bw.OneTimeBurst, ops.OneTimeBurst)
		}
	}

	// The operator's ceilings replace the defaults.
	h2, a2, _ := limitsFixture(t)
	h2.opts.DriveLimits = DriveLimits{Volume: DriveRate{BandwidthMiBPerSecond: 8, IOPS: 300}, Harness: DriveRate{BandwidthMiBPerSecond: 16, IOPS: 600}}
	_, config = preparedConfig(t, h2, a2)
	for _, d := range config.Drives {
		got := [2]int64{d.RateLimiter.Bandwidth.Size, d.RateLimiter.Ops.Size}
		if (d.ID == "data" && got != [2]int64{8 << 20, 300}) || (d.ID == "harness" && got != [2]int64{16 << 20, 600}) {
			t.Fatal("configured ceiling", d.ID, got)
		}
	}
}

func TestDriveLimitsAreBounded(t *testing.T) {
	if err := DefaultDriveLimits.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DriveLimits{
		{},
		{Volume: DriveRate{0, 2000}, Harness: DefaultDriveLimits.Harness},
		{Volume: DriveRate{4097, 2000}, Harness: DefaultDriveLimits.Harness},
		{Volume: DefaultDriveLimits.Volume, Harness: DriveRate{128, 9}},
		{Volume: DefaultDriveLimits.Volume, Harness: DriveRate{128, 1_000_001}},
	} {
		if bad.Validate() == nil {
			t.Error("accepted", bad)
		}
	}
}

// Egress is denied except through the platform (product.md §6): the VM has
// no network device, and its VMM starts in a network namespace of its own,
// which has no interface but loopback. The guest's only channel out is the
// vsock to this host, served by the platform.
func TestGuestsHaveNoNetwork(t *testing.T) {
	h, a, _ := limitsFixture(t)
	raw, config := preparedConfig(t, h, a)
	if _, ok := raw["network-interfaces"]; ok || len(config.Network) != 0 {
		t.Fatal("a VM has a network device", raw["network-interfaces"])
	}
	vsock, ok := raw["vsock"].(map[string]any)
	if !ok || vsock["uds_path"] != "/vsock" {
		t.Fatal("the vsock is not the jail's own socket", raw["vsock"])
	}
	allowed := []string{"boot-source", "machine-config", "drives", "vsock"}
	for key := range raw {
		if !slices.Contains(allowed, key) {
			t.Fatal("unexpected VM device or setting", key)
		}
	}
	group, err := os.Open(h.group(a.Run))
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	cmd := workerhelper.JailerCommand(workerhelper.StartPlan{Jailer: filepath.Join(h.root, "bin", "jailer"), Firecracker: filepath.Join(h.root, "bin", "firecracker"),
		ChrootBase: h.jailBase(), RunID: a.Run.ID, UID: a.UID, Cgroup: h.cgroup, Group: h.group(a.Run)}, group)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET == 0 {
		t.Fatal("the VMM shares the host's network namespace")
	}
	for _, arg := range cmd.Args {
		if arg == "--netns" {
			t.Fatal("the VMM joins an existing network namespace")
		}
	}
}

// A guest that ends ends its VMM (ADR 012, question 6): capsule-init ends
// the guest with a restart (guestinit.EndCommand), and its kernel, booted
// with reboot=k, restarts by resetting the CPU through the keyboard
// controller, on which Firecracker exits. A guest whose kernel panics
// restarts after one second (panic=1). Without them, the guest would halt
// or reboot in place and keep its VMM, unseen by the worker.
func TestAGuestThatEndsEndsItsVMM(t *testing.T) {
	h, a, _ := limitsFixture(t)
	raw, _ := preparedConfig(t, h, a)
	source, ok := raw["boot-source"].(map[string]any)
	if !ok {
		t.Fatal("no boot source", raw["boot-source"])
	}
	args, _ := source["boot_args"].(string)
	parameters := strings.Fields(args)
	for _, want := range []string{"reboot=k", "panic=1"} {
		if !slices.Contains(parameters, want) {
			t.Error("the guest's kernel command line lacks", want, ":", args)
		}
	}
	for _, p := range parameters {
		if strings.HasPrefix(p, "reboot=") && p != "reboot=k" || strings.HasPrefix(p, "panic=") && p != "panic=1" {
			t.Error("the guest's kernel command line overrides", p, ":", args)
		}
	}
}

// A failed boot counts against the agent's restart budget only when its
// guest failed: its VMM exited, or nothing answered on its control channel
// at the end of the grace period, or it answered with an incompatible
// contract. A guest that still answers was refused by the platform.
func TestBootFailureIsTheGuestsOnlyWhenTheGuestFailed(t *testing.T) {
	never := func() bool { return false }
	silent := func(context.Context) bool { return false }
	alive := func(context.Context) bool { return true }
	cause := errors.New("cause")
	if !guestFailed(t.Context(), cause, time.Second, func() bool { return true }, alive) {
		t.Error("a VMM that exited")
	}
	if !guestFailed(t.Context(), cause, 50*time.Millisecond, never, silent) {
		t.Error("a guest that stopped answering")
	}
	if guestFailed(t.Context(), cause, 50*time.Millisecond, never, alive) {
		t.Error("a guest that still answers")
	}
	if guestFailed(t.Context(), cause, 50*time.Millisecond, never, nil) {
		t.Error("without a control channel, only an exit counts")
	}
	if !guestFailed(t.Context(), capsuleprotocol.ErrCapabilitiesUnavailable, time.Second, never, alive) {
		t.Error("an incompatible guest")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if guestFailed(canceled, cause, time.Second, func() bool { return true }, silent) {
		t.Error("a caller that gave up")
	}
	// An exit late in the grace period still counts.
	var polls atomic.Int32
	late := func() bool { return polls.Add(1) > 3 }
	if !guestFailed(t.Context(), cause, time.Second, late, alive) {
		t.Error("a VMM that exited during the grace period")
	}
}

// A guest that refuses, such as one whose volume is not open yet, answers;
// one whose control listener is gone does not.
func TestControlAnswers(t *testing.T) {
	id := capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	host, guest, err := capsuleprotocol.NewCredentials(id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The bootstrap listener of a guest whose volume is not open yet.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol": capsuleprotocol.Version, "identity": id, "code": "volume_unavailable"})
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, listener, guest, handler) }()
	address := listener.Addr().String()
	client, err := capsuleprotocol.NewClient(host, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Health(t.Context()); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("the refusal is not the transport sentinel", err)
	}
	if !controlAnswers(t.Context(), client) {
		t.Fatal("a guest that refuses did not answer")
	}
	cancel()
	<-done
	if controlAnswers(t.Context(), client) {
		t.Fatal("a guest whose listener is gone answered")
	}
}
