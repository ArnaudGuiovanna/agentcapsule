//go:build linux && cgo && kvm_integration && kvm_product_integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// helperWorkerUID is the worker's account of TestKVMProductGuestThroughTheWorkerHelper.
const helperWorkerUID = 61900

// A worker that is not root boots, controls, stops and adopts a product
// guest through its root helper (ADR 024): this process plays the helper,
// as root; a child, as helperWorkerUID with no capability, plays the
// worker. The KVM configuration's artifacts must be readable by that UID.
func TestKVMProductGuestThroughTheWorkerHelper(t *testing.T) {
	c := kvmSettings(t)
	parent, err := os.MkdirTemp(c.RootParent, "separated-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	if err = os.Chmod(parent, 0o711); err != nil {
		t.Fatal(err)
	}
	root, keys, state := filepath.Join(parent, "host"), filepath.Join(parent, "keys"), filepath.Join(parent, "vmm")
	for _, d := range []string{root, keys} {
		if err = os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(d, helperWorkerUID, helperWorkerUID); err != nil {
			t.Fatal(err)
		}
	}
	layout := workerhelper.Layout{Root: root, Jails: filepath.Join(state, "jails"), Bin: filepath.Join(state, "bin"), Cgroup: workerhelper.CgroupFor(root)}
	for _, d := range []string{layout.Bin, filepath.Join(layout.Jails, "firecracker")} {
		if err = os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := workerhelper.Config{Layout: layout, WorkerUID: helperWorkerUID, WorkerGID: helperWorkerUID, FirstUID: 62200, LastUID: 62210,
		ImageRoots: []string{root}, DriveRoots: []string{root}, Jailer: filepath.Join(layout.Bin, "jailer"), Firecracker: filepath.Join(layout.Bin, "firecracker")}
	for pin, source := range map[string]string{cfg.Jailer: c.Jailer, cfg.Firecracker: c.Firecracker} {
		if err = workerhelper.Pin(source, pin, hashFile(t, source), 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err = workerhelper.SetupCgroup(layout.Cgroup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(layout.Cgroup) })
	s, err := workerhelper.NewServer(cfg, workerhelper.System{})
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := os.MkdirTemp("", "wh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	if err = os.Chmod(sockets, 0o711); err != nil {
		t.Fatal(err)
	}
	l, err := workerhelper.Listen(filepath.Join(sockets, "worker.sock"), helperWorkerUID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, l) }()
	defer func() { cancel(); <-served }()

	cmd := exec.Command(os.Args[0], "-test.run", "^TestKVMWorkerHelperChild$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "AC_HELPER_CHILD_ROOT="+root, "AC_HELPER_CHILD_KEYS="+keys, "AC_HELPER_CHILD_SOCKET="+filepath.Join(sockets, "worker.sock"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: helperWorkerUID, Gid: helperWorkerUID}}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestKVMWorkerHelperChild") {
		t.Fatalf("the worker's side: %v\n%s", err, out)
	}
	// Nothing of the runs is left: no jail, no run cgroup.
	if entries, err := os.ReadDir(filepath.Join(layout.Jails, "firecracker")); err != nil || len(entries) != 0 {
		t.Fatal("jails left", entries, err)
	}
	entries, err := os.ReadDir(layout.Cgroup)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Fatal("a run's cgroup stayed", e.Name())
		}
	}
}

// TestKVMWorkerHelperChild is the worker's side of
// TestKVMProductGuestThroughTheWorkerHelper, as its account.
func TestKVMWorkerHelperChild(t *testing.T) {
	root := os.Getenv("AC_HELPER_CHILD_ROOT")
	if root == "" {
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("the worker's side runs as root")
	}
	b, err := os.ReadFile(os.Getenv("AGENTCAPSULE_KVM_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	var c kvmConfig
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	keys, err := keyauthority.Initialize(t.Context(), os.Getenv("AC_HELPER_CHILD_KEYS"))
	if err != nil {
		t.Fatal(err)
	}
	client := workerhelper.NewClient(os.Getenv("AC_HELPER_CHILD_SOCKET"))
	defer client.Close()
	id, volumeID := "agt_"+strings.Repeat("e", 32), "vol_"+strings.Repeat("f", 32)
	var volume volumestore.Container
	initialize := true
	opts := FirecrackerOptions{Root: root, Firecracker: c.Firecracker, Jailer: c.Jailer, Kernel: c.Kernel, Initrd: c.Initrd,
		FirecrackerSHA256: hashFile(t, c.Firecracker), JailerSHA256: hashFile(t, c.Jailer), KernelSHA256: hashFile(t, c.Kernel), InitrdSHA256: hashFile(t, c.Initrd),
		MaxActive: 2, BootTimeout: 60 * time.Second, AuthenticatedControl: true, SerialConsole: true, Helper: client,
		Confirm: func(context.Context, string, VMRun) error { return nil }, Adopt: func(context.Context, string, VMRun) error { return nil },
		PrepareGuest: func(ctx context.Context, _ string, _ VMRun, c *capsuleprotocol.Client) error {
			return keys.WithKey(ctx, id, volumeID, func(key []byte) error {
				return openProductVolume(ctx, c, capsuleprotocol.VolumeBoot{Incarnation: 1, VolumeID: volumeID, UUID: volume.UUID, Initialize: initialize,
					PreviousShutdown: capsuleprotocol.ShutdownUnclean}, key)
			})
		}}
	h, err := NewFirecrackerHost(opts)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := volumestore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), id, volumeID); err != nil {
		t.Fatal(err)
	}
	if err = keys.WithKey(t.Context(), id, volumeID, func(key []byte) error {
		var e error
		volume, e = storage.Prepare(t.Context(), volumestore.Spec{AgentID: id, VolumeID: volumeID, SizeMiB: 128}, key)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = h.RegisterProvisioned(t.Context(), ProvisionedAgent{ID: id, Volume: volume.Path, Device: volume.Device, Inode: volume.Inode,
		Resources: VMResources{VCPUs: 1, MemoryMiB: 256, VolumeMiB: 128}}, 62200, 62210); err != nil {
		t.Fatal(err)
	}
	if _, err = os.OpenFile(volume.Path, os.O_RDONLY, 0); !errors.Is(err, os.ErrPermission) {
		t.Fatal("the worker still opens its VM's volume itself", err)
	}
	if _, err = h.StartForFence(t.Context(), id, 1); err != nil {
		t.Fatal("restricted boot through the helper", err)
	}
	control, err := h.Control(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err = control.Fence(t.Context(), "agent/historical"); err != nil {
		t.Fatal(err)
	}
	if err = h.Stop(t.Context(), id, 1); err != nil {
		t.Fatal(err)
	}
	initialize = false
	run, err := h.Start(t.Context(), id, 2)
	if err != nil {
		t.Fatal("boot through the helper", err)
	}
	// A new worker process adopts the running VM through the helper.
	h.Close()
	again, err := NewFirecrackerHost(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	runs, err := again.ReconcileAgent(t.Context(), id)
	if err != nil || runs[id].ID != run.ID {
		t.Fatal("the running VM was not adopted", runs, err)
	}
	if _, err = again.Control(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err = again.Stop(t.Context(), id, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = again.SealAgent(t.Context(), id, 2); err != nil {
		t.Fatal("seal through the helper", err)
	}
}
