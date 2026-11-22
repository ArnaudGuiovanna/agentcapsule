//go:build linux && root_integration

package workerhelper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The worker's account and an agent's UID of this test.
const rootWorkerUID, rootAgentUID = 61950, 20051

// rootLab is a helper with its real operations, as root, for a worker of
// rootWorkerUID: the runtime root is the worker's, the jails root's.
func rootLab(t *testing.T) (*Server, Config, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("root_integration runs as root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	root, state := filepath.Join(dir, "host"), filepath.Join(dir, "vmm")
	for _, d := range []string{root, filepath.Join(root, "volumes"), filepath.Join(root, "staging")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, rootWorkerUID, rootWorkerUID); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(state, "jails", "firecracker"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := Config{Layout: Layout{Root: root, Jails: filepath.Join(state, "jails"), Bin: filepath.Join(state, "bin"), Cgroup: filepath.Join(dir, "cgroup")},
		WorkerUID: rootWorkerUID, WorkerGID: rootWorkerUID, FirstUID: 20000, LastUID: 20100, ImageRoots: []string{root},
		DriveRoots: []string{root}, Jailer: "/nonexistent/jailer", Firecracker: "/nonexistent/firecracker"}
	s, err := NewServer(c, System{})
	if err != nil {
		t.Fatal(err)
	}
	return s, c, root
}

func workerFile(t *testing.T, path string, size int64) unix.Stat_t {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, rootWorkerUID, rootWorkerUID); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func saveRegistry(t *testing.T, root string, r *Registry) {
	t.Helper()
	b, _ := json.Marshal(r)
	path := filepath.Join(root, "registry.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, rootWorkerUID, rootWorkerUID); err != nil {
		t.Fatal(err)
	}
}

// As root, the helper gives a provisioned volume to its agent's UID, opens
// it for the worker only as that agent's registered volume, and gives a
// builder's drives and takes them back.
func TestAsRootTheHelperGivesAndOpensOnlyTheAgentsFiles(t *testing.T) {
	s, _, root := rootLab(t)
	path := filepath.Join(root, "volumes", "vol_a.luks")
	st := workerFile(t, path, 8192)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	saveRegistry(t, root, &Registry{Version: RegistryVersion, Agents: map[string]*Agent{}})
	resp, out := s.Handle(t.Context(), Request{V: Version, Op: OpGiveVolume, Path: path, Agent: "agt_a", UID: rootAgentUID}, []*os.File{f})
	if !resp.OK {
		t.Fatal(resp)
	}
	closeFiles(out)
	var now unix.Stat_t
	if err = unix.Stat(path, &now); err != nil || now.Uid != rootAgentUID || now.Gid != rootAgentUID {
		t.Fatal("not the agent's", now.Uid, err)
	}
	a := &Agent{ID: "agt_a", UID: rootAgentUID, Volume: path, Device: st.Dev, Inode: st.Ino}
	saveRegistry(t, root, &Registry{Version: RegistryVersion, Agents: map[string]*Agent{"agt_a": a}})
	resp, out = s.Handle(t.Context(), Request{V: Version, Op: OpOpenVolume, Path: path, Write: true}, nil)
	if !resp.OK || len(out) != 1 {
		t.Fatal(resp)
	}
	got, _ := stat(out[0])
	closeFiles(out)
	if got.Ino != st.Ino {
		t.Fatal("another file opened")
	}
	// A volume of another UID than the registry's is refused.
	if err = os.Chown(path, rootAgentUID+1, rootAgentUID+1); err != nil {
		t.Fatal(err)
	}
	if resp, _ = s.Handle(t.Context(), Request{V: Version, Op: OpOpenVolume, Path: path}, nil); resp.OK || resp.Code != CodeRefused {
		t.Fatal(resp)
	}
	drive := filepath.Join(root, "staging", "output.ext4")
	workerFile(t, drive, 8192)
	if resp, _ = s.Handle(t.Context(), Request{V: Version, Op: OpGiveDrives, Agent: "agt_a", Drives: []Drive{{drive, 0o600}}}, nil); !resp.OK {
		t.Fatal(resp)
	}
	if err = unix.Stat(drive, &now); err != nil || now.Uid != rootAgentUID {
		t.Fatal("the drive is not the builder's", now.Uid, err)
	}
	a.Build = &Build{Output: drive}
	saveRegistry(t, root, &Registry{Version: RegistryVersion, Agents: map[string]*Agent{"agt_a": a}})
	if resp, _ = s.Handle(t.Context(), Request{V: Version, Op: OpReclaimDrives, Agent: "agt_a"}, nil); !resp.OK {
		t.Fatal(resp)
	}
	if err = unix.Stat(drive, &now); err != nil || now.Uid != rootWorkerUID || now.Mode&0o777 != 0o600 {
		t.Fatal("the drive is not the worker's again", now.Uid, err)
	}
}

// As root, a jail is reached only through root's directories, its platform
// socket is the VM's UID's, an unidentified run is absent, and its cleanup
// follows no link the VM's user left there.
func TestAsRootAJailIsObservedAndRemovedSafely(t *testing.T) {
	s, c, root := rootLab(t)
	run := &Run{ID: "00000000000000c3", Generation: 1, Phase: "RUNNING", PID: 1, StartTicks: "1"}
	run.Socket = filepath.Join(Jail(c.Layout.Jails, run.ID), "vsock")
	path := filepath.Join(root, "volumes", "vol_b.luks")
	st := workerFile(t, path, 4096)
	saveRegistry(t, root, &Registry{Version: RegistryVersion, Agents: map[string]*Agent{"agt_b": {ID: "agt_b", UID: rootAgentUID, Volume: path, Device: st.Dev, Inode: st.Ino, Run: run}}})
	jail := Jail(c.Layout.Jails, run.ID)
	if err := os.MkdirAll(jail, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(jail, rootAgentUID, rootAgentUID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := s.Handle(t.Context(), Request{V: Version, Op: OpObserve, Agent: "agt_b", Run: run.ID}, nil); resp.OK || resp.Code != CodeAbsent {
		t.Fatal("an unidentified VMM was observed", resp)
	}
	resp, out := s.Handle(t.Context(), Request{V: Version, Op: OpListen, Agent: "agt_b", Run: run.ID}, nil)
	if !resp.OK {
		t.Fatal(resp)
	}
	closeFiles(out)
	var sock unix.Stat_t
	if err := unix.Lstat(filepath.Join(jail, PlatformSocket), &sock); err != nil || sock.Uid != rootAgentUID || sock.Mode&0o777 != 0o600 {
		t.Fatal("the platform socket is not the VM's", sock.Uid, err)
	}
	keep := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(keep), filepath.Join(jail, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c.Layout.Cgroup, 0o700); err != nil {
		t.Fatal(err)
	}
	if resp, _ = s.Handle(t.Context(), Request{V: Version, Op: OpCleanup, Agent: "agt_b", Run: run.ID}, nil); !resp.OK {
		t.Fatal(resp)
	}
	if _, err := os.Lstat(filepath.Dir(jail)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the run's directory stayed", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("a link was followed", err)
	}
}
