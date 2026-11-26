//go:build linux

package workerhelper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"golang.org/x/sys/unix"
)

// fakeOps records what the server asks once a request passed its checks.
type fakeOps struct {
	mu    sync.Mutex
	calls []string
	owned []ownCall
	plan  *JailPlan
	runs  bool
}

type ownCall struct {
	ino      uint64
	uid, gid uint32
	mode     os.FileMode
}

func (f *fakeOps) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeOps) ownedCalls() []ownCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.owned)
}

func (f *fakeOps) Own(file *os.File, uid, gid uint32, mode os.FileMode, sync bool) error {
	st, err := stat(file)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.owned = append(f.owned, ownCall{st.Ino, uid, gid, mode})
	f.mu.Unlock()
	f.record("own")
	return nil
}
func (f *fakeOps) PrepareJail(p JailPlan) error { f.plan = &p; f.record("prepare"); return nil }
func (f *fakeOps) Start(StartPlan) error        { f.record("start"); return nil }
func (f *fakeOps) Observe(*os.File, Target) (Observation, error) {
	f.record("observe")
	return Observation{PID: 7, Ticks: "9"}, nil
}
func (f *fakeOps) Populated(string) (bool, error) { f.record("populated"); return false, nil }
func (f *fakeOps) Cleanup(runs *os.File, _, _ string) error {
	f.mu.Lock()
	f.runs = runs != nil
	f.mu.Unlock()
	f.record("cleanup")
	return nil
}
func (f *fakeOps) Dial(*os.File, uint32) (*os.File, error) {
	f.record("dial")
	return os.Open(os.DevNull)
}
func (f *fakeOps) Listen(*os.File, uint32) (*os.File, error) {
	f.record("listen")
	return os.Open(os.DevNull)
}
func (f *fakeOps) LinkProbe(*os.File, string) error { f.record("link"); return nil }
func (f *fakeOps) Sandbox(context.Context, SandboxPlan) ([]byte, error) {
	f.record("sandbox")
	return []byte("ok\n"), nil
}
func (f *fakeOps) Fetch(context.Context, FetchPlan) error { f.record("fetch"); return nil }

func (f *fakeOps) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// lab is a helper whose "root" is the test's account: the jails' tree and
// the worker's files belong to it. Agents' UIDs are other UIDs of the range.
type lab struct {
	t    *testing.T
	s    *Server
	ops  *fakeOps
	c    Config
	reg  *Registry
	root string
}

const agentUID = 20001

func newLab(t *testing.T) *lab { return newLabWith(t, nil) }

// newLabWith is newLab with change applied to the configuration first.
func newLabWith(t *testing.T, change func(*Config)) *lab {
	t.Helper()
	dir := t.TempDir()
	root, state := filepath.Join(dir, "host"), filepath.Join(dir, "vmm")
	for _, d := range []string{root, filepath.Join(root, "volumes"), filepath.Join(root, "bin"), filepath.Join(root, "corpus-staging"),
		filepath.Join(state, "jails", "firecracker"), filepath.Join(state, "bin")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	me := uint32(os.Getuid())
	c := Config{Layout: Layout{Root: root, Jails: filepath.Join(state, "jails"), Bin: filepath.Join(state, "bin"), Cgroup: filepath.Join(dir, "cgroup")},
		Owner: me, WorkerUID: me, WorkerGID: uint32(os.Getgid()), WorkerName: "worker", FirstUID: 20000, LastUID: 20100, InspectionUID: 61999,
		ImageRoots: []string{root}, DriveRoots: []string{root}, Jailer: filepath.Join(state, "bin", "jailer"), Firecracker: filepath.Join(state, "bin", "firecracker"),
		Debugfs: "/usr/sbin/debugfs", Executable: "/opt/agentcapsule/agentcapsule-worker", ArchiveFetch: []string{"/bin/false"}}
	if change != nil {
		change(&c)
	}
	ops := &fakeOps{}
	s, err := NewServer(c, ops)
	if err != nil {
		t.Fatal(err)
	}
	l := &lab{t: t, s: s, ops: ops, c: c, root: root, reg: &Registry{Version: RegistryVersion, Agents: map[string]*Agent{}}}
	l.save()
	return l
}

func (l *lab) save() {
	l.t.Helper()
	b, err := json.Marshal(l.reg)
	if err != nil {
		l.t.Fatal(err)
	}
	tmp := filepath.Join(l.root, "registry.tmp")
	if err = os.WriteFile(tmp, b, 0o600); err != nil {
		l.t.Fatal(err)
	}
	if err = os.Rename(tmp, filepath.Join(l.root, "registry.json")); err != nil {
		l.t.Fatal(err)
	}
}

// volume creates a worker-owned volume file in the managed directory.
func (l *lab) volume(name string) (string, unix.Stat_t) {
	l.t.Helper()
	path := filepath.Join(l.root, "volumes", name)
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		l.t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		l.t.Fatal(err)
	}
	return path, st
}

// agent registers an agent with a run in the given phase.
func (l *lab) agent(id string, uid uint32, phase string) *Agent {
	l.t.Helper()
	path, st := l.volume(id + ".luks")
	a := &Agent{ID: id, UID: uid, Volume: path, Device: st.Dev, Inode: st.Ino, Generation: 1}
	if phase != "" {
		run := &Run{ID: "00000000000000a1", Generation: 1, Phase: phase}
		run.Socket = filepath.Join(Jail(l.c.Layout.Jails, run.ID), "vsock")
		a.Run = run
	}
	l.reg.Agents[id] = a
	l.save()
	return a
}

func (l *lab) handle(req Request, files ...*os.File) (Response, error) {
	l.t.Helper()
	req.V = Version
	resp, out := l.s.Handle(l.t.Context(), req, files)
	closeFiles(out)
	if !resp.OK {
		return resp, &Error{Code: resp.Code, Message: resp.Error}
	}
	return resp, nil
}

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

func TestTheServerRefusesAnotherVersionAndUnknownOperations(t *testing.T) {
	l := newLab(t)
	resp, _ := l.s.Handle(t.Context(), Request{V: 2, Op: OpHello}, nil)
	if resp.OK || resp.Code != CodeUnsupported {
		t.Fatal(resp)
	}
	_, err := l.handle(Request{Op: "chown"})
	expectCode(t, err, CodeUnsupported)
	resp, err = l.handle(Request{Op: OpHello})
	if err != nil || resp.Version != Version || resp.Jails != l.c.Layout.Jails || resp.Cgroup != l.c.Layout.Cgroup {
		t.Fatal(resp, err)
	}
	// An operation with more descriptors than it takes is malformed.
	null, _ := os.Open(os.DevNull)
	defer null.Close()
	_, err = l.handle(Request{Op: OpObserve, Agent: "a", Run: "00000000000000a1"}, null)
	expectCode(t, err, CodeInvalid)
}

// A volume goes only to a UID of the provisioning range that no other agent
// holds, and only the worker's own 0600 file at the volume's name.
func TestGiveVolumeChecksTheUIDAndTheFile(t *testing.T) {
	l := newLab(t)
	path, _ := l.volume("vol_new.luks")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	other := l.agent("agt_other", agentUID, "")
	for name, req := range map[string]Request{
		"root":                {Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: 0},
		"below the range":     {Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: 19999},
		"above the range":     {Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: 20101},
		"the inspection UID":  {Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: 61999},
		"another agent's UID": {Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: other.UID},
		"outside the volumes": {Op: OpGiveVolume, Path: filepath.Join(l.root, "bin", "x"), Agent: "agt_new", UID: agentUID + 1},
		"another name":        {Op: OpGiveVolume, Path: other.Volume, Agent: "agt_new", UID: agentUID + 1},
		"a traversal":         {Op: OpGiveVolume, Path: filepath.Join(l.root, "volumes", "..", "registry.json"), Agent: "agt_new", UID: agentUID + 1},
	} {
		if _, err := l.handle(req, f); err == nil {
			t.Fatal(name, "was given")
		}
	}
	// Another agent's volume, even by its own name.
	g, err := os.OpenFile(other.Volume, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	_, err = l.handle(Request{Op: OpGiveVolume, Path: other.Volume, Agent: "agt_new", UID: agentUID + 1}, g)
	expectCode(t, err, CodeRefused)
	// A link in place of the volumes' directory.
	if err = os.Rename(filepath.Join(l.root, "volumes"), filepath.Join(l.root, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(l.root, "elsewhere"), filepath.Join(l.root, "volumes")); err != nil {
		t.Fatal(err)
	}
	if _, err = l.handle(Request{Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: agentUID + 1}, f); err == nil {
		t.Fatal("given through a link")
	}
	os.Remove(filepath.Join(l.root, "volumes"))
	if err = os.Rename(filepath.Join(l.root, "elsewhere"), filepath.Join(l.root, "volumes")); err != nil {
		t.Fatal(err)
	}
	if calls := l.ops.called(); len(calls) != 0 {
		t.Fatal("a refused request reached the operations:", calls)
	}
	// A file of another mode.
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = l.handle(Request{Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: agentUID + 1}, f)
	expectCode(t, err, CodeRefused)
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = l.handle(Request{Op: OpGiveVolume, Path: path, Agent: "agt_new", UID: agentUID + 1}, f); err != nil {
		t.Fatal(err)
	}
	st, _ := stat(f)
	if len(l.ops.ownedCalls()) != 1 || l.ops.ownedCalls()[0] != (ownCall{st.Ino, agentUID + 1, agentUID + 1, 0}) {
		t.Fatal(l.ops.ownedCalls())
	}
}

// A volume is opened only for a registered agent, as that agent's file.
func TestOpenVolumeOpensOnlyARegisteredAgentsVolume(t *testing.T) {
	l := newLab(t)
	stray, _ := l.volume("stray.luks")
	_, err := l.handle(Request{Op: OpOpenVolume, Path: stray})
	expectCode(t, err, CodeUnknownAgent)
	_, err = l.handle(Request{Op: OpOpenVolume, Path: filepath.Join(l.root, "registry.json")})
	expectCode(t, err, CodeRefused)
	_, err = l.handle(Request{Op: OpOpenVolume, Path: "/etc/shadow"})
	expectCode(t, err, CodeRefused)
	// The registry names a volume the worker still owns: not the agent's.
	a := l.agent("agt_a", agentUID, "")
	_, err = l.handle(Request{Op: OpOpenVolume, Path: a.Volume, Write: true})
	expectCode(t, err, CodeRefused)
	// An agent whose recorded UID is outside the range.
	a.UID = uint32(os.Getuid())
	l.save()
	_, err = l.handle(Request{Op: OpOpenVolume, Path: a.Volume})
	expectCode(t, err, CodeRefused)
}

// Build drives: a stopped builder's, under the drive roots, 0400 or 0600.
func TestGiveDrivesChecksTheAgentAndThePaths(t *testing.T) {
	l := newLab(t)
	staging := filepath.Join(l.root, "corpus-staging")
	drive := filepath.Join(staging, "output.ext4")
	if err := os.WriteFile(drive, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := l.handle(Request{Op: OpGiveDrives, Agent: "agt_none", Drives: []Drive{{drive, 0o600}}})
	expectCode(t, err, CodeUnknownAgent)
	l.agent("agt_busy", agentUID, "RUNNING")
	_, err = l.handle(Request{Op: OpGiveDrives, Agent: "agt_busy", Drives: []Drive{{drive, 0o600}}})
	expectCode(t, err, CodeBusy)
	l.agent("agt_b", agentUID+1, "")
	for name, d := range map[string]Drive{"a mode": {drive, 0o644}, "set-ID bits": {drive, 0o6600}, "outside the roots": {"/etc/passwd", 0o400}, "a traversal": {staging + "/../registry.json", 0o400}} {
		if _, err := l.handle(Request{Op: OpGiveDrives, Agent: "agt_b", Drives: []Drive{d}}); err == nil {
			t.Fatal(name, "was given")
		}
	}
	// A file of whole 4 KiB blocks only, with one link.
	if err = os.Link(drive, drive+".second"); err != nil {
		t.Fatal(err)
	}
	_, err = l.handle(Request{Op: OpGiveDrives, Agent: "agt_b", Drives: []Drive{{drive, 0o600}}})
	expectCode(t, err, CodeRefused)
	os.Remove(drive + ".second")
	if len(l.ops.called()) != 0 {
		t.Fatal(l.ops.called())
	}
	if _, err = l.handle(Request{Op: OpGiveDrives, Agent: "agt_b", Drives: []Drive{{drive, 0o600}}}); err != nil {
		t.Fatal(err)
	}
	if len(l.ops.ownedCalls()) != 1 || l.ops.ownedCalls()[0].uid != agentUID+1 || l.ops.ownedCalls()[0].mode != 0o600 {
		t.Fatal(l.ops.ownedCalls())
	}
	// Reclaimed: the recorded drives go back to the worker.
	l.reg.Agents["agt_b"].Build = &Build{Output: drive}
	l.save()
	if _, err = l.handle(Request{Op: OpReclaimDrives, Agent: "agt_b"}); err != nil {
		t.Fatal(err)
	}
	if last := l.ops.ownedCalls()[len(l.ops.ownedCalls())-1]; last.uid != l.c.WorkerUID || last.gid != l.c.WorkerGID || last.mode != 0o600 {
		t.Fatal(last)
	}
}

// A run's jail is built only for the registry's run, starting, from the
// registry's files: a run of another ID, phase or jail is refused.
func TestPrepareTakesOnlyTheRegistrysStartingRun(t *testing.T) {
	l := newLab(t)
	config := []byte(`{"boot-source":{}}`)
	_, err := l.handle(Request{Op: OpPrepare, Agent: "agt_none", Run: "00000000000000a1", Config: config})
	expectCode(t, err, CodeUnknownAgent)
	a := l.agent("agt_a", agentUID, "RUNNING")
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: config})
	expectCode(t, err, CodeRefused)
	a.Run.Phase = "STARTING"
	l.save()
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: "00000000000000b2", Config: config})
	expectCode(t, err, CodeRefused)
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: []byte("not json")})
	expectCode(t, err, CodeInvalid)
	// A socket the worker put elsewhere: under the runtime root, or a
	// legacy jail for a new boot.
	for _, base := range []string{filepath.Join(l.root, "elsewhere"), l.c.Layout.LegacyJails()} {
		a.Run.Socket = filepath.Join(Jail(base, a.Run.ID), "vsock")
		l.save()
		_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: config})
		expectCode(t, err, CodeRefused)
	}
	a.Run.Socket = filepath.Join(Jail(l.c.Layout.Jails, a.Run.ID), "vsock")
	// The kernel is the worker's, the volume still the worker's and not the
	// agent's: refused, before any operation.
	if err = os.WriteFile(filepath.Join(l.root, "bin", "kernel"), []byte("k"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(l.root, "bin", "initrd"), []byte("i"), 0o444); err != nil {
		t.Fatal(err)
	}
	l.save()
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: config})
	expectCode(t, err, CodeRefused)
	// A pinned image named by a digest that is not one.
	a.SystemImage = &BootImage{Kernel: "../../etc/passwd", Initrd: strings.Repeat("a", 64)}
	l.save()
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: config})
	expectCode(t, err, CodeRefused)
	// A fenced agent never boots.
	a.SystemImage, a.Fenced = nil, true
	l.save()
	_, err = l.handle(Request{Op: OpPrepare, Agent: "agt_a", Run: a.Run.ID, Config: config})
	expectCode(t, err, CodeRefused)
	if len(l.ops.called()) != 0 {
		t.Fatal(l.ops.called())
	}
}

// observe, dial, listen and cleanup concern the registry's run alone, in a
// jail of root's: a missing jail is an absence, a jail of another owner a
// refusal.
func TestRunOperationsCheckTheRunAndItsJail(t *testing.T) {
	l := newLab(t)
	a := l.agent("agt_a", agentUID, "RUNNING")
	_, err := l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: "00000000000000b2"})
	expectCode(t, err, CodeRefused)
	_, err = l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: a.Run.ID})
	expectCode(t, err, CodeAbsent)
	if err = os.MkdirAll(Jail(l.c.Layout.Jails, a.Run.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	resp, err := l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: a.Run.ID, Lock: true})
	if err != nil || resp.Observation == nil || resp.Observation.PID != 7 {
		t.Fatal(resp, err)
	}
	for _, op := range []string{OpDial, OpListen, OpPopulated, OpCleanup} {
		if _, err = l.handle(Request{Op: op, Agent: "agt_a", Run: a.Run.ID}); err != nil {
			t.Fatal(op, err)
		}
	}
	if !l.ops.runs {
		t.Fatal("cleanup did not reach the run's directory")
	}
	// A fence-only run has no platform channel.
	a.Run.FenceOnly = true
	l.save()
	_, err = l.handle(Request{Op: OpListen, Agent: "agt_a", Run: a.Run.ID})
	expectCode(t, err, CodeRefused)
	// A jail tree the worker could write is not the helper's.
	if err = os.Chmod(filepath.Join(l.c.Layout.Jails, "firecracker"), 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(l.c.Layout.Jails, "firecracker"), 0o700)
	_, err = l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: a.Run.ID})
	expectCode(t, err, CodeRefused)
	_, err = l.handle(Request{Op: OpCleanup, Agent: "agt_a", Run: a.Run.ID})
	expectCode(t, err, CodeRefused)
	// A legacy jail reached through a link the worker made.
	a.Run.FenceOnly = false
	a.Run.Socket = filepath.Join(Jail(l.c.Layout.LegacyJails(), a.Run.ID), "vsock")
	l.save()
	if err = os.Symlink(l.c.Layout.Jails, l.c.Layout.LegacyJails()); err != nil {
		t.Fatal(err)
	}
	_, err = l.handle(Request{Op: OpDial, Agent: "agt_a", Run: a.Run.ID})
	if err == nil {
		t.Fatal("a legacy jail was reached through a link")
	}
}

// A confined run names the configured debugfs, or a program of the
// worker's executable; nothing else runs.
func TestSandboxRunsOnlyTheConfiguredPrograms(t *testing.T) {
	l := newLab(t)
	run := func(r SandboxRequest) error {
		r.TimeoutMS, r.CPUMS = 1000, 1000
		_, err := l.handle(Request{Op: OpSandbox, Sandbox: &r})
		return err
	}
	expectCode(t, run(SandboxRequest{Program: "/bin/sh", Args: []string{"-c", "id"}}), CodeRefused)
	expectCode(t, run(SandboxRequest{Program: "/usr/sbin/debugfs", Self: "agentcapsule-luks-check"}), CodeRefused)
	expectCode(t, run(SandboxRequest{Program: "/usr/sbin/debugfs", Input: []byte("x")}), CodeInvalid)
	if err := run(SandboxRequest{Program: "/usr/sbin/debugfs", Args: []string{"-R", "stats"}}); err != nil {
		t.Fatal(err)
	}
	expectCode(t, run(SandboxRequest{Self: "agentcapsule-luks-check", Input: make([]byte, sandbox.MaxInput+1)}), CodeInvalid)
	if err := run(SandboxRequest{Self: "agentcapsule-luks-check", Input: []byte("key")}); err != nil {
		t.Fatal(err)
	}
	l.s.c.InspectionUID = 0
	expectCode(t, run(SandboxRequest{Program: "/usr/sbin/debugfs"}), CodeUnavailable)
}

func TestPreUpgradeHelperOnlyPermitsConfinedRestore(t *testing.T) {
	l := newLabWith(t, func(c *Config) { c.RestoreCheckOnly = true })
	path, _ := l.volume("copy")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	check := Request{Op: OpSandbox, Path: path, Sandbox: &SandboxRequest{
		Self: "agentcapsule-luks-check", TimeoutMS: 1000, CPUMS: 1000,
	}}
	if _, err := l.handle(check, f); err != nil {
		t.Fatal(err)
	}
	_, err = l.handle(check)
	expectCode(t, err, CodeRefused)
	for _, req := range []Request{{Op: OpStart}, {Op: OpGiveVolume}, {Op: OpFetchArchive},
		{Op: OpSandbox, Sandbox: &SandboxRequest{Program: "/usr/sbin/debugfs"}}} {
		_, err = l.handle(req, f)
		expectCode(t, err, CodeRefused)
	}
}

func TestFetchAndLinkChecksStayInTheirRoots(t *testing.T) {
	l := newLab(t)
	archives := filepath.Join(t.TempDir(), "archives")
	if err := os.Mkdir(archives, 0o750); err != nil {
		t.Fatal(err)
	}
	id := "arc_" + strings.Repeat("0", 32)
	_, err := l.handle(Request{Op: OpFetchArchive, Path: archives, Store: "ftp", Archive: id})
	expectCode(t, err, CodeInvalid)
	_, err = l.handle(Request{Op: OpFetchArchive, Path: archives, Store: "s3", Archive: "arc_../x"})
	expectCode(t, err, CodeInvalid)
	_, err = l.handle(Request{Op: OpFetchArchive, Path: archives, Store: "s3", Archive: id})
	expectCode(t, err, CodeRefused)
	if err = os.Chmod(archives, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = l.handle(Request{Op: OpFetchArchive, Path: archives, Store: "s3", Archive: id}); err != nil {
		t.Fatal(err)
	}
	_, err = l.handle(Request{Op: OpCheckLinkable, Paths: []string{"/etc/passwd"}})
	expectCode(t, err, CodeRefused)
	image := filepath.Join(l.root, "corpus.ext4")
	if err = os.WriteFile(image, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err = l.handle(Request{Op: OpCheckLinkable, Paths: []string{image}}); err != nil {
		t.Fatal(err)
	}
}

// The registry is the worker's file, reached without a link, of the version
// the runtime writes.
func TestTheRegistryIsReadSafely(t *testing.T) {
	l := newLab(t)
	l.agent("agt_a", agentUID, "RUNNING")
	path := filepath.Join(l.root, "registry.json")
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if _, err := l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: "00000000000000a1"}); err == nil {
		t.Fatal("a registry was read through a link")
	}
	os.Remove(path)
	if err := os.WriteFile(path, []byte(`{"version":2,"agents":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := l.handle(Request{Op: OpObserve, Agent: "agt_a", Run: "00000000000000a1"})
	expectCode(t, err, CodeRefused)
}

func TestTheJailFilesFollowTheRegistry(t *testing.T) {
	lay := Layout{Root: "/r"}
	a := &Agent{Volume: "/r/volumes/v.luks", Harness: &Image{Path: "/r/releases/h.ext4"}, Corpora: []Image{{"/r/corpora/a.ext4"}, {"/r/corpora/b.ext4"}},
		Build: &Build{Enricher: true, Output: "/r/corpus-staging/o.ext4"}}
	files, err := lay.JailFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name+"="+f.Source)
	}
	want := []string{"kernel=/r/bin/kernel", "data.ext4=/r/volumes/v.luks", "harness.ext4=/r/releases/h.ext4", "corpus0.ext4=/r/corpora/a.ext4",
		"corpus1.ext4=/r/corpora/b.ext4", "output.ext4=/r/corpus-staging/o.ext4"}
	if !slices.Equal(names, want) {
		t.Fatal(names)
	}
	if got := Limits(Resources{}); got["memory.max"] != "536870912" || got["cpu.max"] != "100000 100000" || got["pids.max"] != "32" {
		t.Fatal(got)
	}
	if _, err := lay.JailBase(&Run{ID: "00000000000000a1", Socket: "/r/jails/firecracker/00000000000000a1/root/vsock"}); err != nil {
		t.Fatal("the legacy jail", err)
	}
	if _, err := lay.JailBase(&Run{ID: "00000000000000a1", Socket: "/r/jails/firecracker/00000000000000b2/root/vsock"}); err == nil {
		t.Fatal("another run's jail")
	}
}
