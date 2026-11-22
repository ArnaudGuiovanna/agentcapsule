//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// observed is what the helper's observe answers about pid and volume.
func observed(pid int, volume string) workerhelper.Observation {
	open, locked, err := workerhelper.VolumeLock(pid, volume)
	o := workerhelper.Observation{PID: pid, Open: open, Locked: locked}
	if err != nil {
		o.LockError = err.Error()
	}
	return o
}

// fakeHelper stands in for the worker's helper: it records what the driver
// asks, and opens the test's own files where the helper opens the VM's.
type fakeHelper struct {
	mu      sync.Mutex
	calls   []string
	observe func(*HostAgent, bool) (workerhelper.Observation, error)
	drives  []workerhelper.Drive
}

func (f *fakeHelper) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeHelper) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeHelper) GiveVolume(_ context.Context, _ *os.File, path, agent string, uid uint32) error {
	f.record("give_volume %s %s %d", filepath.Base(path), agent, uid)
	return nil
}
func (f *fakeHelper) OpenVolume(_ context.Context, path string, write bool) (*os.File, error) {
	f.record("open_volume %s %v", filepath.Base(path), write)
	flags := os.O_RDONLY
	if write {
		flags = os.O_RDWR
	}
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0)
}
func (f *fakeHelper) GiveDrives(_ context.Context, a *HostAgent, drives []workerhelper.Drive) error {
	f.mu.Lock()
	f.drives = append(f.drives, drives...)
	f.mu.Unlock()
	f.record("give_drives %s %d", a.ID, len(drives))
	return nil
}
func (f *fakeHelper) ReclaimDrives(_ context.Context, a *HostAgent) error {
	f.record("reclaim_drives %s", a.ID)
	return nil
}
func (f *fakeHelper) CheckLinkable(_ context.Context, paths ...string) error {
	f.record("check_linkable %d", len(paths))
	return nil
}
func (f *fakeHelper) Prepare(_ context.Context, a *HostAgent, config []byte, appendix *os.File) error {
	var c map[string]any
	if json.Unmarshal(config, &c) != nil {
		return errors.New("config.json")
	}
	f.record("prepare %s %s", a.ID, a.Run.Phase)
	return nil
}
func (f *fakeHelper) Start(_ context.Context, a *HostAgent, log *os.File) error {
	f.record("start %s", a.ID)
	return nil
}
func (f *fakeHelper) Observe(_ context.Context, a *HostAgent, lock bool) (workerhelper.Observation, error) {
	f.record("observe %s %v", a.ID, lock)
	if f.observe != nil {
		return f.observe(a, lock)
	}
	return workerhelper.Observation{PID: os.Getpid(), Ticks: "1", Open: lock, Locked: lock}, nil
}
func (f *fakeHelper) Populated(_ context.Context, a *HostAgent) (bool, error) {
	f.record("populated %s", a.ID)
	return false, nil
}
func (f *fakeHelper) Cleanup(_ context.Context, id string, run *VMRun) error {
	f.record("cleanup %s %s", id, run.ID)
	return nil
}
func (f *fakeHelper) Dial(context.Context, *HostAgent) (net.Conn, error) {
	return nil, workerhelper.ErrHelperUnavailable
}
func (f *fakeHelper) Listen(context.Context, *HostAgent) (*net.UnixListener, error) {
	return nil, workerhelper.ErrHelperUnavailable
}

// helperHost is a host driver of a worker that is not root: its operations
// that need root go to fake.
func helperHost(t *testing.T, fake *fakeHelper) *FirecrackerHost {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"admission", "volumes", "locks", "logs", "credentials", "platform", "bin"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h := &FirecrackerHost{root: root, cgroup: filepath.Join(root, "groups"), priv: fake, jails: filepath.Join(t.TempDir(), "jails")}
	h.opts = FirecrackerOptions{MaxActive: 4, BootTimeout: 5 * time.Second, DriveLimits: DefaultDriveLimits,
		Ready:   func(context.Context, string) error { return nil },
		Confirm: func(context.Context, string, VMRun) error { return nil },
		Adopt:   func(context.Context, string, VMRun) error { return nil }}
	path := filepath.Join(root, "volumes", "a")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents["a"] = &HostAgent{ID: "a", UID: 20000, Volume: path, Device: uint64(id.Dev), Inode: id.Ino}
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

// A boot, its observation and its stop ask root for each step, in order,
// for the agent's registered run, and put the run's jail under the helper's
// chroot base (ADR 024).
func TestABootAsksTheHelperForWhatNeedsRoot(t *testing.T) {
	fake := &fakeHelper{}
	h := helperHost(t, fake)
	run, err := h.Start(t.Context(), "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if run.Phase != "RUNNING" || run.PID != os.Getpid() || !strings.HasPrefix(run.Socket, h.jails+"/firecracker/"+run.ID+"/") {
		t.Fatal(run)
	}
	if err = h.Stop(t.Context(), "a", 1); err != nil {
		t.Fatal(err)
	}
	want := []string{"open_volume a true", "prepare a STARTING", "start a", "observe a false", "observe a true", "cleanup a " + run.ID}
	if got := fake.called(); !slices.Equal(got, want) {
		t.Fatalf("asked %q, want %q", got, want)
	}
	runs, err := h.runs("")
	if err != nil || len(runs) != 0 {
		t.Fatal(runs, err)
	}
}

// A census that the helper does not answer retires nothing: the run, its
// slot and its VMM stay until the helper answers. Only an identification
// that failed is an absence.
func TestAnUnansweredHelperIsNeverAnAbsence(t *testing.T) {
	fake := &fakeHelper{}
	h := helperHost(t, fake)
	run, err := h.Start(t.Context(), "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	fake.observe = func(*HostAgent, bool) (workerhelper.Observation, error) {
		return workerhelper.Observation{}, fmt.Errorf("%w: connection refused", workerhelper.ErrHelperUnavailable)
	}
	if _, err = h.Reconcile(t.Context()); !errors.Is(err, workerhelper.ErrHelperUnavailable) {
		t.Fatal(err)
	}
	if runs, err := h.runs(""); err != nil || runs["a"].ID != run.ID {
		t.Fatal("an unanswered census retired the run", runs, err)
	}
	if slices.ContainsFunc(fake.called(), func(c string) bool { return strings.HasPrefix(c, "cleanup") }) {
		t.Fatal("an unanswered census cleaned the run up")
	}
	// A second look that cannot be made keeps the VMM.
	if alive, err := vmmWithVolume(workerhelper.Observation{PID: 1, Open: true}, func() (bool, error) { return false, workerhelper.ErrHelperUnavailable }); !alive || err == nil {
		t.Fatal("a VMM was given up on an unanswered second look", alive, err)
	}
	fake.observe = func(*HostAgent, bool) (workerhelper.Observation, error) {
		return workerhelper.Observation{}, fmt.Errorf("%w: no PID file", workerhelper.ErrAbsent)
	}
	if _, err = h.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if runs, err := h.runs(""); err != nil || len(runs) != 0 {
		t.Fatal("an absent VMM's run stayed", runs, err)
	}
	if !slices.Contains(fake.called(), "cleanup a "+run.ID) {
		t.Fatal("an absent VMM's run was not cleaned up", fake.called())
	}
}

// A seal, a copy and an install open the VM's volume through root; a
// builder's drives are given to it, and reclaimed when its build ends.
func TestVolumesAndDrivesGoThroughTheHelper(t *testing.T) {
	fake := &fakeHelper{}
	h := helperHost(t, fake)
	a, err := h.agent(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WithStoppedVolume(t.Context(), "a", 0, a.Device, a.Inode, func(r io.Reader) error { _, err := io.ReadAll(r); return err }); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(h.root, "corpus-staging")
	if err = os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	drives := BuildDrives{Source: filepath.Join(staging, "source.bin"), Output: filepath.Join(staging, "output.ext4")}
	for _, p := range []string{drives.Source, drives.Output} {
		if err = os.WriteFile(p, make([]byte, 8192), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err = h.SetBuildDrives(t.Context(), "a", &drives); err != nil {
		t.Fatal(err)
	}
	if err = h.SetBuildDrives(t.Context(), "a", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = h.SealAgent(t.Context(), "a", 1); err != nil {
		t.Fatal(err)
	}
	want := []string{"open_volume a false", "check_linkable 2", "give_drives a 2", "reclaim_drives a", "open_volume a true"}
	if got := fake.called(); !slices.Equal(got, want) {
		t.Fatalf("asked %q, want %q", got, want)
	}
	if !slices.Contains(fake.drives, workerhelper.Drive{Path: drives.Output, Mode: 0o600}) || !slices.Contains(fake.drives, workerhelper.Drive{Path: drives.Source, Mode: 0o400}) {
		t.Fatal(fake.drives)
	}
}

// The helper reads the registry the runtime writes: every field it uses
// keeps its name, and a jail gets the drives config.json names.
func TestTheHelperReadsTheRuntimesRegistry(t *testing.T) {
	h := admissionHost(t)
	digest := strings.Repeat("ab", 32)
	run := &VMRun{Incarnation: 1, ID: "0123456789abcdef", Generation: 3, Phase: "RUNNING", PID: 42, StartTicks: "99", FenceOnly: true}
	run.Socket = filepath.Join(h.jail(run), "vsock")
	want := &HostAgent{ID: "a", UID: 10000, Volume: filepath.Join(h.root, "volumes", "a"), Device: 7, Inode: 8, Generation: 3, Run: run,
		Resources: VMResources{VCPUs: 2, MemoryMiB: 512, VolumeMiB: 128}, SystemImage: &BootImageID{Kernel: digest, Initrd: digest},
		Harness: &HarnessImage{Path: "/h.ext4", Digest: "sha256:" + digest, Entrypoint: []string{"/bin/x"}},
		Corpora: []CorpusImage{{Path: "/c0.ext4", Digest: "sha256:" + digest, UUID: "u", Mount: "docs"}},
		Build:   &BuildDrives{Enricher: true, Output: "/o.ext4"}}
	if err := h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents = map[string]*HostAgent{"a": want}
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(h.registryPath())
	if err != nil {
		t.Fatal(err)
	}
	r, err := workerhelper.DecodeRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Agents["a"]; got == nil || *got.Run != *helperView(want).Run || got.UID != want.UID || got.Device != 7 || got.Inode != 8 ||
		got.Resources != workerhelper.Resources(want.Resources) || *got.SystemImage != *helperView(want).SystemImage || got.Harness.Path != "/h.ext4" ||
		len(got.Corpora) != 1 || got.Corpora[0].Path != "/c0.ext4" || *got.Build != *helperView(want).Build {
		t.Fatalf("%+v", got)
	}
	extra, _, err := extraDrives(&HostAgent{Harness: want.Harness, Corpora: want.Corpora}, DefaultDriveLimits)
	if err == nil {
		t.Fatal("drives of files that do not exist")
	}
	files, err := (workerhelper.Layout{Root: h.root}).JailFiles(helperView(want))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	if !slices.Equal(names, []string{"kernel", "data.ext4", "harness.ext4", "corpus0.ext4", "output.ext4"}) {
		t.Fatal(names, extra)
	}
}

// The files a boot appends to its initrd are padded as they were when they
// were written into the initrd's copy.
func TestTheBootAppendixKeepsTheInitrdsOffsets(t *testing.T) {
	b := &offsetBuffer{base: 6, pos: 6}
	if _, err := b.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if at, err := b.Seek(0, io.SeekCurrent); err != nil || at != 8 {
		t.Fatal(at, err)
	}
	if _, err := b.Seek(2, io.SeekStart); err == nil {
		t.Fatal("seek into the initrd")
	}
	f, err := memfile(t.TempDir(), b.buf)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, err := io.ReadAll(f); err != nil || string(got) != "ab" {
		t.Fatal(string(got), err)
	}
}
