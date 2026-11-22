//go:build linux

package runtime

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The VMM's log is cut once it passes its limit and goes with its run; a log
// whose run is gone goes at the census, and nothing else in logs/ (S-20).
func TestAVMMLogIsBoundedAndRemovedWithItsRun(t *testing.T) {
	defer func(limit int64, period time.Duration) { VMMLogCap, monitorPeriod = limit, period }(VMMLogCap, monitorPeriod)
	VMMLogCap, monitorPeriod = 1024, 10*time.Millisecond
	l := newAdoptionLab(t, 2, false)
	if err := os.MkdirAll(filepath.Join(l.h.root, "logs"), 0700); err != nil {
		t.Fatal(err)
	}
	run := l.runOf(t, "agent-00")
	log, err := l.h.openLog(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if st, err := log.Stat(); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("the log is not the host's alone", err)
	}
	if _, err = log.Write(bytes.Repeat([]byte("guest flood\n"), 1000)); err != nil {
		t.Fatal(err)
	}
	// The host's monitor cuts the log, and the VMM's next write follows.
	l.h.watch()
	defer l.h.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := os.Stat(l.h.logPath(run.ID))
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() <= VMMLogCap {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the log was not cut:", st.Size())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = log.Write([]byte("after the cut\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(l.h.logPath(run.ID))
	if err != nil || !bytes.HasPrefix(b, []byte(logCut)) || !bytes.HasSuffix(b, []byte("after the cut\n")) || int64(len(b)) > VMMLogCap {
		t.Fatalf("the cut log holds %q, %v", b, err)
	}
	// A log of a run that is gone, from a worker that died before its
	// cleanup, goes at the next census; another file stays.
	stale := strings.Repeat("ab", 8)
	for _, name := range []string{stale + ".log", "dispatch-crash.log"} {
		if err = os.WriteFile(filepath.Join(l.h.root, "logs", name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = l.h.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(l.h.root, "logs", stale+".log")); !os.IsNotExist(err) {
		t.Fatal("the stale log was kept:", err)
	}
	for _, name := range []string{run.ID + ".log", "dispatch-crash.log"} {
		if _, err = os.Stat(filepath.Join(l.h.root, "logs", name)); err != nil {
			t.Fatal(name, "was removed:", err)
		}
	}
	// The run's own cleanup removes its log.
	l.refuse["agent-00"] = ErrGeneration
	if _, err = l.h.ReconcileAgent(t.Context(), "agent-00"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(l.h.logPath(run.ID)); !os.IsNotExist(err) {
		t.Fatal("the log outlived its run:", err)
	}
}

// A debugging host keeps the log of a run that ended, for inspection, and
// the census keeps only the newest few of those; garbage collection removes
// them all (S-20).
func TestADebuggingHostKeepsOnlyItsNewestLogs(t *testing.T) {
	l := newAdoptionLab(t, 1, false)
	l.h.opts.SerialConsole = true
	if err := os.MkdirAll(filepath.Join(l.h.root, "logs"), 0700); err != nil {
		t.Fatal(err)
	}
	run := l.runOf(t, "agent-00")
	if err := os.WriteFile(l.h.logPath(run.ID), []byte("console"), 0600); err != nil {
		t.Fatal(err)
	}
	l.refuse["agent-00"] = ErrGeneration
	if _, err := l.h.ReconcileAgent(t.Context(), "agent-00"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.h.logPath(run.ID)); err != nil {
		t.Fatal("a debugging host lost the log of a run that ended:", err)
	}
	old := time.Now().Add(-time.Hour)
	for i := range debugLogsKept + 3 {
		id := fmt.Sprintf("%016x", 0xabc000+i)
		if err := os.WriteFile(l.h.logPath(id), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(l.h.logPath(id), old, old.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.h.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	left, err := l.h.listLogs()
	if err != nil || len(left) != debugLogsKept {
		t.Fatal("the census kept", len(left), err)
	}
	if n, err := CollectStaleLogsAt(t.Context(), l.h.root, true); err != nil || n != debugLogsKept {
		t.Fatal("a dry run counted", n, err)
	}
	if n, err := CollectStaleLogsAt(t.Context(), l.h.root, false); err != nil || n != debugLogsKept {
		t.Fatal("the collection removed", n, err)
	}
	if left, err = l.h.listLogs(); err != nil || len(left) != 0 {
		t.Fatal("logs left after the collection", left, err)
	}
}

// Without the debugging option the guest gets no serial console (S-20).
func TestTheGuestHasNoSerialConsoleUnlessDebugging(t *testing.T) {
	if args := bootArgs(false); strings.Contains(args, "console=ttyS0") || !strings.Contains(args, "8250.nr_uarts=0") || !strings.Contains(args, "reboot=k panic=1") {
		t.Fatal(args)
	}
	if args := bootArgs(true); !strings.Contains(args, "console=ttyS0") || strings.Contains(args, "nr_uarts") {
		t.Fatal(args)
	}
}

// The PID file in a jail its VMM's user owns is read without following a
// link, without waiting on a FIFO and at most a few bytes (L-15).
func TestTheJailPIDFileIsReadSafely(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("4242\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "valid"), []byte("4242\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if pid, err := readPIDFile(dir, "valid"); err != nil || pid != 4242 {
		t.Fatal(pid, err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "large"), bytes.Repeat([]byte("1"), 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "fifo", "large"} {
		done := make(chan error, 1)
		go func() { _, err := readPIDFile(dir, name); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal(name, "read as a PID file")
			}
		case <-time.After(2 * time.Second):
			t.Fatal(name, "blocked the read")
		}
	}
}

// The platform socket is bound and given to the VMM's user without following
// a link the VMM put in its place (L-15).
func TestThePlatformSocketIsNeverFollowed(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, nil, 0644); err != nil {
		t.Fatal(err)
	}
	// A link planted beforehand is replaced by the socket.
	if err := os.Symlink(victim, filepath.Join(dir, "vsock_5001")); err != nil {
		t.Fatal(err)
	}
	l, err := listenInJail(dir, "vsock_5001", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(filepath.Join(dir, "vsock_5001"))
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		t.Fatal("not the host's socket", st, err)
	}
	c, err := net.Dial("unix", filepath.Join(dir, "vsock_5001"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	l.Close()
	// A link swapped in between the bind and the change of owner is refused,
	// and its target keeps its mode.
	afterBind = func() {
		os.Remove(filepath.Join(dir, "vsock_5001"))
		if err := os.Symlink(victim, filepath.Join(dir, "vsock_5001")); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterBind = nil }()
	if l, err = listenInJail(dir, "vsock_5001", os.Getuid()); err == nil {
		l.Close()
		t.Fatal("a swapped link was accepted")
	}
	if st, err = os.Stat(victim); err != nil || st.Mode().Perm() != 0644 {
		t.Fatal("the link's target changed", st.Mode(), err)
	}
}

// A boot links the cached kernel into its jail and clones or copies the
// initrd with the boot's own files appended; the cache does not change
// (P-12).
func TestBootImagesAreLinkedIntoTheJail(t *testing.T) {
	h := &FirecrackerHost{root: t.TempDir()}
	for _, d := range []string{"bin", "jail"} {
		if err := os.Mkdir(filepath.Join(h.root, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{"kernel": "kernel image", "initrd": "initrd image"} {
		if err := os.WriteFile(filepath.Join(h.root, "bin", name), []byte(content), 0500); err != nil {
			t.Fatal(err)
		}
	}
	jail := filepath.Join(h.root, "jail")
	if err := h.placeBootImages(&HostAgent{}, jail, func(f *os.File) error { _, err := f.Write([]byte("+boot files")); return err }); err != nil {
		t.Fatal(err)
	}
	cached, err := os.Stat(filepath.Join(h.root, "bin", "kernel"))
	if err != nil {
		t.Fatal(err)
	}
	linked, err := os.Stat(filepath.Join(jail, "kernel"))
	if err != nil || !os.SameFile(cached, linked) || linked.Mode().Perm() != 0444 {
		t.Fatal("the kernel is not the cached image, readable by the VMM", err)
	}
	if b, err := os.ReadFile(filepath.Join(jail, "initrd")); err != nil || string(b) != "initrd image+boot files" {
		t.Fatalf("initrd %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(h.root, "bin", "initrd")); err != nil || string(b) != "initrd image" {
		t.Fatalf("the cached initrd changed: %q %v", b, err)
	}
	if st, err := os.Stat(filepath.Join(jail, "initrd")); err != nil || st.Mode().Perm() != 0444 {
		t.Fatal(err)
	}
}
