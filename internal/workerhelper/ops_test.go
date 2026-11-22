//go:build linux

package workerhelper

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openDir(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// The PID file in a jail its VMM's user owns is read without following a
// link, without waiting on a FIFO and at most a few bytes (L-15).
func TestTheJailPIDFileIsReadSafely(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "valid"), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := openDir(t, dir)
	if pid, err := readPIDFile(d, "valid"); err != nil || pid != 4242 {
		t.Fatal(pid, err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "large"), bytes.Repeat([]byte("1"), 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "fifo", "large"} {
		done := make(chan error, 1)
		go func() { _, err := readPIDFile(d, name); done <- err }()
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
	d := openDir(t, dir)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A link planted beforehand is replaced by the socket.
	if err := os.Symlink(victim, filepath.Join(dir, PlatformSocket)); err != nil {
		t.Fatal(err)
	}
	l, err := ListenInJail(d, PlatformSocket, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(filepath.Join(dir, PlatformSocket))
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Fatal("not the host's socket", st, err)
	}
	c, err := net.Dial("unix", filepath.Join(dir, PlatformSocket))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	l.Close()
	// A link swapped in between the bind and the change of owner is refused,
	// and its target keeps its mode.
	AfterBind = func() {
		os.Remove(filepath.Join(dir, PlatformSocket))
		if err := os.Symlink(victim, filepath.Join(dir, PlatformSocket)); err != nil {
			t.Error(err)
		}
	}
	defer func() { AfterBind = nil }()
	if l, err = ListenInJail(d, PlatformSocket, os.Getuid()); err == nil {
		l.Close()
		t.Fatal("a swapped link was accepted")
	}
	if st, err = os.Stat(victim); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatal("the link's target changed", st.Mode(), err)
	}
}

// A jail gets the kernel linked, the initrd copied with the appendix after
// it, the files linked and config.json read-only; the cgroup its limits. The
// cached images do not change (P-12).
func TestPrepareJailBuildsTheJailAndTheCgroup(t *testing.T) {
	dir := t.TempDir()
	open := func(name, content string, mode os.FileMode) *os.File {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	kernel, initrd, appendix := open("kernel", "kernel image", 0o444), open("initrd", "initrd image", 0o444), open("appendix", "+boot", 0o600)
	volume := open("volume", "volume", 0o600)
	jail := filepath.Join(dir, "jails", "firecracker", "00000000000000a1", "root")
	group := filepath.Join(dir, "group")
	p := JailPlan{Jail: jail, Kernel: kernel, Initrd: initrd, Appendix: appendix, Config: []byte(`{}`), Group: group,
		Files: []PlacedFile{{Name: "data.ext4", Kind: KindVolume, File: volume}}, Limits: Limits(Resources{VCPUs: 2, MemoryMiB: 512})}
	if err := (System{}).PrepareJail(p); err != nil {
		t.Fatal(err)
	}
	same := func(a, b string) bool {
		x, err1 := os.Stat(a)
		y, err2 := os.Stat(b)
		return err1 == nil && err2 == nil && os.SameFile(x, y)
	}
	if !same(filepath.Join(dir, "kernel"), filepath.Join(jail, "kernel")) || !same(filepath.Join(dir, "volume"), filepath.Join(jail, "data.ext4")) {
		t.Fatal("not linked")
	}
	if b, err := os.ReadFile(filepath.Join(jail, "initrd")); err != nil || string(b) != "initrd image+boot" {
		t.Fatal(string(b), err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "initrd")); string(b) != "initrd image" {
		t.Fatal("the cached initrd changed")
	}
	if st, err := os.Stat(filepath.Join(jail, "config.json")); err != nil || st.Mode().Perm() != 0o444 {
		t.Fatal(st, err)
	}
	if b, err := os.ReadFile(filepath.Join(group, "cpu.max")); err != nil || string(b) != "200000 100000" {
		t.Fatal(string(b), err)
	}
	// Cleanup removes the run's directory through base/firecracker, and
	// follows no link the VMM's user left in its jail.
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(jail, "escape")); err != nil {
		t.Fatal(err)
	}
	runs := openDir(t, filepath.Join(dir, "jails", "firecracker"))
	if err := (System{}).Cleanup(runs, "00000000000000a1", group); err == nil {
		// The test's cgroup directory holds the limits' files: rmdir fails.
		t.Fatal("removed a cgroup with files")
	}
	for _, name := range []string{"cpu.max", "memory.max", "pids.max", "memory.swap.max"} {
		os.Remove(filepath.Join(group, name))
	}
	if err := (System{}).Cleanup(runs, "00000000000000a1", group); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(jail)); !os.IsNotExist(err) {
		t.Fatal("the run's directory stayed", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("a link was followed", err)
	}
}

// openJail reaches a run's chroot only through directories of the owner,
// without a link.
func TestOpenJailRefusesLinksAndOtherOwners(t *testing.T) {
	base := filepath.Join(t.TempDir(), "jails")
	run := "00000000000000a1"
	if err := os.MkdirAll(Jail(base, run), 0o700); err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	jail, runs, err := openJail(base, run, me)
	if err != nil {
		t.Fatal(err)
	}
	jail.Close()
	runs.Close()
	if _, _, err = openJail(base, run, me+1); err == nil {
		t.Fatal("a tree of another owner was accepted")
	}
	if _, _, err = openJail(base, "../../etc", me); err == nil {
		t.Fatal("not a run")
	}
	link := filepath.Join(filepath.Dir(base), "link")
	if err = os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err = openJail(link, run, me); err == nil {
		t.Fatal("a base reached through a link")
	}
	if err = os.Rename(filepath.Join(base, "firecracker", run), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(base, "moved"), filepath.Join(base, "firecracker", run)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = openJail(base, run, me); err == nil {
		t.Fatal("a run's directory reached through a link")
	}
}
