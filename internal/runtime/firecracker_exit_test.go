//go:build linux

package runtime

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// TestVolumeHolderChild plays a VMM's hold on its volume for
// TestAnExitingVMMLeavesTheCensus: it opens the volume and takes its
// exclusive lock, as the patched Firecracker does, then, when told, closes
// it and lingers, as Firecracker does as it exits, then ends.
func TestVolumeHolderChild(t *testing.T) {
	volume := os.Getenv("AC_VOLUME_HOLDER")
	if volume == "" {
		return
	}
	f, err := os.OpenFile(volume, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	in := bufio.NewReader(os.Stdin)
	fmt.Println("locked")
	if _, err = in.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("closed")
	_, _ = in.ReadString('\n')
	os.Exit(0)
}

// A guest that restarts ends its VMM (ADR 012, question 6), and Firecracker
// closes its drive, which releases the volume's lock, before its process
// ends: between 59 and 110 ms from "Vmm is stopping" to its last line, on
// the KVM run of 2026-11-18. A census in that moment found a VMM alive
// without its lock and failed. A VMM that no longer has its volume open
// cannot write it any more: the census finds it gone, and its cleanup kills
// what is left of it. So does a VMM that exited, reaped or not. A VMM that
// has its volume open without the lock is still an error: an unpatched VMM,
// or another writer.
func TestAnExitingVMMLeavesTheCensus(t *testing.T) {
	volume := filepath.Join(t.TempDir(), "data.ext4")
	if err := os.WriteFile(volume, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestVolumeHolderChild$")
	cmd.Env = append(os.Environ(), "AC_VOLUME_HOLDER="+volume)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	out := bufio.NewReader(stdout)
	expect := func(want string) {
		t.Helper()
		line, err := out.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != want {
			t.Fatalf("the holder said %q, %v; want %q", line, err, want)
		}
	}
	pid := cmd.Process.Pid
	expect("locked")
	ticks, err := workerhelper.ProcIdentity(pid)
	if err != nil {
		t.Fatal(err)
	}
	alive := func() bool { got, err := workerhelper.ProcIdentity(pid); return err == nil && got == ticks }
	census := func(stage string, want bool) {
		t.Helper()
		if got, err := vmmWithVolume(observed(pid, volume), func() (bool, error) { return alive(), nil }); err != nil || got != want {
			t.Fatalf("%s: alive %v, error %v; want alive %v and no error", stage, got, err, want)
		}
	}
	census("a VMM that holds its volume", true)
	if _, err = stdin.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	expect("closed")
	census("a VMM that closed its volume as it exits", false)
	if _, err = stdin.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); alive(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the holder did not exit")
		}
	}
	census("a VMM that exited, not yet reaped", false)
	reaped = true
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	census("a VMM that exited and was reaped", false)

	// The safety rule: a live process with the volume open without its
	// lock, this test's own, is an error, not an absence.
	f, err := os.OpenFile(volume, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, err := vmmWithVolume(observed(os.Getpid(), volume), func() (bool, error) { return true, nil }); err == nil {
		t.Fatal("a VMM with its volume open without the lock was accepted; alive:", got)
	}
}
