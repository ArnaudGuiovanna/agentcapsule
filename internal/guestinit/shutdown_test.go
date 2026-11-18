//go:build linux

package guestinit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// The store is closed once the harness's processes are gone, whatever the
// harness's exit status: a harness killed by the guest's kernel for taking
// all its memory, or one that exits with an error, still leaves its store
// synchronized, unmounted and closed, and its error is still reported. A
// harness whose processes cannot be confirmed gone (its cgroup did not
// drain) keeps the store open: it is never unmounted under a live writer.
func TestStoreIsClosedOnceTheHarnessIsGone(t *testing.T) {
	root, err := os.MkdirTemp("", "acp-close-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err = os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	binary := harnessFixture(t, root)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	start := func(name string) *Process {
		t.Helper()
		data := filepath.Join(root, name)
		if err := os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(data, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
		// A barrier-only boot: the contract child offers health and fences.
		opts := ProcessOptions{Boot: HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean,
			Identity:      capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef", FenceOnly: true},
			DataDirectory: data, SupervisorUID: uint32(os.Geteuid())}, UID: uid, GID: gid,
			SocketPath: filepath.Join(root, name+".sock"), Entrypoint: []string{binary, "-test.run=^TestContractHarnessChild$", "--", "contract-child-" + name}}
		ready, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		p, err := StartHarness(t.Context(), ready, opts)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	closed := 0
	closeStore := func(context.Context) error { closed++; return nil }
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	// A harness that stops cleanly: the store is closed, no error.
	if err = StopHarnessAndCloseStore(ctx, start("stops"), closeStore); err != nil || closed != 1 {
		t.Fatal("a harness that stopped cleanly", err, closed)
	}

	// A harness killed on its own, as the guest's kernel kills one that
	// takes all its memory: the store is closed, and the kill is reported.
	killed := start("killed")
	if err = killed.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-killed.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the killed harness was not reaped")
	}
	closed = 0
	err = StopHarnessAndCloseStore(ctx, killed, closeStore)
	var exit *exec.ExitError
	if closed != 1 {
		t.Fatal("the store of a harness that was killed was not closed", err)
	}
	if !errors.As(err, &exit) {
		t.Fatal("the harness's kill was not reported", err)
	}
	// The store's own failure is reported with it.
	failed := errors.New("unmount refused")
	if err = StopHarnessAndCloseStore(ctx, killed, func(context.Context) error { return failed }); !errors.As(err, &exit) || !errors.Is(err, failed) {
		t.Fatal("the harness's and the store's failures", err)
	}

	// A harness whose processes are not confirmed gone: its cgroup did not
	// drain. The store stays open, and the drain's failure is reported.
	done := make(chan struct{})
	close(done)
	undrained := &Process{done: done, err: context.DeadlineExceeded, forced: true}
	closed = 0
	if err = StopHarnessAndCloseStore(ctx, undrained, closeStore); !errors.Is(err, context.DeadlineExceeded) || closed != 0 {
		t.Fatal("the store was closed under a harness not confirmed gone", err, closed)
	}

	// No harness started: the store is closed.
	closed = 0
	if err = StopHarnessAndCloseStore(ctx, nil, closeStore); err != nil || closed != 1 {
		t.Fatal("a store without a harness", err, closed)
	}
}
