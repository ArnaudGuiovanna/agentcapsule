//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Go projections of the runs of spec/fair_admission.qnt on an agent's
// admission queue: WithApplication is a shared client, WithBarrier an
// exclusive one, all for agent "a". spec/projections.md lists every run and
// its projection.

type admissionClient struct {
	queued, entered chan struct{}
	release         chan struct{}
	done            chan error
}

// startAdmission queues one client and returns once it is in the queue.
func startAdmission(t *testing.T, h *FirecrackerHost, ctx context.Context, shared bool, target string) *admissionClient {
	t.Helper()
	c := &admissionClient{queued: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{}), done: make(chan error, 1)}
	peer := &FirecrackerHost{root: h.root, admissionHook: func(stage, _ string) {
		if stage == "queued" {
			close(c.queued)
		}
	}}
	fn := func(ctx context.Context) error {
		close(c.entered)
		select {
		case <-c.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	go func() {
		if shared {
			c.done <- peer.WithApplication(ctx, target, fn)
		} else {
			c.done <- peer.WithBarrier(ctx, target, fn)
		}
	}()
	select {
	case <-c.queued:
	case err := <-c.done:
		t.Fatal("client left before it was queued:", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client was not queued")
	}
	return c
}

func (c *admissionClient) admitted(t *testing.T) {
	t.Helper()
	select {
	case <-c.entered:
	case err := <-c.done:
		t.Fatal("client left before it was admitted:", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client was not admitted")
	}
}

func (c *admissionClient) waiting(t *testing.T) {
	t.Helper()
	select {
	case <-c.entered:
		t.Fatal("client overtook the queue")
	case <-time.After(100 * time.Millisecond):
	}
}

func (c *admissionClient) finish(t *testing.T) {
	t.Helper()
	close(c.release)
	select {
	case err := <-c.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not finish")
	}
}

// noOvertakeTest (fairAdmissionShared): the watched shared client 1 waits
// behind the exclusive client 3. Once 3 finishes, the leading shared clients
// 1 and 2 run together, and 3, queued again behind them, waits.
func TestNoOvertake(t *testing.T) {
	h := admissionHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	// init: queue (3, 1). admit(3).
	three := startAdmission(t, h, ctx, false, "a")
	three.admitted(t)
	one := startAdmission(t, h, ctx, true, "a")
	// enqueue(2), then 3 queues again. The model queues 3 again after it
	// finishes; queued before, it is still behind 1 and 2, the same queue.
	two := startAdmission(t, h, ctx, true, "a")
	again := startAdmission(t, h, ctx, false, "a")
	one.waiting(t)
	two.waiting(t)
	// finish(3), admit(1), admit(2): expect s.active == Set(1, 2).
	three.finish(t)
	one.admitted(t)
	two.admitted(t)
	again.waiting(t)
	// finish(1): expect s.done.
	one.finish(t)
	again.waiting(t)
	two.finish(t)
	again.admitted(t)
	again.finish(t)
}

// deadOwnerTest (fairAdmissionExclusive): the shared client 2 is admitted in
// another process, which is killed (SIGKILL). Its released kernel lock lets
// the watched exclusive client 1 in, and 2, queued again behind 1, waits.
func TestDeadOwner(t *testing.T) {
	h := admissionHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	// init: queue (2, 1). admit(2), in the child process.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeadOwnerChild$")
	cmd.Env = append(os.Environ(), "AC_DEAD_OWNER_ROOT="+h.root)
	log, err := os.Create(filepath.Join(h.root, "child.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for {
		if _, err = os.Stat(filepath.Join(h.root, "ready")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	one := startAdmission(t, h, ctx, false, "a")
	one.waiting(t)
	// crash(2): the owner dies; only its released kernel lock says so.
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exited *exec.ExitError
	if err = cmd.Wait(); !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal(err)
	}
	// prune, enqueue(2), admit(1).
	two := startAdmission(t, h, ctx, true, "a")
	one.admitted(t)
	// admit(2).fail(): 2 is behind the exclusive 1.
	two.waiting(t)
	one.finish(t)
	two.admitted(t)
	two.finish(t)
}

// TestDeadOwnerChild is the shared owner that TestDeadOwner kills.
func TestDeadOwnerChild(t *testing.T) {
	root := os.Getenv("AC_DEAD_OWNER_ROOT")
	if root == "" {
		return
	}
	h := &FirecrackerHost{root: root, admissionHook: func(stage, _ string) {
		if stage == "admitted" {
			if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			select {} // killed here, holding its shared admission
		}
	}}
	if err := h.WithApplication(t.Context(), "a", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
