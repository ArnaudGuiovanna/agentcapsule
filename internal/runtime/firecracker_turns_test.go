//go:build linux

package runtime

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

// A long boot of one agent holds that agent's lock, never host.lock: the
// platform channel's accept check of another agent's VM reads the registry
// without waiting, even while host.lock itself is held (S-03).
func TestPlatformAcceptCheckDoesNotWait(t *testing.T) {
	l := newAdoptionLab(t, 2, false)
	l.h.peer = func(*HostAgent, *syscall.Ucred) error { return nil }
	run := l.runOf(t, "agent-00")
	booting, err := l.h.lockAgent(t.Context(), "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	defer booting()
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.h.locked(t.Context(), func(*hostRegistry) error { close(held); <-release; return nil })
	}()
	<-held
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	check := l.h.platformCheck("agent-00", run.ID, run.Generation)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	peer := &syscall.Ucred{Pid: int32(run.PID), Uid: 10000, Gid: 10000}
	if err = check(ctx, peer); err != nil {
		t.Fatal("the accept check waited:", err)
	}
	for _, wrong := range []*syscall.Ucred{{Pid: int32(run.PID) + 1, Uid: 10000, Gid: 10000}, {Pid: int32(run.PID), Uid: 10001, Gid: 10001}} {
		if err = check(ctx, wrong); !errors.Is(err, ErrGeneration) {
			t.Fatal("another peer accepted:", err)
		}
	}
	if err = l.h.platformCheck("agent-00", run.ID, run.Generation+1)(ctx, peer); !errors.Is(err, ErrGeneration) {
		t.Fatal("another generation accepted:", err)
	}
}

// runOf returns agent id's recorded run.
func (l *adoptionLab) runOf(t *testing.T, id string) VMRun {
	t.Helper()
	a, err := l.h.agent(t.Context(), id)
	if err != nil || a == nil || a.Run == nil {
		t.Fatal("no run for", id, err)
	}
	return *a.Run
}

// The census does not wait for an agent that another operation holds (a
// boot, a stop, a volume copy): it leaves its run as is and goes on.
func TestTheCensusSkipsAnAgentInUse(t *testing.T) {
	l := newAdoptionLab(t, 3, false)
	busy, err := l.h.lockAgent(t.Context(), "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	runs, err := l.h.Reconcile(ctx)
	if err != nil || len(runs) != 3 {
		t.Fatal("the census waited for a busy agent:", runs, err)
	}
	l.expectAdopted(t, "a census beside a busy agent", map[string]int{"agent-00": 1, "agent-02": 1})
	busy()
	// An agent whose turn another caller holds is skipped as well.
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.h.WithApplication(t.Context(), "agent-02", func(context.Context) error { close(held); <-release; return nil })
	}()
	<-held
	if _, err = l.h.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	l.expectAdopted(t, "a census beside a call", map[string]int{"agent-00": 1, "agent-01": 1})
	if err = l.h.TryBarrier(ctx, "agent-02", func(context.Context) error { return nil }); !errors.Is(err, ErrAgentBusy) {
		t.Fatal("a turn in use was taken at once:", err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = l.h.TryBarrier(ctx, "agent-02", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// An eviction takes its victim's exclusive turn in the victim's FIFO: it
// waits for the calls already admitted on the victim, the calls that come
// after it wait for it, and other agents never wait (S-02, ADR 017).
func TestAnEvictionWaitsInItsVictimsQueue(t *testing.T) {
	h := admissionHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := h.WithEviction(ctx, "b", func(context.Context) error { return nil }); !errors.Is(err, ErrAdmissionLost) {
		t.Fatal("an eviction outside an exclusive turn:", err)
	}
	release := holdApplication(t, h, "b")
	order := make(chan string, 4)
	evicted := make(chan error, 1)
	queued := make(chan struct{})
	evictor := &FirecrackerHost{root: h.root, admissionHook: func(stage, target string) {
		if stage == "queued" && target == "b" {
			close(queued)
		}
	}}
	go func() {
		evicted <- evictor.WithBarrier(ctx, "a", func(ctx context.Context) error {
			return evictor.WithEviction(ctx, "b", func(ctx context.Context) error {
				// Within the eviction the scope holds both agents.
				if err := evictor.WithBarrier(ctx, "b", func(context.Context) error { return nil }); err != nil {
					return err
				}
				order <- "eviction"
				return nil
			})
		})
	}()
	<-queued
	later := make(chan error, 1)
	laterQueued := make(chan struct{})
	caller := &FirecrackerHost{root: h.root, admissionHook: func(stage, target string) {
		if stage == "queued" {
			close(laterQueued)
		}
	}}
	go func() {
		later <- caller.WithApplication(ctx, "b", func(context.Context) error { order <- "later call"; return nil })
	}()
	<-laterQueued
	// Agent c is not held by any of this.
	if err := h.WithBarrier(ctx, "c", func(context.Context) error { order <- "other agent"; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := <-order; got != "other agent" {
		t.Fatal(got)
	}
	select {
	case got := <-order:
		t.Fatal("ran before the admitted call ended:", got)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	for _, ch := range []chan error{evicted, later} {
		if err := <-ch; err != nil {
			t.Fatal(err)
		}
	}
	if first, second := <-order, <-order; first != "eviction" || second != "later call" {
		t.Fatal("not in the victim's order:", first, second)
	}
}
