//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestAdmissionRegistryMigrationKeepsLiveBarrier(t *testing.T) {
	h := admissionHost(t)
	const id = "0123456789abcdef0123456789abcdef"
	f, err := os.OpenFile(h.requestLock(id), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Version = 1
		r.LegacyBarriers = []admissionWaiter{{ID: id, Target: "a"}}
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if err = h.WithApplication(ctx, func(context.Context) error { t.Error("migration discarded live barrier"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h.root, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r hostRegistry
	if err = json.Unmarshal(b, &r); err != nil || r.Version != 2 || len(r.LegacyBarriers) != 0 || len(r.Admissions) != 1 || r.Admissions[0].ID != id {
		t.Fatal(r, err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = h.WithApplication(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Filesystem admission tests deliberately use no VMM or synthetic placement
// callback. The real KVM campaign checks eviction and durable barrier effects.
func admissionHost(t *testing.T) *FirecrackerHost {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"admission", "volumes"} {
		if err := os.Mkdir(filepath.Join(root, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	h := &FirecrackerHost{root: root}
	if err := h.locked(t.Context(), func(r *hostRegistry) error {
		for i, id := range []string{"a", "b", "c"} {
			r.Agents[id] = &HostAgent{ID: id, UID: uint32(10000 + i), Volume: filepath.Join(root, "volumes", id)}
		}
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func holdApplication(t *testing.T, h *FirecrackerHost) func() {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.WithApplication(t.Context(), func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	<-entered
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(release)
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

func TestBarrierAdmissionFIFOAndOrdinaryBackpressure(t *testing.T) {
	h := admissionHost(t)
	release := holdApplication(t, h)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	queued := make(chan string, 3)
	finished := make(chan error, 3)
	order := make(chan string, 3)
	for _, id := range []string{"a", "b", "c"} {
		peer := &FirecrackerHost{root: h.root, admissionHook: func(stage, target string) {
			if stage == "queued" {
				queued <- target
			}
		}}
		go func() {
			finished <- peer.WithBarrier(ctx, id, func(ctx context.Context) error { order <- id; return nil })
		}()
		if got := <-queued; got != id {
			t.Fatal(got, id)
		}
	}
	probe, cancelProbe := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancelProbe()
	if err := h.WithApplication(probe, func(context.Context) error { t.Error("ordinary work overtook barrier"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case got := <-order:
		t.Fatal("barrier bypassed active application:", got)
	default:
	}
	release()
	for range 3 {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
	got := []string{<-order, <-order, <-order}
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatal("not FIFO:", got)
	}
	var escaped context.Context
	if err := h.WithApplication(ctx, func(scoped context.Context) error { escaped = scoped; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.WithApplication(escaped, func(context.Context) error { return nil }); !errors.Is(err, ErrAdmissionLost) {
		t.Fatal("expired scope reused:", err)
	}
}

func TestCanceledBarrierDoesNotReserveCapacity(t *testing.T) {
	h := admissionHost(t)
	release := holdApplication(t, h)
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := h.WithBarrier(ctx, "a", func(context.Context) error { t.Error("barrier ran through active application"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := h.WithApplication(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Fatal("canceled request still blocks work:", err)
	}
}

func TestBarrierAdmissionWorkerSIGKILL(t *testing.T) {
	for _, point := range []string{"queued", "admitted"} {
		t.Run(point, func(t *testing.T) {
			h := admissionHost(t)
			release := func() {}
			if point == "queued" {
				release = holdApplication(t, h)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBarrierAdmissionWorkerChild$", "-test.v")
			cmd.Env = append(os.Environ(), "AC_ADMISSION_CHILD_ROOT="+h.root, "AC_ADMISSION_CHILD_POINT="+point)
			log, err := os.Create(filepath.Join(h.root, "child.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout = log
			cmd.Stderr = log
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
			probe, cancelProbe := context.WithTimeout(ctx, 40*time.Millisecond)
			err = h.WithApplication(probe, func(context.Context) error { return nil })
			cancelProbe()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("live owner's reservation ignored:", err)
			}
			next := make(chan error, 1)
			go func() { next <- h.WithBarrier(ctx, "b", func(context.Context) error { return nil }) }()
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal(err)
			}
			release()
			if err = <-next; err != nil {
				t.Fatal("dead worker prevented next barrier:", err)
			}
			if err = h.WithApplication(ctx, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork(t *testing.T) {
	h := admissionHost(t)
	release := holdApplication(t, h)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	queued := make(chan string, 1)
	order := make(chan string, 8)
	done := make(chan error, 8)
	for _, item := range []struct {
		name, target string
		shared       bool
	}{
		{"barrier-before", "a", false}, {"ordinary", "", true}, {"barrier-after-1", "b", false}, {"barrier-after-2", "c", false},
	} {
		peer := &FirecrackerHost{root: h.root, admissionHook: func(stage, target string) {
			if stage == "queued" {
				queued <- item.name
			}
		}}
		go func() {
			fn := func(context.Context) error { order <- item.name; return nil }
			if item.shared {
				done <- peer.WithApplication(ctx, fn)
			} else {
				done <- peer.WithBarrier(ctx, item.target, fn)
			}
		}()
		if got := <-queued; got != item.name {
			t.Fatal(got)
		}
	}
	release()
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	got := []string{<-order, <-order, <-order, <-order}
	if !reflect.DeepEqual(got, []string{"barrier-before", "ordinary", "barrier-after-1", "barrier-after-2"}) {
		t.Fatal(got)
	}
	// Two leading shared callbacks can coexist, but neither may upgrade to an
	// exclusive scope while retaining its shared kernel lock.
	release = holdApplication(t, h)
	defer release()
	if err := h.WithApplication(ctx, func(scoped context.Context) error {
		return h.WithBarrier(scoped, "a", func(context.Context) error { return nil })
	}); !errors.Is(err, ErrAdmissionBusy) {
		t.Fatal("shared scope upgraded:", err)
	}
}

func TestBarrierAdmissionWorkerChild(t *testing.T) {
	root := os.Getenv("AC_ADMISSION_CHILD_ROOT")
	if root == "" {
		return
	}
	point := os.Getenv("AC_ADMISSION_CHILD_POINT")
	h := &FirecrackerHost{root: root, admissionHook: func(stage, target string) {
		if stage == point {
			if err := os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			select {}
		}
	}}
	if err := h.WithBarrier(t.Context(), "a", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary not reached")
}
