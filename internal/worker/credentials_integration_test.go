//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func hostCredentials(t *testing.T, root string, run runtime.VMRun) capsuleprotocol.Credentials {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "credentials", run.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c capsuleprotocol.Credentials
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal("invalid private credential fixture")
	}
	return c
}

// Only the renewal decision clock is injected; TLS and the guest retain the
// actual system clock. Protocol tests separately exercise expired TLS handshakes.
func renewalClock(t *testing.T, c capsuleprotocol.Credentials, mode string) time.Time {
	t.Helper()
	before, after, err := c.Validity()
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "expired":
		return after.Add(time.Second)
	case "rollback":
		return before.Add(-time.Second)
	default:
		return after.Add(-runtime.CredentialRenewalMargin)
	}
}

func TestCredentialRotationPreservesEffectsFencesAndAdmission(t *testing.T) {
	w, _, _, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	event := harnessstore.Event{ID: "before-rotation", Subjects: []string{"agent/a", "event/before-rotation"}, Body: []byte("local")}
	receipt, err := w.Send(t.Context(), "a", event)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Fence(t.Context(), "a", "request/blocked"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"margin", "expired", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			old, err := w.Start(t.Context(), "a")
			if err != nil {
				t.Fatal(err)
			}
			credentials := hostCredentials(t, options.Root, old)
			now := renewalClock(t, credentials, mode)
			w.credentialNow = func() time.Time { return now }
			w.afterCredentialStop = func() { w.credentialNow = time.Now }
			calls := 0
			err = w.WithDeliveryAdmission(t.Context(), func(ctx context.Context) error {
				calls++
				runs, err := w.Reconcile(ctx)
				if err != nil || runs["a"].Generation != old.Generation+1 {
					t.Error("callback admitted before replacement:", runs, err)
				}
				replayed, err := w.Send(ctx, "a", event)
				if err != nil || !replayed.Replayed || !bytes.Equal(replayed.Result, receipt.Result) {
					t.Error("receipt lost:", replayed, err)
				}
				return nil
			})
			if err != nil || calls != 1 {
				t.Fatal(calls, err)
			}
			runs, err := w.Reconcile(t.Context())
			if err != nil || len(runs) != 1 || runs["a"].ID == old.ID {
				t.Fatal(runs, err)
			}
			current := runs["a"]
			if _, err = os.Stat(filepath.Join(options.Root, "credentials", old.ID+".json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old credentials retained:", err)
			}
			stale, err := capsuleprotocol.NewClient(credentials, func(ctx context.Context) (net.Conn, error) { return capsuleprotocol.DialControl(ctx, current.Socket) })
			if err != nil || stale.Health(t.Context()) == nil {
				t.Fatal("old certificate accepted:", err)
			}
			if err = w.Stop(t.Context(), "a", old.Generation); !errors.Is(err, controlplane.ErrPlacement) {
				t.Fatal("old stop changed replacement:", err)
			}
			blocked := harnessstore.Event{ID: "blocked", Subjects: []string{"agent/a", "request/blocked", "event/blocked"}, Body: []byte("local")}
			if _, err = w.Send(t.Context(), "a", blocked); !errors.Is(err, harnessstore.ErrFenced) {
				t.Fatal("durable barrier lost:", err)
			}
		})
	}
	next := harnessstore.Event{ID: "after-rotation", Subjects: []string{"agent/a", "event/after-rotation"}, Body: []byte("local")}
	r, err := w.Send(t.Context(), "a", next)
	if err != nil || !bytes.Contains(r.Result, []byte(`"effects":2`)) {
		t.Fatal("effect duplicated during rotation:", r, err)
	}
}

func TestConcurrentCredentialRotationDrainsAdmittedWork(t *testing.T) {
	w, _, _, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	old, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewPlacements(w.store, "host", "other-renewer", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	now := renewalClock(t, hostCredentials(t, options.Root, old), "margin")
	var rotated atomic.Bool
	for _, worker := range []*Placements{w, other} {
		worker.credentialNow = func() time.Time {
			if rotated.Load() {
				return time.Now()
			}
			return now
		}
		worker.afterCredentialStop = func() { rotated.Store(true) }
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	release, entered := make(chan struct{}), make(chan struct{})
	appDone, rotations := make(chan error, 1), make(chan error, 2)
	go func() {
		appDone <- w.host.WithApplication(ctx, func(context.Context) error {
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
	go func() { rotations <- w.RefreshCredentials(ctx) }()
	go func() { rotations <- other.RefreshCredentials(ctx) }()
	for {
		b, err := os.ReadFile(filepath.Join(options.Root, "registry.json"))
		var r struct {
			Admissions []json.RawMessage `json:"admissions"`
		}
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatal("cannot inspect admission queue")
		}
		if len(r.Admissions) == 3 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if rotated.Load() {
		t.Fatal("rotation interrupted admitted callback")
	}
	close(release)
	if err = <-appDone; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = <-rotations; err != nil {
			t.Fatal(err)
		}
	}
	runs, err := w.Reconcile(ctx)
	if err != nil || runs["a"].Generation != old.Generation+1 {
		t.Fatal("concurrent renewer replaced fresh boot:", runs, err)
	}
}

func TestExpiredQuiescingBootRotatesOnlyForFence(t *testing.T) {
	w, _, _, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	old, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	now := renewalClock(t, hostCredentials(t, options.Root, old), "expired")
	w.credentialNow = func() time.Time { return now }
	w.afterCredentialStop = func() { w.credentialNow = time.Now }
	if err = w.Fence(t.Context(), "a", "request/after-expiry"); err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || len(runs) != 0 {
		t.Fatal("temporary boot retained:", runs, err)
	}
	placements, err := w.store.Placements(t.Context(), "host")
	if err != nil || len(placements) != 1 || !placements[0].FenceOnly || !placements[0].UncleanStop || placements[0].Generation != old.Generation+1 {
		t.Fatal("rotation upgraded scope:", placements, err)
	}
}

func TestCredentialRotationWorkerCrash(t *testing.T) {
	for _, stage := range []string{"intent", "retired"} {
		t.Run(stage, func(t *testing.T) {
			w, _, schema, options := labWithCapacity(t, 1, true)
			t.Cleanup(w.Close)
			e := harnessstore.Event{ID: "before-crash", Subjects: []string{"agent/a", "event/before-crash"}, Body: []byte("local")}
			original, err := w.Send(t.Context(), "a", e)
			if err != nil {
				t.Fatal(err)
			}
			old, err := w.Start(t.Context(), "a")
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialRotationChild$", "-test.v")
			cmd.Env = append(os.Environ(), "AC_CREDENTIAL_CHILD_SCHEMA="+schema, "AC_CREDENTIAL_CHILD_ROOT="+options.Root, "AC_CREDENTIAL_CHILD_STAGE="+stage)
			log, err := os.Create(filepath.Join(options.Root, "logs", "rotation-worker.log"))
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
				if _, err = os.Stat(filepath.Join(options.Root, "logs", "rotation-boundary")); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if stage == "intent" && syscall.Kill(old.PID, 0) != nil {
				t.Fatal("intent assumed VM absence")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal(err)
			}
			next, err := NewPlacements(w.store, "host", "replacement-renewer", time.Minute, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(next.Close)
			// Return to the real clock: the durable stop intent still wins.
			if _, err = next.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			p, err := next.store.Placements(ctx, "host")
			if err != nil || len(p) != 1 || p[0].State != "STOPPED" || !p[0].UncleanStop {
				t.Fatal(p, err)
			}
			if _, err = next.host.Start(ctx, "a", old.Generation); !errors.Is(err, runtime.ErrGeneration) {
				t.Fatal("retired generation revived:", err)
			}
			r, err := next.Send(ctx, "a", e)
			if err != nil || !r.Replayed || !bytes.Equal(r.Result, original.Result) {
				t.Fatal("crash duplicated effect:", r, err)
			}
		})
	}
}

func TestCredentialRotationChild(t *testing.T) {
	schema := os.Getenv("AC_CREDENTIAL_CHILD_SCHEMA")
	if schema == "" {
		return
	}
	root := os.Getenv("AC_CREDENTIAL_CHILD_ROOT")
	s, _ := database(t, schema, false)
	options := opts(t, root)
	options.AuthenticatedControl, options.MaxActive = true, 1
	options.Initrd = config(t).ControlInitrd
	options.InitrdSHA256 = digest(t, options.Initrd)
	w, err := NewPlacements(s, "host", "rotation-child", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := renewalClock(t, hostCredentials(t, root, runs["a"]), "expired")
	w.credentialNow = func() time.Time { return now }
	boundary := func() {
		if err := os.WriteFile(filepath.Join(root, "logs", "rotation-boundary"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	switch os.Getenv("AC_CREDENTIAL_CHILD_STAGE") {
	case "intent":
		w.afterStopIntent = boundary
	case "confirmed":
		w.afterConfirm = func(runtime.VMRun) { boundary() }
	case "running":
		w.afterRunning = func(runtime.VMRun) { boundary() }
	default:
		w.afterCredentialStop = boundary
	}
	if err = w.RefreshCredentials(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("rotation crash boundary not reached")
}
