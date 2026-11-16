//go:build linux && cgo

package authorityclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// TestBindingGateSerializesReservationAndNeverEnrolls, across two
// connections: a reservation waits for a binding hold, and the hold's
// binding is stale once it lands.
func TestBindingHoldSerializesReservation(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	holder, other := l.client(t), l.client(t)
	ctx := t.Context()
	if _, err := holder.Lookup(ctx, "missing"); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("lookup fabricated a binding", err)
	}
	b, err := holder.Register(ctx, "store-a", "volume-a")
	if err != nil || b.Incarnation != 1 {
		t.Fatal(b, err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- holder.HoldBinding(ctx, b, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	reserved := make(chan error, 1)
	go func() { _, err := other.ReserveIncarnation(ctx, b, "restore"); reserved <- err }()
	select {
	case err := <-reserved:
		close(release)
		<-done
		t.Fatal("a reservation overtook a binding hold", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-reserved; err != nil {
		t.Fatal(err)
	}
	if err = holder.CheckBinding(ctx, b); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("an obsolete binding passed", err)
	}
	if err = holder.HoldBinding(ctx, b, func(context.Context) error { t.Error("an obsolete binding held"); return nil }); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	current, err := other.Lookup(ctx, b.Store)
	if err != nil || current.Incarnation != 2 {
		t.Fatal(current, err)
	}
	if err = other.RecordRetiredSeal(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Lookup(ctx, b.Store); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal("a sealed store looked up", err)
	}
}

// TestPublicationSerializesConcurrentRevocation, across two connections: a
// new revocation subject waits for a fences hold, and the receipt is stale
// once it lands.
func TestFencesHoldSerializesRevocation(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	holder, other := l.client(t), l.client(t)
	ctx := t.Context()
	_, r := fenced(t, holder, "store-a", "volume-a")
	entered, release := make(chan struct{}), make(chan struct{})
	publication := make(chan error, 1)
	go func() {
		publication <- holder.HoldFences(ctx, r, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	intent := make(chan error, 1)
	go func() { _, err := other.BeginRevocation(ctx, "new-subject"); intent <- err }()
	select {
	case err := <-intent:
		close(release)
		<-publication
		t.Fatal("a revocation crossed a fences hold", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-publication; err != nil {
		t.Fatal(err)
	}
	if err := <-intent; err != nil {
		t.Fatal(err)
	}
	if err := holder.HoldFences(ctx, r, func(context.Context) error { t.Error("an old receipt published"); return nil }); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the new revision was not observed", err)
	}
}

// destructionWaitsForAllCachedCopiesTest across the socket: the key's
// destruction waits while any hold has it, and the client clears its
// buffer when the hold ends.
func TestKeyHoldDelaysDestructionAndClearsTheKey(t *testing.T) {
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	b, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	var want []byte
	if err = keys.WithKey(ctx, agent, volume, func(k []byte) error { want = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	tombstone := filepath.Join(dir, "keys", "revoked", volume)
	type holder struct {
		entered, release chan struct{}
		done             chan error
		seen             []byte // the client's own buffer, kept to check it is cleared
		copy             []byte
	}
	holders := []*holder{{}, {}}
	for i, h := range holders {
		h.entered, h.release, h.done = make(chan struct{}), make(chan struct{}), make(chan error, 1)
		use := func(key []byte) error {
			h.seen, h.copy = key, bytes.Clone(key)
			close(h.entered)
			<-h.release
			return nil
		}
		own := l.client(t)
		go func() {
			if i == 0 {
				// A boot: the binding and the key, in one hold.
				h.done <- own.HoldKey(ctx, b, func(_ context.Context, key []byte) error { return use(key) })
			} else {
				h.done <- own.WithKey(ctx, agent, volume, use)
			}
		}()
		<-h.entered
		if !bytes.Equal(h.copy, want) {
			t.Fatal("the hold did not carry the volume key")
		}
	}
	for i, h := range holders {
		if err = c.Revoke(within(t, 200*time.Millisecond), agent, volume); !errors.Is(err, restoreauthority.ErrUnavailable) {
			t.Fatalf("destruction with %d holder(s) left: %v", len(holders)-i, err)
		}
		if _, err = os.Lstat(tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a refused destruction published a tombstone", err)
		}
		close(h.release)
		if err = <-h.done; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(h.seen, make([]byte, 32)) {
			t.Fatal("the client kept the key after its hold")
		}
	}
	if err = c.Revoke(ctx, agent, volume); err != nil {
		t.Fatal("destruction after the last holder", err)
	}
	if err = c.HoldKey(ctx, b, func(context.Context, []byte) error { t.Error("a destroyed key held"); return nil }); err == nil {
		t.Fatal("a destroyed key was held")
	}
}

// holderChild names the hold a child process takes, then keeps.
type holderChild struct {
	Socket, RestoreID, KeyID string
	Binding                  restoreauthority.Binding
}

const holderEnv = "AGENTCAPSULE_TEST_KEY_HOLDER"

// TestKeyHolderChild is the child of TestKilledHolderReleasesItsHold.
func TestKeyHolderChild(t *testing.T) {
	text := os.Getenv(holderEnv)
	if text == "" {
		t.Skip("child process of TestKilledHolderReleasesItsHold")
	}
	var h holderChild
	if err := json.Unmarshal([]byte(text), &h); err != nil {
		t.Fatal(err)
	}
	c, err := New(h.Socket, svc.RoleWorker, h.RestoreID, h.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	err = c.HoldKey(context.Background(), h.Binding, func(context.Context, []byte) error {
		fmt.Println("held")
		time.Sleep(time.Hour) // until the parent kills this process
		return nil
	})
	t.Fatal("the hold ended", err)
}

// A worker killed during a hold releases it: its connection ends, and the
// destruction proceeds.
func TestKilledHolderReleasesItsHold(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog, caps(time.Minute, 5*time.Minute))
	c := l.client(t)
	ctx := t.Context()
	b, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(holderChild{Socket: l.worker, RestoreID: catalog.Identity(), KeyID: keys.Identity(), Binding: b})
	child := exec.Command(os.Args[0], "-test.run=^TestKeyHolderChild$", "-test.v")
	child.Env = append(os.Environ(), holderEnv+"="+string(spec))
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	held := make(chan bool, 1)
	go func() {
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			if strings.TrimSpace(lines.Text()) == "held" {
				held <- true
				return
			}
		}
		held <- false
	}()
	select {
	case ok := <-held:
		if !ok {
			t.Fatal("the child did not take its hold")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the child did not take its hold")
	}
	if !strings.Contains(l.scrape(t), `agentcapsule_authority_service_holds{kind="key"} 1`) {
		t.Fatal("the hold is not counted")
	}
	destroyed := make(chan error, 1)
	go func() { destroyed <- c.Revoke(within(t, 30*time.Second), agent, volume) }()
	select {
	case err := <-destroyed:
		t.Fatal("the destruction overtook a living holder", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err = child.Process.Kill(); err != nil { // SIGKILL
		t.Fatal(err)
	}
	child.Wait()
	select {
	case err := <-destroyed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the hold of a killed holder was not released")
	}
	if !strings.Contains(l.scrape(t), `agentcapsule_authority_service_holds{kind="key"} 0`) {
		t.Fatal("the released hold is still counted")
	}
}

// The service stops during a hold: the publish's context ends before its
// commit, and the hold fails as an outage.
func TestLostHoldCancelsThePublish(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	b, err := c.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	canceled := make(chan error, 1)
	result := make(chan error, 1)
	go func() {
		result <- c.HoldBinding(t.Context(), b, func(ctx context.Context) error {
			close(entered)
			select {
			case <-ctx.Done():
				canceled <- context.Cause(ctx)
				return ctx.Err()
			case <-time.After(20 * time.Second):
				canceled <- nil // the publish would commit here
				return nil
			}
		})
	}()
	<-entered
	start := time.Now()
	if err = l.stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if cause := <-canceled; cause == nil || time.Since(start) > 5*time.Second {
		t.Fatal("the publish outlived its hold", cause, time.Since(start))
	}
	err = <-result
	if !errors.Is(err, restoreauthority.ErrUnavailable) || errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("a lost hold is not an outage", err)
	}
}

// A hold that outlives its cap ends there: what it excluded proceeds,
// although its callback still runs, and the callback's context ended
// before.
func TestHoldEndsAtItsCap(t *testing.T) {
	const publishCap = 800 * time.Millisecond
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog, caps(publishCap, time.Minute))
	holder, other := l.client(t), l.client(t)
	ctx := t.Context()
	b, err := holder.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan time.Time, 1)
	ctxEnded := make(chan time.Time, 1)
	done := make(chan error, 1)
	go func() {
		done <- holder.HoldBinding(ctx, b, func(ctx context.Context) error {
			entered <- time.Now()
			<-ctx.Done()
			ctxEnded <- time.Now()
			time.Sleep(3 * publishCap) // a publish that ignores its context
			return nil
		})
	}()
	start := <-entered
	reserved := make(chan error, 1)
	go func() { _, err := other.ReserveIncarnation(ctx, b, "restore"); reserved <- err }()
	select {
	case err = <-reserved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the hold outlived its cap")
	}
	proceeded := time.Since(start)
	if proceeded < publishCap/2 || proceeded > 2*publishCap {
		t.Fatal("the reservation proceeded at", proceeded, "not at the cap", publishCap)
	}
	if ended := (<-ctxEnded).Sub(start); ended >= publishCap {
		t.Fatal("the hold's context ended at", ended, "not before the cap")
	}
	if err = <-done; !errors.Is(err, svc.ErrHoldExpired) || !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal(err)
	}
	if !strings.Contains(l.scrape(t), `agentcapsule_authority_service_hold_expired_total{kind="binding"} 1`) {
		t.Fatal("the expired hold is not counted")
	}
}
