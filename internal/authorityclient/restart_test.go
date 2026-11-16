//go:build linux && cgo

package authorityclient

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// A restarted service cannot know which holds its previous process granted:
// the writes they exclude wait for their caps, the others run at once.
func TestRestartedServiceWaitsTheQuietPeriod(t *testing.T) {
	const publishCap, keyCap = time.Second, 2 * time.Second
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	// The state the previous process left.
	before := restoreauthority.Local{Catalog: catalog, Keys: keys}
	ctx := t.Context()
	a, r := fenced(t, before, "store-a", "volume-a")
	if _, err := before.BeginRevocation(ctx, "known-subject"); err != nil {
		t.Fatal(err)
	}
	if r, _ = before.Scan(ctx, a); before.RecordVerifiedFence(ctx, r) != nil {
		t.Fatal("fence")
	}
	k, err := before.Register(ctx, "store-k", "volume-k")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := before.ReserveIncarnation(ctx, k, "known-restore")
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := before.Register(ctx, "store-r", "volume-r")
	if err != nil {
		t.Fatal(err)
	}
	seal, err := before.Register(ctx, "store-s", "volume-s")
	if err != nil {
		t.Fatal(err)
	}
	// A deleted agent, sealed by the previous process: the new one destroys
	// its key.
	gone, err := before.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = before.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	if err = before.RecordRetiredSeal(ctx, gone); err != nil {
		t.Fatal(err)
	}
	keys, catalog = reopen(t, dir, keys, catalog)
	start := time.Now()
	l := serve(t, keys, catalog, caps(publishCap, keyCap), func(c *svc.Config) { c.Started = start })
	c := l.client(t)
	operations := map[string]struct {
		wait time.Duration
		run  func() error
	}{
		"outcome": {0, func() error {
			return c.RecordOutcome(ctx, a, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")})
		}},
		"fence":         {0, func() error { return c.RecordVerifiedFence(ctx, r) }},
		"known subject": {0, func() error { _, err := c.BeginRevocation(ctx, "known-subject"); return err }},
		"known reservation": {0, func() error {
			got, err := c.ReserveIncarnation(ctx, k, "known-restore")
			if err == nil && got != k2 {
				err = errors.New("another incarnation")
			}
			return err
		}},
		"new subject":     {publishCap, func() error { _, err := c.BeginRevocation(ctx, "new-subject"); return err }},
		"new reservation": {keyCap, func() error { _, err := c.ReserveIncarnation(ctx, reserve, "new-restore"); return err }},
		"seal":            {keyCap, func() error { return c.RecordRetiredSeal(ctx, seal) }},
		"destruction":     {keyCap, func() error { return c.DestroyKey(ctx, gone) }},
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	took := map[string]time.Duration{}
	for name, op := range operations {
		wg.Go(func() {
			err := op.run()
			mu.Lock()
			defer mu.Unlock()
			took[name] = time.Since(start)
			if err != nil {
				t.Error(name, err)
			}
		})
	}
	wg.Wait()
	for name, op := range operations {
		switch {
		case op.wait == 0 && took[name] >= publishCap:
			t.Error(name, "waited", took[name])
		case op.wait > 0 && took[name] < op.wait:
			t.Error(name, "ran after", took[name], "within the quiet period", op.wait)
		}
	}
	// A new subject waits for the publish holds only.
	if took["new subject"] >= keyCap {
		t.Error("a new subject waited for the key holds", took["new subject"])
	}
}

// Finding 2, across the socket: a restarted service that cannot reach its
// replica runs nothing, reads included, until it does.
func TestRestartedServiceRunsNothingUntilItReachesTheReplica(t *testing.T) {
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = catalog.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	if err = svc.LinkTo(t.Context(), catalog, keys, &tap{target: replica}, 0); err != nil {
		t.Fatal(err)
	}
	first := serve(t, keys, catalog)
	c := first.client(t)
	ctx := t.Context()
	b, r := fenced(t, c, "store-a", "volume-a")
	if err = c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	if status, err := c.Status(ctx); err != nil || status.Mode != restoreauthority.ModeSynchronous || status.Epoch != 1 {
		t.Fatal(status, err)
	}
	applied, err := replica.Position(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The service restarts while the standby is away.
	if err = first.stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	catalog.Close()
	keys, catalog = reopen(t, dir, keys, catalog)
	link := &tap{target: replica, down: true}
	if err = svc.LinkTo(t.Context(), catalog, keys, link, 0); err != nil {
		t.Fatal(err)
	}
	second := serve(t, keys, catalog)
	c = second.client(t)
	if status, err := c.Status(ctx); err != nil || status.Mode != restoreauthority.ModeWaiting {
		t.Fatal("a restarted service reports", status, err)
	}
	for name, run := range map[string]func(context.Context) error{
		"read":  func(ctx context.Context) error { _, err := c.Lookup(ctx, "store-a"); return err },
		"check": func(ctx context.Context) error { return c.CheckBinding(ctx, b) },
		"outcome": func(ctx context.Context) error {
			return c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-2", Digest: digest("two")})
		},
		"fence":    func(ctx context.Context) error { return c.RecordVerifiedFence(ctx, r) },
		"key":      func(ctx context.Context) error { return c.Ensure(ctx, agent, volume) },
		"revision": func(ctx context.Context) error { _, err := c.BeginRevocation(ctx, "agent/one"); return err },
		"hold": func(ctx context.Context) error {
			return c.HoldBinding(ctx, b, func(context.Context) error { t.Error("a hold without the replica"); return nil })
		},
	} {
		if err := run(within(t, 300*time.Millisecond)); !errors.Is(err, restoreauthority.ErrUnavailable) || errors.Is(err, restoreauthority.ErrStale) {
			t.Fatal("a restarted service ran", name, "without its replica:", err)
		}
	}
	if state, err := catalog.Replication(ctx); err != nil || state.Committed.Seq != applied.Seq {
		t.Fatal("a restarted service wrote without its replica", state, err)
	}
	// It reaches the replica: everything runs.
	link.set(false)
	if got, err := c.Lookup(ctx, "store-a"); err != nil || got != b {
		t.Fatal(got, err)
	}
	if err = c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-2", Digest: digest("two")}); err != nil {
		t.Fatal(err)
	}
	if status, err := c.Status(ctx); err != nil || status.Mode != restoreauthority.ModeSynchronous {
		t.Fatal(status, err)
	}
}
