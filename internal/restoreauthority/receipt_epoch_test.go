//go:build linux && cgo

package restoreauthority

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Fence receipts carry the epoch inside their MAC (ADR 005, "What the code
// must do", item 10).

func TestStandaloneReceiptsKeepTheFirstEpochThroughArming(t *testing.T) {
	dir := t.TempDir()
	keys, c := primary(t, dir)
	b, err := c.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	// No replication row yet: the first epoch, the one a snapshot creates.
	r := receipt(t, c, b)
	if r.Epoch != 1 {
		t.Fatal("standalone receipt epoch", r.Epoch)
	}
	// The epoch is inside the MAC: it cannot be moved forward.
	moved := r
	moved.Epoch = 2
	if err = c.RecordVerifiedFence(t.Context(), moved); !errors.Is(err, ErrStale) {
		t.Fatal("receipt with a rewritten epoch accepted", err)
	}
	// Version 1 of the format, without the tag and the epoch, no longer binds.
	var secret []byte
	if err = c.db.QueryRow("SELECT secret FROM authority").Scan(&secret); err != nil {
		t.Fatal(err)
	}
	v1, _ := json.Marshal(struct {
		Authority   string
		Store       string
		Incarnation uint64
		Revision    uint64
		Subjects    []string
		MAC         []byte
	}{r.Authority, r.Store, r.Incarnation, r.Revision, r.Subjects, nil})
	m := hmac.New(sha256.New, secret)
	m.Write(v1)
	old := r
	old.MAC = m.Sum(nil)
	if err = c.WithCurrentFences(t.Context(), old, func() error { return nil }); !errors.Is(err, ErrStale) {
		t.Fatal("version 1 receipt accepted", err)
	}
	// Arming creates the row with the same epoch: the receipt still binds.
	_, recipient := newUnlockKey(t)
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = c.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if err = c.Replicate(t.Context(), &tap{target: replica}); err != nil {
		t.Fatal(err)
	}
	if err = c.WithCurrentFences(t.Context(), r, func() error { return nil }); err != nil {
		t.Fatal("arming invalidated a standalone receipt", err)
	}
	// A version 2 catalogue, with no replication table, signs under epoch 1.
	_, legacy := primary(t, filepath.Join(dir, "legacy"))
	if _, err = legacy.db.Exec("DROP TABLE replication_log; DROP TABLE replication; PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	lb, err := legacy.Register(t.Context(), "store-l", "volume-l")
	if err != nil {
		t.Fatal(err)
	}
	if lr := receipt(t, legacy, lb); lr.Epoch != 1 {
		t.Fatal("version 2 receipt epoch", lr.Epoch)
	}
}

// sameEpochScenario runs restoreWitnessSameEpochBroken up to its last step.
// A restoring image (store-r, incarnation 2) is fenced for a subject that the
// old primary revoked without replicating it, and keeps the old primary's
// receipt. The primary is lost; the promoted authority gives the same
// revision to another subject. It returns the promoted catalogue, the old
// receipt, and the signing secret, which the promotion kept.
func sameEpochScenario(t *testing.T) (*Catalog, Receipt, []byte) {
	t.Helper()
	p := replicated(t)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-r", "volume-r")
	if err != nil {
		t.Fatal(err)
	}
	// beginRestore(1), retire(1), install(1), launchRestore(1).
	next, err := p.catalog.ReserveIncarnation(ctx, b, "restore-r")
	if err != nil {
		t.Fatal(err)
	}
	// loseLink, beginRevocation(0): the revision commits on the old primary
	// and never reaches the replica.
	p.link.set(true)
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = p.catalog.BeginRevocation(short, "agent/zero")
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("revocation returned without the replica", err)
	}
	// scan(1), synchronize(1): degraded mode (a later wave) would let the old
	// primary sign this receipt. Its revision and secret are on its disk.
	old := Receipt{Authority: p.catalog.Identity(), Epoch: 1, Store: next.Store, Incarnation: next.Incarnation, Subjects: []string{"agent/zero"}}
	var secret []byte
	if err = p.catalog.db.QueryRow("SELECT revision,secret FROM authority").Scan(&old.Revision, &secret); err != nil {
		t.Fatal(err)
	}
	old.MAC = signReceipt(old, secret)
	// losePrimary, promote.
	result, err := Promote(ctx, filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys"), p.unlock)
	if err != nil || result.Epoch != 2 {
		t.Fatal(result, err)
	}
	c, err := Open(ctx, filepath.Join(p.dir, "promoted-restore"), result.RestoreAuthority, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	// beginRevocation(1): the promoted root hands out the same revision.
	revision, err := c.BeginRevocation(ctx, "agent/one")
	if err != nil || revision != old.Revision {
		t.Fatal("expected the promoted root to reuse the revision", revision, old.Revision, err)
	}
	return c, old, secret
}

// restoreWitnessSameEpochGuard: the old primary's receipt is refused by
// RecordVerifiedFence and by every activation path. The image scans again
// under the new epoch and fences what the promoted root knows
// (restoredImageRescansUnderNewEpochTest, without its degraded period).
func TestReceiptOfTheOldEpochCannotBindAfterPromotion(t *testing.T) {
	c, old, _ := sameEpochScenario(t)
	ctx := t.Context()
	published := false
	publish := func() error { published = true; return nil }
	if err := c.RecordVerifiedFence(ctx, old); !errors.Is(err, ErrStale) {
		t.Fatal("receipt of the old epoch recorded", err)
	}
	if err := c.WithCurrentFences(ctx, old, publish); !errors.Is(err, ErrStale) {
		t.Fatal("receipt of the old epoch published a boot", err)
	}
	if err := c.WithActivation(ctx, old, nothingMissing, publish); !errors.Is(err, ErrStale) {
		t.Fatal("receipt of the old epoch activated", err)
	}
	if _, err := c.Activate(ctx, old, Restoration{Inspect: nothingMissing, Repair: func([]Outcome) error { return nil }, Publish: publish}); !errors.Is(err, ErrStale) {
		t.Fatal("receipt of the old epoch activated a restore", err)
	}
	if published {
		t.Fatal("published with a receipt of the old epoch")
	}
	// The image scans again: the receipt names the promoted root's subjects.
	next := Binding{Store: old.Store, Volume: "volume-r", Incarnation: old.Incarnation}
	r, err := c.Scan(ctx, next)
	if err != nil || r.Epoch != 2 || !slices.Equal(r.Subjects, []string{"agent/one"}) {
		t.Fatal("rescan under the new epoch", r, err)
	}
	if err = c.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Activate(ctx, r, Restoration{Inspect: nothingMissing, Publish: publish}); err != nil || !published {
		t.Fatal("activation under the new epoch", err)
	}
}

// restoreWitnessSameEpochBroken: had the promotion kept the epoch, the old
// receipt would bind, and the image would activate without fencing the
// subject that the promoted root revoked (activationCurrent).
func TestReceiptOfTheSameEpochWouldActivateUnfenced(t *testing.T) {
	c, old, secret := sameEpochScenario(t)
	same := old
	same.Epoch = 2 // NEW_EPOCH=false: the old primary signed under this epoch
	same.MAC = signReceipt(same, secret)
	if err := c.RecordVerifiedFence(t.Context(), same); err != nil {
		t.Fatal(err)
	}
	published := false
	if err := c.WithActivation(t.Context(), same, nothingMissing, func() error { published = true; return nil }); err != nil || !published {
		t.Fatal("the broken schedule did not reach its last step", err)
	}
	if slices.Contains(same.Subjects, "agent/one") {
		t.Fatal("the image fenced the promoted root's subject")
	}
}
