//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6): a
// key of the key authority bound to a day, wrapped and replicated as a
// volume key, destroyed once its day's receipts have expired.

var receiptDay = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

// replicaKey returns the replica's copy of day's receipt key, unwrapped
// with the unlock key; nil when the replica has no copy, revoked when it
// holds the tombstone.
func replicaKey(t *testing.T, p *pair, day time.Time) (key []byte, revoked bool) {
	t.Helper()
	volume := keyauthority.ReceiptKeyVolume(day)
	var wrapped []byte
	err := p.replica.db.QueryRow("SELECT revoked,wrapped FROM replica_volumes WHERE volume=? AND agent=?", volume, keyauthority.ReceiptKeyAgent).Scan(&revoked, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	if wrapped == nil {
		return nil, revoked
	}
	key, err = p.unlock.Open(authoritylog.KeyContext(p.keys.Identity(), keyauthority.ReceiptKeyAgent, volume), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	return key, revoked
}

func receiptKey(t *testing.T, l Local, day time.Time) []byte {
	t.Helper()
	key, err := l.ReceiptKey(t.Context(), day)
	if err != nil || len(key) != 32 {
		t.Fatal("the receipt key of", day, err)
	}
	return key
}

// Answer 4(b): the standby is away when a day's key is due. Its creation
// continues on the primary alone, and holds nothing behind it; a volume key
// still waits. When the standby returns, the key reaches it, wrapped, before
// degraded mode ends: the primary's log kept it until then.
func TestReceiptKeyCreationContinuesInDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	local := Local{Catalog: p.catalog, Keys: p.keys}
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	// With the standby, the key is on the replica before the creation
	// returns.
	if err = local.EnsureReceiptKey(ctx, receiptDay); err != nil {
		t.Fatal(err)
	}
	if got, _ := replicaKey(t, p, receiptDay); !bytes.Equal(got, receiptKey(t, local, receiptDay)) {
		t.Fatal("the replica lacks the receipt key the primary created with it")
	}
	degrade(t, p, k, b)
	next := receiptDay.AddDate(0, 0, 1)
	if err = local.EnsureReceiptKey(within(t, 5*time.Second), next); err != nil {
		t.Fatal("the creation of a receipt key waited for the standby in degraded mode", err)
	}
	key := receiptKey(t, local, next)
	if got, _ := replicaKey(t, p, next); got != nil {
		t.Fatal("the replica holds a key created while it was away")
	}
	if err = p.catalog.RecordOutcome(within(t, 5*time.Second), b, Outcome{ID: "event-after", Digest: digest("after")}); err != nil {
		t.Fatal("the receipt key's record holds the writes after it", err)
	}
	if err = p.keys.Ensure(within(t, 200*time.Millisecond), streamAgent, streamVolume); !errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("a volume key was created in degraded mode", err)
	}
	resync(t, p)
	if got, _ := replicaKey(t, p, next); !bytes.Equal(got, key) {
		t.Fatal("the receipt key created in degraded mode did not reach the standby")
	}
	if !bytes.Equal(receiptKey(t, local, next), key) {
		t.Fatal("the key changed")
	}
	p.same(t)
	// Once the replica holds it, the primary's log keeps no wrapped copy.
	eventually(t, "the log's wrapped copy to go", func() bool {
		var n int
		if err := p.catalog.db.QueryRow("SELECT count(*) FROM replication_log").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 0
	})
}

// The destruction of a receipt key waits for the standby, in degraded mode
// too: a key that only the replica still held would come back after a
// failover. It needs no seal: a receipt key has no store.
func TestReceiptKeyDestructionWaitsForTheStandby(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	local := Local{Catalog: p.catalog, Keys: p.keys}
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.EnsureReceiptKey(ctx, receiptDay); err != nil {
		t.Fatal(err)
	}
	key := receiptKey(t, local, receiptDay)
	degrade(t, p, k, b)
	if err = local.DestroyReceiptKey(within(t, 200*time.Millisecond), receiptDay); !errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("a receipt key was destroyed in degraded mode", err)
	}
	if !bytes.Equal(receiptKey(t, local, receiptDay), key) {
		t.Fatal("a refused destruction changed the key")
	}
	if got, _ := replicaKey(t, p, receiptDay); !bytes.Equal(got, key) {
		t.Fatal("the replica lost its copy")
	}
	resync(t, p)
	if err = local.DestroyReceiptKey(ctx, receiptDay); err != nil {
		t.Fatal("a receipt key needs a seal to be destroyed", err)
	}
	if _, err = local.ReceiptKey(ctx, receiptDay); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed receipt key is readable", err)
	}
	if got, revoked := replicaKey(t, p, receiptDay); got != nil || !revoked {
		t.Fatal("the replica keeps the destroyed receipt key")
	}
	// Destroyed for good: the creation does not bring it back.
	if err = local.EnsureReceiptKey(ctx, receiptDay); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed day's key was created again", err)
	}
	if held, err := local.ReceiptKeys(); err != nil || len(held) != 0 {
		t.Fatal("held", held, err)
	}
	p.same(t)
}

// The reserved binding names receipt keys only: the catalogue never
// registers its agent as a store, the worker's ensure_key refuses it, and
// the stream refuses it with any volume but a day's. A volume key's
// destruction still needs its seal.
func TestReceiptKeyBindingIsReserved(t *testing.T) {
	p := replicated(t)
	local := Local{Catalog: p.catalog, Keys: p.keys}
	ctx := t.Context()
	volume := keyauthority.ReceiptKeyVolume(receiptDay)
	if _, err := p.catalog.Register(ctx, keyauthority.ReceiptKeyAgent, volume); !errors.Is(err, ErrInput) {
		t.Fatal("the receipt keys' agent was registered as a store", err)
	}
	if err := local.Ensure(ctx, keyauthority.ReceiptKeyAgent, volume); !errors.Is(err, keyauthority.ErrInput) {
		t.Fatal("ensure_key created a receipt key", err)
	}
	if err := p.keys.Ensure(ctx, keyauthority.ReceiptKeyAgent, streamVolume); !errors.Is(err, ErrInput) {
		t.Fatal("the receipt keys' agent holds a volume key", err)
	}
	if err := p.keys.Ensure(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	if err := p.keys.Revoke(ctx, streamAgent, streamVolume); !errors.Is(err, ErrStale) {
		t.Fatal("a volume key was destroyed without its seal", err)
	}
	if held, err := local.ReceiptKeys(); err != nil || len(held) != 0 {
		t.Fatal("held", held, err)
	}
	p.same(t)
}

// Standalone, without a standby, the receipt keys work the same: created,
// read and destroyed at once, without a seal.
func TestStandaloneReceiptKeys(t *testing.T) {
	keys, c := primary(t, t.TempDir())
	local := Local{Catalog: c, Keys: keys}
	ctx := t.Context()
	for _, d := range []time.Time{receiptDay, receiptDay.AddDate(0, 0, 1)} {
		if err := local.EnsureReceiptKey(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(receiptKey(t, local, receiptDay), receiptKey(t, local, receiptDay.AddDate(0, 0, 1))) {
		t.Fatal("two days share a key")
	}
	if err := local.DestroyReceiptKey(ctx, receiptDay); err != nil {
		t.Fatal(err)
	}
	held, err := local.ReceiptKeys()
	if err != nil || len(held) != 1 || !held[0].Day.Equal(receiptDay.AddDate(0, 0, 1)) || !held[0].Usable {
		t.Fatal("held", held, err)
	}
}

// The receipt keys survive a failover: the snapshot carries those of its
// time, the stream those created after it, and the promotion installs
// both. A destroyed day's key stays destroyed. So a receipt the database's
// standby holds is still replayed after the failover.
func TestReceiptKeysSurviveThePromotion(t *testing.T) {
	p := &pair{dir: t.TempDir(), link: &tap{}}
	p.keys, p.catalog = primary(t, p.dir)
	local := Local{Catalog: p.catalog, Keys: p.keys}
	ctx := t.Context()
	before, gone, after := receiptDay.AddDate(0, 0, -1), receiptDay.AddDate(0, 0, -2), receiptDay
	for _, d := range []time.Time{gone, before} {
		if err := local.EnsureReceiptKey(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	p.unlock, p.recipient = newUnlockKey(t)
	snapshot := filepath.Join(p.dir, "snapshot.sqlite")
	if _, err := p.catalog.Snapshot(ctx, p.keys, p.recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := InitializeReplica(ctx, filepath.Join(p.dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	p.replica = replica
	t.Cleanup(func() { p.replica.Close() })
	p.link.target = p.replica
	if err = p.catalog.Replicate(ctx, p.link); err != nil {
		t.Fatal(err)
	}
	p.keys.SetJournal(p.catalog)
	if err = local.EnsureReceiptKey(ctx, after); err != nil {
		t.Fatal(err)
	}
	if err = local.DestroyReceiptKey(ctx, gone); err != nil {
		t.Fatal(err)
	}
	want := map[time.Time][]byte{before: receiptKey(t, local, before), after: receiptKey(t, local, after)}
	p.same(t)
	keys, c := promote(t, p)
	promoted := Local{Catalog: c, Keys: keys}
	for d, key := range want {
		if !bytes.Equal(receiptKey(t, promoted, d), key) {
			t.Fatal("the promoted key of", d, "differs")
		}
	}
	if _, err = promoted.ReceiptKey(ctx, gone); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed receipt key came back with the promotion", err)
	}
	if err = promoted.EnsureReceiptKey(ctx, gone); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the promoted authority created a destroyed day's key again", err)
	}
	held, err := promoted.ReceiptKeys()
	if err != nil || len(held) != 2 || !held[0].Day.Equal(before) || !held[1].Day.Equal(after) || !held[0].Usable || !held[1].Usable {
		t.Fatal("the promoted authority holds", held, err)
	}
}
