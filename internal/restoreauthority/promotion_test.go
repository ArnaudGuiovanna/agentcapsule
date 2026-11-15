//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// Promotion and epoch fencing (ADR 005, "What the code must do", items 9 to
// 13), with Go projections of the model's runs named in each test.

// promoteStandby promotes p's replica into new directories and opens both
// authorities, standalone, as the worker on the standby does.
func promoteStandby(t *testing.T, p *pair) (*keyauthority.Files, *Catalog, Promotion) {
	t.Helper()
	restoreRoot, keyRoot := filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys")
	result, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyauthority.Open(keyRoot, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(t.Context(), restoreRoot, result.RestoreAuthority, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return keys, c, result
}

// seedStandby arms the promoted authorities for a new standby, with a new
// unlock key, and links them to it, as snapshot and init-replica do.
func seedStandby(t *testing.T, dir string, keys *keyauthority.Files, c *Catalog) *pair {
	t.Helper()
	q := &pair{dir: dir, keys: keys, catalog: c, link: &tap{}}
	q.unlock, q.recipient = newUnlockKey(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "seed.sqlite")
	if _, err := c.Snapshot(t.Context(), keys, q.recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	q.replica, q.link.target = replica, replica
	if err = c.Replicate(t.Context(), q.link); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	return q
}

// writeEveryKind runs each kind of write of both authorities, with names
// derived from tag (one hex digit), and checks their effects.
func writeEveryKind(t *testing.T, keys *keyauthority.Files, c *Catalog, tag string) {
	t.Helper()
	ctx := t.Context()
	agent := "agt_" + strings.Repeat(tag, 32)
	live, destroyed := "vol_"+strings.Repeat(tag, 31)+"0", "vol_"+strings.Repeat(tag, 31)+"1"
	b, err := c.Register(ctx, "kind-store-"+tag, "kind-volume-"+tag)
	if err != nil {
		t.Fatal("registration", err)
	}
	if err = keys.Ensure(ctx, agent, live); err != nil {
		t.Fatal("new key", err)
	}
	if _, err = c.BeginRevocation(ctx, "kind/agent-"+tag); err != nil {
		t.Fatal("revocation", err)
	}
	r, err := c.Scan(ctx, b)
	if err == nil {
		err = c.RecordVerifiedFence(ctx, r)
	}
	if err != nil {
		t.Fatal("fence revision", err)
	}
	if err = c.RecordOutcome(ctx, b, Outcome{ID: "kind-event-" + tag, Digest: sha256.Sum256([]byte("first"))}); err != nil {
		t.Fatal("outcome", err)
	}
	next, err := c.ReserveIncarnation(ctx, b, "kind-restore-"+tag)
	if err != nil {
		t.Fatal("reservation", err)
	}
	if r, err = c.Scan(ctx, next); err == nil {
		err = c.RecordVerifiedFence(ctx, r)
	}
	if err != nil {
		t.Fatal("fence revision", err)
	}
	losses, err := c.Activate(ctx, r, Restoration{Inspect: everythingMissing, Publish: func() error { return nil }})
	if err != nil || len(losses) != 1 {
		t.Fatal("declared loss", losses, err)
	}
	if err = c.RecordOutcome(ctx, next, Outcome{ID: "kind-event-" + tag, Digest: sha256.Sum256([]byte("rerun"))}); err != nil {
		t.Fatal("rerun", err)
	}
	if err = keys.Ensure(ctx, agent, destroyed); err == nil {
		err = keys.Revoke(ctx, agent, destroyed)
	}
	if err != nil {
		t.Fatal("key destruction", err)
	}
	sealed := Binding{Store: "kind-sealed-" + tag, Volume: "kind-sealed-volume-" + tag, Incarnation: 1}
	if _, err = c.Register(ctx, sealed.Store, sealed.Volume); err == nil {
		err = c.RecordRetiredSeal(ctx, sealed)
	}
	if err != nil {
		t.Fatal("seal", err)
	}
	if status, _, err := c.OutcomeStatus(ctx, "kind-event-"+tag); err != nil || status != StatusRerunConfirmed {
		t.Fatal("outcome status", status, err)
	}
	if _, err = c.Lookup(ctx, sealed.Store); !errors.Is(err, ErrSealed) {
		t.Fatal("seal lost", err)
	}
	if err = keys.WithKey(ctx, agent, destroyed, func([]byte) error { return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed key usable", err)
	}
	if err = keys.WithKey(ctx, agent, live, func([]byte) error { return nil }); err != nil {
		t.Fatal("new key unusable", err)
	}
}

// NEW_EPOCH: the promoted catalogue holds the next epoch before anything
// opens it, and signs and logs under it.
func TestPromotionWritesTheNextEpochBeforeItsFirstWrite(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	position, _ := p.replica.Position(t.Context())
	// Before any write: read the new catalogue's row as it lies on disk.
	result, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys"), p.unlock)
	if err != nil || result.Epoch != position.Epoch+1 || result.Position.Seq != position.Seq {
		t.Fatal(result, err)
	}
	db, err := openSQLite(filepath.Join(p.dir, "promoted-restore", "catalog.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var epoch, seq uint64
	var recipient []byte
	err = db.QueryRow("SELECT epoch,seq,recipient FROM replication").Scan(&epoch, &seq, &recipient)
	db.Close()
	if err != nil || epoch != 2 || seq != position.Seq || recipient != nil {
		t.Fatal("promoted catalogue's row", epoch, seq, recipient, err)
	}
	keys, err := keyauthority.Open(filepath.Join(p.dir, "promoted-keys"), result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if armed, err := keys.Replicated(); err != nil || armed {
		t.Fatal("promoted key authority armed", err)
	}
	c, err := Open(t.Context(), filepath.Join(p.dir, "promoted-restore"), result.RestoreAuthority, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Its first receipt carries the new epoch.
	r, err := c.Scan(t.Context(), Binding{Store: "store-a", Volume: "volume-a", Incarnation: 2})
	if err != nil || r.Epoch != 2 {
		t.Fatal("first receipt", r.Epoch, err)
	}
	// Its first record, once a new standby arms it, too, after the replica's
	// last record.
	q := seedStandby(t, filepath.Join(p.dir, "standby"), keys, c)
	if _, err = c.Register(t.Context(), "store-n", "volume-n"); err != nil {
		t.Fatal(err)
	}
	sent := q.link.records()
	first, err := authoritylog.Decode(sent[len(sent)-1])
	if err != nil || first.Epoch != 2 || first.Seq != position.Seq+1 || !bytes.Equal(first.Prev, position.Digest) {
		t.Fatal("first record of the promoted authority", first, err)
	}
	q.same(t)
}

// A crash at any step of a promotion: the next call completes it. Records
// are refused from the first step on.
func TestInterruptedPromotionCompletes(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	restoreRoot, keyRoot := filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys")
	// The restore authority's directory cannot be used: the replica is marked
	// and the key authority written, then the call fails.
	if err := os.Mkdir(restoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock); !errors.Is(err, ErrUnavailable) {
		t.Fatal("promotion into an unusable directory", err)
	}
	if status, err := InspectReplica(t.Context(), filepath.Join(p.dir, "replica")); err != nil || !status.Promoted {
		t.Fatal("the replica was not marked first", status, err)
	}
	if _, err := p.catalog.Register(t.Context(), "store-late", "volume-late"); !isRefusal(err, authoritylog.RefusedPromoted) {
		t.Fatal("a record reached an interrupted promotion", err)
	}
	if err := os.Chmod(restoreRoot, 0700); err != nil {
		t.Fatal(err)
	}
	result, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock)
	if err != nil || result.Epoch != 2 {
		t.Fatal("the promotion did not complete", result, err)
	}
	c, err := Open(t.Context(), restoreRoot, result.RestoreAuthority, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !slices.Equal(dump(t, c.db), dump(t, p.replica.db)) {
		t.Fatal("completed promotion differs from the replica")
	}
}

// Promote twice, and again after the promoted authority wrote and was armed:
// each call reports the same promotion and changes nothing.
func TestPromotingTwiceReportsTheSamePromotion(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	keys, c, result := promoteStandby(t, p)
	writeEveryKind(t, keys, c, "1")
	again := func() {
		t.Helper()
		before := dump(t, c.db)
		got, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys"), p.unlock)
		if err != nil || got.Epoch != result.Epoch || got.Position.Seq != result.Position.Seq {
			t.Fatal("repeated promotion", got, err)
		}
		if !slices.Equal(dump(t, c.db), before) {
			t.Fatal("a repeated promotion changed the authority")
		}
	}
	again()
	seedStandby(t, filepath.Join(p.dir, "standby"), keys, c)
	writeEveryKind(t, keys, c, "2")
	again()
	// Never into other directories: the replica gave its keys once.
	if _, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "other-restore"), filepath.Join(p.dir, "other-keys"), p.unlock); err == nil {
		t.Fatal("a promoted replica was promoted again elsewhere")
	}
}

// FENCE_OLD: a promoted replica takes no record and runs no listener.
func TestPromotedReplicaRunsNoListener(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	root := filepath.Join(p.dir, "replica")
	if status, err := InspectReplica(t.Context(), root); err != nil || status.Promoted || status.RestoreAuthority != p.catalog.Identity() {
		t.Fatal(status, err)
	}
	promoteStandby(t, p)
	if _, err := OpenReplica(t.Context(), root, p.catalog.Identity(), p.keys.Identity()); !errors.Is(err, ErrPromoted) {
		t.Fatal("a promoted replica opened to serve", err)
	}
	// A listener still running from before stops at its next check.
	if status, err := p.replica.Status(t.Context()); err != nil || !status.Promoted {
		t.Fatal("promotion not visible to the running replica", status, err)
	}
	if _, err := p.replica.Sync(t.Context(), p.catalog.request(1, nil)); !isRefusal(err, authoritylog.RefusedPromoted) {
		t.Fatal("promoted replica answered", err)
	}
}

// oldPrimaryCannotResendAfterPromotionTest and restoreWitnessUnfencedGuard:
// the old primary comes back with a record its replica never acknowledged.
// After the promotion a key was destroyed. Neither the promoted replica nor
// a standby seeded from the promoted authority takes the old primary's
// resend or stream, twice; the key stays destroyed.
func TestOldPrimaryCannotResendAfterPromotion(t *testing.T) {
	p := replicated(t)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	if err = p.keys.Ensure(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	// The tail of the old primary's log: committed there, never acknowledged.
	p.link.set(true)
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	err = p.catalog.RecordOutcome(short, b, Outcome{ID: "event-lost", Digest: sha256.Sum256([]byte("lost"))})
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	tail, _, err := p.catalog.readLog(ctx, 0, 1<<62)
	if err != nil || len(tail) != 1 {
		t.Fatal("expected one unacknowledged record", len(tail), err)
	}
	// losePrimary, promote; then beginRevocation and destroyKey on the new root.
	keys, c, result := promoteStandby(t, p)
	if _, err = c.BeginRevocation(ctx, "agent/after"); err != nil {
		t.Fatal(err)
	}
	if err = keys.Revoke(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	q := seedStandby(t, filepath.Join(p.dir, "standby"), keys, c)
	before, standby := dump(t, c.db), dump(t, q.replica.db)
	position, _ := q.replica.Position(ctx)
	// oldPrimaryReturns, oldPrimaryResends: to the promoted replica, then to
	// the new standby; its next transaction resends, and so does a replay.
	resend := authoritylog.Request{RestoreAuthority: p.catalog.Identity(), KeyAuthority: p.keys.Identity(), Epoch: 1, Records: tail}
	for _, target := range []struct {
		link authoritylog.Link
		kind string
	}{{p.replica, authoritylog.RefusedPromoted}, {q.replica, authoritylog.RefusedOlderEpoch}} {
		p.link.mu.Lock()
		p.link.target, p.link.down = target.link, false
		p.link.mu.Unlock()
		_, old := p.reopen(t, p.link)
		if _, err = old.Lookup(ctx, "store-a"); !errors.Is(err, ErrUnavailable) || !isRefusal(err, target.kind) {
			t.Fatal("the old primary's resend was taken", target.kind, err)
		}
		for range 2 {
			if _, err = target.link.Sync(ctx, resend); !isRefusal(err, target.kind) {
				t.Fatal("the old primary's replay was taken", target.kind, err)
			}
		}
	}
	// Its records under the new epoch's number: still an older epoch.
	resend.Epoch = result.Epoch
	if _, err = q.replica.Sync(ctx, resend); !isRefusal(err, authoritylog.RefusedOlderEpoch) {
		t.Fatal("old records relabelled", err)
	}
	if after, _ := q.replica.Position(ctx); after.Seq != position.Seq || !slices.Equal(dump(t, q.replica.db), standby) {
		t.Fatal("the old primary changed the new standby")
	}
	if !slices.Equal(dump(t, c.db), before) {
		t.Fatal("the old primary changed the promoted authority")
	}
	if err = keys.Ensure(ctx, streamAgent, streamVolume); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a key destroyed after the promotion came back", err)
	}
	var revoked bool
	var wrapped []byte
	if err = q.replica.db.QueryRow("SELECT revoked,wrapped FROM replica_volumes WHERE volume=?", streamVolume).Scan(&revoked, &wrapped); err != nil || !revoked || wrapped != nil {
		t.Fatal("the new standby holds the destroyed key", revoked, err)
	}
	if status, _, err := c.OutcomeStatus(ctx, "event-lost"); err != nil || status != StatusUnrecorded {
		t.Fatal("the old primary's unacknowledged outcome reached the promoted authority", status, err)
	}
}

// acknowledgedWriteIsOnReplicaTest and destroyedKeyNeverReturnsAfterFailoverTest:
// a revocation completed and a key destroyed on the primary are in the
// promoted authorities, which run alone at epoch 2.
func TestAcknowledgedWritesSurviveTheFailover(t *testing.T) {
	p := replicated(t)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	if err = p.keys.Ensure(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	// revoke(0): begin, fence the store, complete.
	if _, err = p.catalog.BeginRevocation(ctx, "agent/zero"); err != nil {
		t.Fatal(err)
	}
	receipt(t, p.catalog, b)
	if err = p.catalog.WithRevocation(ctx, "agent/zero", []Binding{b}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// permanentlySeal(0), destroyKey(0).
	if err = p.catalog.RecordRetiredSeal(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err = p.keys.Revoke(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	keys, c, result := promoteStandby(t, p)
	state, err := c.Replication(ctx)
	if err != nil || result.Epoch != 2 || state.Armed || state.Committed.Epoch != 2 {
		t.Fatal("promoted authority", result, state, err)
	}
	if err = c.WithSubjectKey(ctx, "agent/zero", func() error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal("revocation lost in the failover", err)
	}
	if _, err = c.Lookup(ctx, b.Store); !errors.Is(err, ErrSealed) {
		t.Fatal("seal lost in the failover", err)
	}
	// decryptBackup(1,0).fail(): no key, and no second key, for the volume.
	if err = keys.WithKey(ctx, streamAgent, streamVolume, func([]byte) error { return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed key came back", err)
	}
	if err = keys.Ensure(ctx, streamAgent, streamVolume); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a second key for a destroyed volume", err)
	}
}

// Finding 3 and promotedAuthorityRunsAloneUntilSeededTest: with no standby,
// every kind of write proceeds, seals, new keys and destruction included,
// and nothing is logged. Once a new standby is seeded, every write reaches
// it, and waits when it is unreachable. A second failover then promotes it.
func TestPromotedAuthorityRunsAloneUntilSeeded(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	keys, c, result := promoteStandby(t, p)
	// No standby: nothing to reach, nothing to wait for.
	writeEveryKind(t, keys, c, "1")
	state, err := c.Replication(t.Context())
	if err != nil || state.Armed || state.Committed.Seq != result.Position.Seq {
		t.Fatal("the promoted authority logged without a standby", state, err)
	}
	var logged int
	if err = c.db.QueryRow("SELECT count(*) FROM replication_log").Scan(&logged); err != nil || logged != 0 {
		t.Fatal("log without a standby", logged, err)
	}
	// seedStandby, with the existing snapshot and init-replica path.
	q := seedStandby(t, filepath.Join(p.dir, "standby"), keys, c)
	q.same(t)
	writeEveryKind(t, keys, c, "2")
	q.same(t)
	// The new standby's stream replays twice without change.
	records := q.link.records()
	before := dump(t, q.replica.db)
	for range 2 {
		for start := 0; start < len(records); start += authoritylog.MaxRecords {
			batch := records[start:min(start+authoritylog.MaxRecords, len(records))]
			if _, err = q.replica.Sync(t.Context(), c.request(result.Epoch, batch)); err != nil {
				t.Fatal("replay of the new stream", err)
			}
		}
	}
	if !slices.Equal(dump(t, q.replica.db), before) {
		t.Fatal("a replay changed the new standby")
	}
	// Armed again: the standby is unreachable, and a seal waits for it.
	if _, err = c.Register(t.Context(), "store-w", "volume-w"); err != nil {
		t.Fatal(err)
	}
	q.link.set(true)
	short, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	err = c.RecordRetiredSeal(short, Binding{Store: "store-w", Volume: "volume-w", Incarnation: 1})
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("a seal returned without the new standby", err)
	}
	q.link.set(false)
	if _, err = c.Lookup(t.Context(), "store-w"); !errors.Is(err, ErrSealed) {
		t.Fatal(err)
	}
	q.same(t)
	// The second failover: the new standby becomes the root, at epoch 3, with
	// everything written since the first.
	second, err := Promote(t.Context(), filepath.Join(q.dir, "replica"), filepath.Join(q.dir, "promoted-restore"), filepath.Join(q.dir, "promoted-keys"), q.unlock)
	if err != nil || second.Epoch != 3 {
		t.Fatal(second, err)
	}
	third, err := Open(t.Context(), filepath.Join(q.dir, "promoted-restore"), second.RestoreAuthority, second.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if !slices.Equal(dump(t, third.db), dump(t, c.db)) {
		t.Fatal("the second promotion lost writes")
	}
	if _, err = c.Register(t.Context(), "store-x", "volume-x"); !isRefusal(err, authoritylog.RefusedPromoted) {
		t.Fatal("the first promoted authority still replicates", err)
	}
}
