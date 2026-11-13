//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

var (
	streamAgent  = "agt_" + strings.Repeat("a", 32)
	streamVolume = "vol_" + strings.Repeat("b", 32)
)

// pair is a primary with both authorities, armed, and its replica.
type pair struct {
	dir       string
	keys      *keyauthority.Files
	catalog   *Catalog
	replica   *Replica
	link      *tap
	unlock    *authoritylog.UnlockKey
	recipient authoritylog.Recipient
}

// tap is an in-memory link that keeps every request and can fail on demand.
type tap struct {
	mu       sync.Mutex
	target   authoritylog.Link
	down     bool
	sent     [][]byte
	afterAck func()
}

func (l *tap) Sync(ctx context.Context, r authoritylog.Request) (authoritylog.Position, error) {
	l.mu.Lock()
	down, target := l.down, l.target
	l.sent = append(l.sent, r.Records...)
	after := l.afterAck
	l.mu.Unlock()
	if down || target == nil {
		return authoritylog.Position{}, errors.New("standby unreachable")
	}
	p, err := target.Sync(ctx, r)
	if after != nil && len(r.Records) > 0 {
		after()
	}
	return p, err
}

func (l *tap) set(down bool) {
	l.mu.Lock()
	l.down = down
	l.mu.Unlock()
}

func (l *tap) records() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.sent)
}

func newUnlockKey(t *testing.T) (*authoritylog.UnlockKey, authoritylog.Recipient) {
	t.Helper()
	text, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := authoritylog.ParseUnlockKey(text)
	if err != nil || unlock.Recipient() != recipient {
		t.Fatal("unlock key does not round trip", err)
	}
	return unlock, recipient
}

// primary initializes both authorities, standalone.
func primary(t *testing.T, dir string) (*keyauthority.Files, *Catalog) {
	t.Helper()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return keys, c
}

func replicated(t *testing.T) *pair {
	t.Helper()
	p := &pair{dir: t.TempDir(), link: &tap{}}
	p.keys, p.catalog = primary(t, p.dir)
	p.unlock, p.recipient = newUnlockKey(t)
	snapshot := filepath.Join(p.dir, "snapshot.sqlite")
	position, err := p.catalog.Snapshot(t.Context(), p.keys, p.recipient, snapshot)
	if err != nil || position.Epoch != 1 || position.Seq != 0 {
		t.Fatal(position, err)
	}
	if p.replica, err = InitializeReplica(t.Context(), filepath.Join(p.dir, "replica"), snapshot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.replica.Close() })
	p.link.target = p.replica
	if err = p.catalog.Replicate(t.Context(), p.link); err != nil {
		t.Fatal(err)
	}
	p.keys.SetJournal(p.catalog)
	return p
}

// reopen opens the primary as another process would, with its own link.
func (p *pair) reopen(t *testing.T, link authoritylog.Link) (*keyauthority.Files, *Catalog) {
	t.Helper()
	keys, err := keyauthority.Open(filepath.Join(p.dir, "keys"), p.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(t.Context(), filepath.Join(p.dir, "restore"), p.catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if link != nil {
		if err = c.Replicate(t.Context(), link); err != nil {
			t.Fatal(err)
		}
		keys.SetJournal(c)
	}
	return keys, c
}

// dump lists the catalogue's rows, without the signing secret.
func dump(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var out []string
	for _, query := range []string{
		"SELECT identity||'|'||key_identity||'|'||revision FROM authority",
		"SELECT id||'|'||volume||'|'||incarnation||'|'||sealed||'|'||ack_revision FROM stores ORDER BY id",
		"SELECT operation||'|'||store||'|'||previous||'|'||current FROM reservations ORDER BY operation",
		"SELECT subject||'|'||revision FROM revocations ORDER BY subject",
		"SELECT id||'|'||store||'|'||hex(digest) FROM outcomes ORDER BY id",
		"SELECT outcome||'|'||store||'|'||incarnation FROM losses ORDER BY outcome,incarnation",
		"SELECT outcome||'|'||incarnation||'|'||hex(digest) FROM reruns ORDER BY outcome,incarnation",
	} {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err = rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		rows.Close()
		out = append(out, "--")
	}
	return out
}

func (p *pair) same(t *testing.T) {
	t.Helper()
	if got, want := dump(t, p.replica.db), dump(t, p.catalog.db); !slices.Equal(got, want) {
		t.Fatalf("replica differs from the primary:\n%v\n%v", got, want)
	}
	state, err := p.catalog.Replication(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	position, err := p.replica.Position(t.Context())
	if err != nil || position.Seq != state.Committed.Seq || !bytes.Equal(position.Digest, state.Committed.Digest) {
		t.Fatal("replica position", position, state.Committed, err)
	}
	// Every live key on the primary is on the replica, wrapped; every
	// tombstone too, without a wrapped copy.
	err = p.keys.Export(t.Context(), func(e keyauthority.Entry) error {
		var commitment, wrapped []byte
		var revoked bool
		if err := p.replica.db.QueryRow("SELECT revoked,commitment,wrapped FROM replica_volumes WHERE volume=? AND agent=?", e.Volume, e.Agent).Scan(&revoked, &commitment, &wrapped); err != nil {
			return fmt.Errorf("volume %s: %w", e.Volume, err)
		}
		if revoked != e.Revoked {
			return errors.New("tombstone differs")
		}
		if e.Revoked && wrapped != nil {
			return errors.New("destroyed key kept wrapped")
		}
		if e.Key != nil && !bytes.Equal(commitment, authoritylog.KeyCommitment(p.keys.Identity(), e.Agent, e.Volume, e.Key)) {
			return errors.New("replicated key differs")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// everyWrite runs one of each replicated write of both authorities.
func everyWrite(t *testing.T, keys *keyauthority.Files, c *Catalog) Binding {
	t.Helper()
	ctx := t.Context()
	b, err := c.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	if _, err = c.BeginRevocation(ctx, "agent/one"); err != nil {
		t.Fatal(err)
	}
	r, err := c.Scan(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = c.RecordOutcome(ctx, b, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("one"))}); err != nil {
		t.Fatal(err)
	}
	next, err := c.ReserveIncarnation(ctx, b, "restore-1")
	if err != nil {
		t.Fatal(err)
	}
	r, err = c.Scan(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Activate(ctx, r, Restoration{Inspect: everythingMissing, Publish: func() error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err = c.RecordOutcome(ctx, next, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("rerun"))}); err != nil {
		t.Fatal(err)
	}
	other := "vol_" + strings.Repeat("c", 32)
	if err = keys.Ensure(ctx, streamAgent, other); err != nil {
		t.Fatal(err)
	}
	if err = keys.Revoke(ctx, streamAgent, other); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Register(ctx, "store-z", "volume-z"); err != nil {
		t.Fatal(err)
	}
	if err = c.RecordRetiredSeal(ctx, Binding{Store: "store-z", Volume: "volume-z", Incarnation: 1}); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestStandaloneModeLogsNothing(t *testing.T) {
	keys, c := primary(t, t.TempDir())
	everyWrite(t, keys, c)
	state, err := c.Replication(t.Context())
	if err != nil || state.Armed || state.Committed.Seq != 0 {
		t.Fatal("standalone catalogue logged", state, err)
	}
	var rows int
	if err = c.db.QueryRow("SELECT (SELECT count(*) FROM replication)+(SELECT count(*) FROM replication_log)").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("standalone catalogue logged", rows, err)
	}
	if armed, err := keys.Replicated(); err != nil || armed {
		t.Fatal("standalone key authority armed", err)
	}
	if err = c.Replicate(t.Context(), &tap{}); !errors.Is(err, ErrNotArmed) {
		t.Fatal("a link was accepted without a snapshot", err)
	}
	registry := telemetry.NewRegistry()
	c.ObserveReplication(authoritylog.NewMetrics(registry))
	var out strings.Builder
	registry.WriteTo(&out)
	if !strings.Contains(out.String(), "agentcapsule_authority_replication_enabled 0\n") {
		t.Fatal("standalone mode not reported", out.String())
	}
}

func TestEveryWriteReachesTheReplicaBeforeItReturns(t *testing.T) {
	p := replicated(t)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	acknowledged := uint64(0)
	// After each write, the replica already holds it.
	p.link.afterAck = func() {
		position, err := p.replica.Position(context.Background())
		if err != nil || position.Seq <= acknowledged {
			t.Error("acknowledgment without a durable apply", position, err)
		}
		acknowledged = position.Seq
	}
	everyWrite(t, p.keys, p.catalog)
	p.same(t)
	if acknowledged < 10 {
		t.Fatal("too few records", acknowledged)
	}
	var logged int
	if err := p.catalog.db.QueryRow("SELECT count(*) FROM replication_log").Scan(&logged); err != nil || logged > 1 {
		t.Fatal("the primary keeps acknowledged records", logged, err)
	}
	var out strings.Builder
	registry.WriteTo(&out)
	for _, want := range []string{
		"agentcapsule_authority_replication_enabled 1\n",
		fmt.Sprintf("agentcapsule_authority_replication_acknowledged_sequence %d\n", acknowledged),
		"agentcapsule_authority_replication_lag_records 0\n",
		`agentcapsule_authority_replication_last_error{kind="none"} 1` + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("missing metric", want, out.String())
		}
	}
	// A retry that changes nothing records nothing.
	sent := len(p.link.records())
	if err := p.catalog.RecordOutcome(t.Context(), Binding{Store: "store-a", Volume: "volume-a", Incarnation: 2}, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("rerun"))}); err != nil {
		t.Fatal(err)
	}
	if err := p.keys.Ensure(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	if len(p.link.records()) != sent {
		t.Fatal("a retry was recorded")
	}
}

func TestWrappedKeysLeaveNoCopyBehind(t *testing.T) {
	p := replicated(t)
	if err := p.keys.Ensure(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	var wrapped []byte
	if err := p.replica.db.QueryRow("SELECT wrapped FROM replica_volumes WHERE volume=?", streamVolume).Scan(&wrapped); err != nil || len(wrapped) == 0 {
		t.Fatal("key not replicated", err)
	}
	var key []byte
	if err := p.keys.WithKey(t.Context(), streamAgent, streamVolume, func(k []byte) error { key = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	got, err := p.unlock.Open(authoritylog.KeyContext(p.keys.Identity(), streamAgent, streamVolume), wrapped)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("the replica's copy does not open to the key", err)
	}
	clear(got)
	// The primary's log dropped the wrapped key once acknowledged.
	if contains(t, filepath.Join(p.dir, "restore", "catalog.sqlite"), wrapped) {
		t.Fatal("the primary's log kept the wrapped key")
	}
	// Destroying the key removes the replica's copy in the same write.
	if err = p.keys.Revoke(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	var left []byte
	if err = p.replica.db.QueryRow("SELECT revoked,wrapped FROM replica_volumes WHERE volume=?", streamVolume).Scan(&revoked, &left); err != nil || !revoked || left != nil {
		t.Fatal("destroyed key kept on the replica", revoked, err)
	}
	for _, path := range []string{filepath.Join(p.dir, "replica", "replica.sqlite"), filepath.Join(p.dir, "restore", "catalog.sqlite")} {
		if contains(t, path, wrapped) {
			t.Fatal("a wrapped copy outlived its key", path)
		}
	}
	for _, record := range p.link.records() {
		r, err := authoritylog.Decode(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range r.Ops {
			if op.Kind == authoritylog.OpKeyCreate && bytes.Contains(op.Wrapped, key) {
				t.Fatal("a record carried the key in clear")
			}
		}
	}
	p.same(t)
}

func contains(t *testing.T, path string, b []byte) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	return bytes.Contains(data, b)
}

func TestReplicaRefusesGapOlderEpochAndChangedDuplicate(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	records := p.link.records()
	last, err := authoritylog.Decode(records[len(records)-1])
	if err != nil {
		t.Fatal(err)
	}
	request := func(epoch uint64, records ...[]byte) authoritylog.Request {
		return authoritylog.Request{RestoreAuthority: p.catalog.Identity(), KeyAuthority: p.keys.Identity(), Epoch: epoch, Records: records}
	}
	encode := func(r authoritylog.Record) []byte {
		b, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := dump(t, p.replica.db)
	gap := last
	gap.Seq += 2
	changed := last
	changed.Ops = []authoritylog.Op{{Kind: authoritylog.OpKeyRevoke, Agent: streamAgent, Volume: "vol_" + strings.Repeat("e", 32)}}
	older := last
	older.Seq++
	older.Prev = authoritylog.Digest(records[len(records)-1])
	wrongPrev := older
	wrongPrev.Prev = authoritylog.Origin()
	for _, c := range []struct {
		name string
		req  authoritylog.Request
		kind string
	}{
		{"gap", request(1, encode(gap)), authoritylog.RefusedGap},
		{"changed duplicate", request(1, encode(changed)), authoritylog.RefusedConflict},
		{"broken chain", request(1, encode(wrongPrev)), authoritylog.RefusedConflict},
		{"newer epoch", request(2, encode(older)), authoritylog.RefusedNewerEpoch},
		{"other authority", authoritylog.Request{RestoreAuthority: "restoreauth_" + strings.Repeat("0", 32), KeyAuthority: p.keys.Identity(), Epoch: 1}, authoritylog.RefusedIdentity},
		{"malformed", request(1, []byte(`{"v":1}`)), authoritylog.RefusedInvalid},
	} {
		_, err := p.replica.Sync(t.Context(), c.req)
		var refusal *authoritylog.Refusal
		if !errors.As(err, &refusal) || refusal.Kind != c.kind || refusal.Position.Seq != last.Seq {
			t.Fatal(c.name, err)
		}
	}
	// An older epoch: the replica moved on, as after a promotion.
	if _, err = p.replica.db.Exec("UPDATE replica_state SET epoch=2"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.replica.Sync(t.Context(), request(1, encode(older))); !isRefusal(err, authoritylog.RefusedOlderEpoch) {
		t.Fatal("older epoch accepted", err)
	}
	older.Epoch = 1
	if _, err = p.replica.Sync(t.Context(), request(2, encode(older))); !isRefusal(err, authoritylog.RefusedOlderEpoch) {
		t.Fatal("record of an older epoch accepted", err)
	}
	if _, err = p.replica.db.Exec("UPDATE replica_state SET epoch=1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dump(t, p.replica.db), before) {
		t.Fatal("a refused record changed the replica")
	}
	// The primary stops on a refusal and reports it.
	if _, err = p.replica.db.Exec("UPDATE replica_state SET epoch=2"); err != nil {
		t.Fatal(err)
	}
	_, other := p.reopen(t, p.link)
	if _, err = other.Register(t.Context(), "store-q", "volume-q"); !errors.Is(err, ErrUnavailable) || !isRefusal(err, authoritylog.RefusedOlderEpoch) {
		t.Fatal("write accepted by a replica of a newer epoch", err)
	}
}

func isRefusal(err error, kind string) bool {
	var refusal *authoritylog.Refusal
	return errors.As(err, &refusal) && refusal.Kind == kind
}

func TestReplayingTheStreamTwiceIsIdempotent(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	before := dump(t, p.replica.db)
	position, _ := p.replica.Position(t.Context())
	records := p.link.records()
	for range 2 {
		for start := 0; start < len(records); start += authoritylog.MaxRecords {
			batch := records[start:min(start+authoritylog.MaxRecords, len(records))]
			got, err := p.replica.Sync(t.Context(), authoritylog.Request{RestoreAuthority: p.catalog.Identity(), KeyAuthority: p.keys.Identity(), Epoch: 1, Records: batch})
			if err != nil || got.Seq != position.Seq {
				t.Fatal("replay was not idempotent", got, err)
			}
		}
	}
	if !slices.Equal(dump(t, p.replica.db), before) {
		t.Fatal("replay changed the replica")
	}
	p.same(t)
}

func TestUnacknowledgedRecordIsResentByTheNextTransaction(t *testing.T) {
	p := replicated(t)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	// The standby is unreachable: the write commits locally, then fails.
	p.link.set(true)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("one"))})
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("write returned without the replica", err)
	}
	// Nothing acts on the unacknowledged record meanwhile, not even a read.
	ctx, cancel = context.WithTimeout(t.Context(), 200*time.Millisecond)
	if _, err = p.catalog.Lookup(ctx, "store-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("read of an unacknowledged record", err)
	}
	cancel()
	state, _ := p.catalog.Replication(t.Context())
	position, _ := p.replica.Position(t.Context())
	if state.Committed.Seq != position.Seq+1 {
		t.Fatal("expected one record committed on the primary only", state.Committed, position)
	}
	// Another process resends it first, from the replica's last sequence.
	p.link.set(false)
	_, other := p.reopen(t, p.link)
	if _, err = other.Lookup(t.Context(), "store-a"); err != nil {
		t.Fatal(err)
	}
	p.same(t)
	// The retry of the operation finds its effect and records nothing.
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("one"))}); err != nil {
		t.Fatal(err)
	}
	if after, _ := p.catalog.Replication(t.Context()); after.Committed.Seq != state.Committed.Seq {
		t.Fatal("the retry was recorded again")
	}
}

func TestReplicaCreatedFromASnapshotCatchesUp(t *testing.T) {
	dir := t.TempDir()
	keys, c := primary(t, dir)
	b, err := c.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	unlock, recipient := newUnlockKey(t)
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = c.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	// Armed: the standalone path is closed, for both authorities.
	if _, err = c.Lookup(t.Context(), "store-a"); !errors.Is(err, ErrReplicaRequired) {
		t.Fatal("armed catalogue used without its replica", err)
	}
	if err = keys.Revoke(t.Context(), streamAgent, streamVolume); !errors.Is(err, keyauthority.ErrUnavailable) {
		t.Fatal("armed key authority used without its journal", err)
	}
	// The worker starts before the replica answers: one write commits
	// locally and waits.
	link := &tap{down: true}
	if err = c.Replicate(t.Context(), link); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	err = c.RecordOutcome(ctx, b, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("one"))})
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	replica, err := InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if _, err = InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot); !errors.Is(err, ErrConflict) {
		t.Fatal("an existing replica was replaced", err)
	}
	link.target = replica
	link.set(false)
	if err = keys.Revoke(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), streamAgent, "vol_"+strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	p := &pair{dir: dir, keys: keys, catalog: c, replica: replica, link: link, unlock: unlock, recipient: recipient}
	p.same(t)
	// A second snapshot keeps the epoch and the recipient.
	if _, err = c.Snapshot(t.Context(), keys, recipient, filepath.Join(dir, "second.sqlite")); err != nil {
		t.Fatal(err)
	}
	_, other := newUnlockKey(t)
	if _, err = c.Snapshot(t.Context(), keys, other, filepath.Join(dir, "third.sqlite")); !errors.Is(err, ErrConflict) {
		t.Fatal("snapshot re-armed with another unlock key", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "third.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed snapshot left its file", err)
	}
}

func TestSnapshotHoldsNoSecretInClear(t *testing.T) {
	dir := t.TempDir()
	keys, c := primary(t, dir)
	if err := keys.Ensure(t.Context(), streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	var key, secret []byte
	if err := keys.WithKey(t.Context(), streamAgent, streamVolume, func(k []byte) error { key = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.db.QueryRow("SELECT secret FROM authority").Scan(&secret); err != nil {
		t.Fatal(err)
	}
	_, recipient := newUnlockKey(t)
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err := c.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	if contains(t, snapshot, key) || contains(t, snapshot, secret) {
		t.Fatal("snapshot holds a secret in clear")
	}
	// A tampered snapshot is refused.
	db, err := openSQLite(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TRIGGER evil AFTER INSERT ON revocations BEGIN DELETE FROM revocations; END"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err = InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot); !errors.Is(err, ErrInput) {
		t.Fatal("tampered snapshot accepted", err)
	}
}

func TestPromotionUnwrapsWithTheUnlockKeyAndFencesTheOldPrimary(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	var want [32]byte
	if err := p.keys.WithKey(t.Context(), streamAgent, streamVolume, func(k []byte) error { want = sha256.Sum256(k); return nil }); err != nil {
		t.Fatal(err)
	}
	position, _ := p.replica.Position(t.Context())
	restoreRoot, keyRoot := filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys")
	wrong, _ := newUnlockKey(t)
	if _, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, wrong); !errors.Is(err, ErrInput) {
		t.Fatal("promoted with another unlock key", err)
	}
	if _, err := os.Stat(keyRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused promotion wrote", err)
	}
	result, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock)
	if err != nil || result.Epoch != 2 || result.Position.Seq != position.Seq || result.RestoreAuthority != p.catalog.Identity() || result.KeyAuthority != p.keys.Identity() {
		t.Fatal(result, err)
	}
	// Again: it completes, and changes nothing.
	if again, err := Promote(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock); err != nil || again.Epoch != result.Epoch {
		t.Fatal(again, err)
	}
	keys, err := keyauthority.Open(keyRoot, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	var got [32]byte
	if err = keys.WithKey(t.Context(), streamAgent, streamVolume, func(k []byte) error { got = sha256.Sum256(k); return nil }); err != nil || got != want {
		t.Fatal("promoted key differs", err)
	}
	other := "vol_" + strings.Repeat("c", 32)
	if err = keys.Ensure(t.Context(), streamAgent, other); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed key came back", err)
	}
	c, err := Open(t.Context(), restoreRoot, result.RestoreAuthority, result.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !slices.Equal(dump(t, c.db), dump(t, p.catalog.db)) {
		t.Fatal("promoted catalogue differs")
	}
	// The secret is the primary's: its receipts and archives stay valid.
	b := Binding{Store: "store-a", Volume: "volume-a", Incarnation: 2}
	r, err := p.catalog.Scan(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.WithCurrentFences(t.Context(), r, func() error { return nil }); err != nil {
		t.Fatal("receipt of the old primary refused", err)
	}
	state, err := c.Replication(t.Context())
	if err != nil || state.Armed || state.Committed.Epoch != 2 {
		t.Fatal("promoted catalogue", state, err)
	}
	// The replica refuses everything now, and kept no wrapped copy.
	if _, err = p.catalog.Register(t.Context(), "store-late", "volume-late"); !isRefusal(err, authoritylog.RefusedPromoted) {
		t.Fatal("promoted replica accepted a record", err)
	}
	var wrapped int
	if err = p.replica.db.QueryRow("SELECT count(*) FROM replica_volumes WHERE wrapped IS NOT NULL").Scan(&wrapped); err != nil || wrapped != 0 {
		t.Fatal("promotion kept wrapped copies", wrapped, err)
	}
	// A new standby for the new primary: the old primary's epoch is refused.
	unlock, recipient := newUnlockKey(t)
	snapshot := filepath.Join(p.dir, "new-snapshot.sqlite")
	if position, err := c.Snapshot(t.Context(), keys, recipient, snapshot); err != nil || position.Epoch != 2 {
		t.Fatal(position, err)
	}
	standby, err := InitializeReplica(t.Context(), filepath.Join(p.dir, "new-replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Close()
	p.link.target = standby
	if _, err = p.catalog.Register(t.Context(), "store-old", "volume-old"); !isRefusal(err, authoritylog.RefusedOlderEpoch) {
		t.Fatal("old primary accepted by the new standby", err)
	}
	if err = c.Replicate(t.Context(), standby); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	if _, err = c.Register(t.Context(), "store-new", "volume-new"); err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), streamAgent, "vol_"+strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	_ = unlock
	if got, want := dump(t, standby.db), dump(t, c.db); !slices.Equal(got, want) {
		t.Fatal("new standby differs", got, want)
	}
}

func TestReplicaIsNeverOpenedAsAnAuthority(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	root := filepath.Join(p.dir, "replica")
	if c, err := Open(t.Context(), root, p.catalog.Identity(), p.keys.Identity()); err == nil {
		c.Close()
		t.Fatal("replica opened as a restore authority")
	}
	if _, err := keyauthority.Open(root, p.keys.Identity()); err == nil {
		t.Fatal("replica opened as a key authority")
	}
	if _, err := OpenReplica(t.Context(), root, p.catalog.Identity(), "keyauth_"+strings.Repeat("0", 32)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replica opened for another authority", err)
	}
	// A copy of its file under the catalogue's name does not open either.
	data, err := os.ReadFile(filepath.Join(root, "replica.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(p.dir, "fake")
	if err = os.Mkdir(fake, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(fake, "catalog.sqlite"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(fake, "identity"), []byte(p.catalog.Identity()), 0600); err != nil {
		t.Fatal(err)
	}
	if c, err := Open(t.Context(), fake, p.catalog.Identity(), p.keys.Identity()); err == nil {
		c.Close()
		t.Fatal("replica file opened as a restore authority")
	}
}
