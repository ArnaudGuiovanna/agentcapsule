//go:build linux && cgo

package restoreauthority

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// These tests project the degraded-mode runs of spec/restore_authority_test.qnt
// (module restoreAuthorityReplicaTests) and the guard of
// restoreWitnessDegradedDestructionBroken (spec/restore_witness.qnt). Each one
// names its Quint run; they are written by hand from the runs. The model's
// degrade is the standby stopping and the delay passing (degrade in
// degraded_test.go); restoreLink then resync is the standby answering again
// and the replica catching up; failover is Promote on the replica as it
// stands, as far as it is built: the announcement of the window and the
// revocation of every bearer token come with the promotion command. As in
// key_runs_test.go, the model's store 0 is the offboarded agent "agt_b…" with
// its volume key, and store 1 is "agt_a…".

// resync brings the standby back and waits until the replica holds the log
// and degraded mode is over.
func resync(t *testing.T, p *pair) {
	t.Helper()
	p.link.set(false)
	eventually(t, "the resync", func() bool { return !isDegraded(p.catalog) && applied(t, p) == committed(t, p.catalog) })
}

// promote is the model's failover, as far as it is built: the primary is
// gone, and the replica becomes both authorities.
func promote(t *testing.T, p *pair) (*keyauthority.Files, *Catalog) {
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
	return keys, c
}

// sealedAndRevoked is init.then(revoke(0)).then(permanentlySeal(0)), with
// store 0's key: the offboarded agent is revoked, every store fenced, and
// store 0 sealed. It returns store 1.
func sealedAndRevoked(t *testing.T, p *pair) Binding {
	t.Helper()
	ctx := t.Context()
	live, err := p.catalog.Register(ctx, keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := p.catalog.Register(ctx, offboarded, offboardedV)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.keys.Ensure(ctx, offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	if _, err = p.catalog.BeginRevocation(ctx, offboarded); err != nil {
		t.Fatal(err)
	}
	receipt(t, p.catalog, live)
	receipt(t, p.catalog, gone)
	if err = p.catalog.WithRevocation(ctx, offboarded, []Binding{live, gone}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.RecordRetiredSeal(ctx, gone); err != nil {
		t.Fatal(err)
	}
	return live
}

// destructionResumesAfterResyncTest. In degraded mode the sealed store's key
// cannot be destroyed: it waits, and still opens a backup, on the primary and
// on the replica. Once the replica has caught up, the destruction goes
// through, and removes the replica's copy in the same write.
func TestDestructionResumesAfterResync(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	live := sealedAndRevoked(t, p)
	header := wrappedBackup(t, p.keys, offboarded, offboardedV)
	degrade(t, p, k, live)
	if err := p.keys.Revoke(within(t, 200*time.Millisecond), offboarded, offboardedV); !errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("key destruction in degraded mode", err)
	}
	if err := openBackup(t, p.keys, offboarded, offboardedV, header); err != nil {
		t.Fatal("the key went without the replica", err)
	}
	var wrapped []byte
	if err := p.replica.db.QueryRow("SELECT wrapped FROM replica_volumes WHERE volume=?", offboardedV).Scan(&wrapped); err != nil || len(wrapped) == 0 {
		t.Fatal("the replica lost its copy", err)
	}
	resync(t, p)
	if err := p.keys.Revoke(t.Context(), offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	if err := openBackup(t, p.keys, offboarded, offboardedV, header); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed key opened a backup", err)
	}
	var revoked bool
	if err := p.replica.db.QueryRow("SELECT revoked,wrapped FROM replica_volumes WHERE volume=?", offboardedV).Scan(&revoked, &wrapped); err != nil || !revoked || wrapped != nil {
		t.Fatal("the replica keeps the destroyed key", revoked, err)
	}
	p.same(t)
}

// restoreWitnessDegradedDestructionGuard: the schedule of
// restoreWitnessDegradedDestructionBroken on the safe configuration ends with
// a destruction that degraded mode refuses. Nothing was destroyed, so a
// promotion has nothing to bring back: the key is where it was.
func TestDegradedModeHoldsKeyDestruction(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	live := sealedAndRevoked(t, p)
	header := wrappedBackup(t, p.keys, offboarded, offboardedV)
	degrade(t, p, k, live)
	if err := p.keys.Revoke(within(t, 200*time.Millisecond), offboarded, offboardedV); !errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("key destruction in degraded mode", err)
	}
	if err := p.keys.WithKey(t.Context(), offboarded, offboardedV, func([]byte) error { return nil }); err != nil {
		t.Fatal("a refused destruction left a tombstone", err)
	}
	keys, _ := promote(t, p)
	if err := openBackup(t, keys, offboarded, offboardedV, header); err != nil {
		t.Fatal("the promoted key differs", err)
	}
}

// subjectRevocationCompletesAfterResyncTest. In degraded mode a revocation
// starts at once on the primary: its subject and revision, then the fences.
// Its completion waits for the replica (finding 1, the model's rule), and
// goes through once the replica has caught up.
func TestSubjectRevocationCompletesAfterResync(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	ctx := t.Context()
	live, err := p.catalog.Register(ctx, keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.catalog.Register(ctx, offboarded, offboardedV)
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, live)
	if _, err = p.catalog.BeginRevocation(ctx, offboarded); err != nil {
		t.Fatal("the start of a revocation waited", err)
	}
	receipt(t, p.catalog, live)
	receipt(t, p.catalog, other)
	if err = p.catalog.WithSubjectKey(ctx, offboarded, func() error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal("the revocation did not close new key grants at once", err)
	}
	var count int
	if err = p.replica.db.QueryRow("SELECT count(*) FROM revocations WHERE subject=?", offboarded).Scan(&count); err != nil || count != 0 {
		t.Fatal("the start reached the replica in degraded mode", count, err)
	}
	done := false
	finish := func() error { done = true; return nil }
	if err = p.catalog.WithRevocation(within(t, 200*time.Millisecond), offboarded, []Binding{live, other}, finish); !errors.Is(err, ErrWaitsForReplica) || done {
		t.Fatal("a revocation completed in degraded mode", err)
	}
	resync(t, p)
	if err = p.catalog.WithRevocation(ctx, offboarded, []Binding{live, other}, finish); err != nil || !done {
		t.Fatal(err)
	}
	if err = p.replica.db.QueryRow("SELECT count(*) FROM revocations WHERE subject=?", offboarded).Scan(&count); err != nil || count != 1 {
		t.Fatal("the replica lacks the completed revocation", count, err)
	}
	p.same(t)
}

// resyncEndsDegradedModeTest. An outcome acknowledged in degraded mode
// reaches the replica when it returns; degraded mode then ends, and a later
// failover finds the outcome: nothing to announce.
func TestResyncEndsDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-0", Digest: digest("job")}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = p.replica.db.QueryRow("SELECT count(*) FROM outcomes WHERE id='event-0'").Scan(&count); err != nil || count != 0 {
		t.Fatal("a degraded write reached the replica at once", count, err)
	}
	resync(t, p)
	_, promoted := promote(t, p)
	if status, _, err := promoted.OutcomeStatus(t.Context(), "event-0"); err != nil || status != StatusConfirmed {
		t.Fatal("the failover lost a resynced outcome", status, err)
	}
}

// degradedOutcomeIsAnnouncedAsWindowTest, in part. An outcome acknowledged in
// degraded mode is lost with the primary: the promoted authority never
// recorded it, so a restored image that lacks it activates without a
// declared loss, and the job may run again. The promotion must announce the
// degraded period as a time window (ADR 005, item 14); that is the promotion
// command's, not built yet.
func TestDegradedOutcomeIsLostWithThePrimary(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-0", Digest: digest("job")}); err != nil {
		t.Fatal(err)
	}
	// The primary is lost before the standby returns.
	_, promoted := promote(t, p)
	ctx := t.Context()
	if status, _, err := promoted.OutcomeStatus(ctx, "event-0"); err != nil || status != StatusUnrecorded {
		t.Fatal("the degraded outcome survived the primary", status, err)
	}
	restored, err := promoted.ReserveIncarnation(ctx, b, "restore-after-failover")
	if err != nil {
		t.Fatal(err)
	}
	r := receipt(t, promoted, restored)
	ready := false
	losses, err := promoted.Activate(ctx, r, Restoration{
		Inspect: func([]Outcome) ([]string, error) { return nil, nil },
		Publish: func() error { ready = true; return nil },
	})
	if err != nil || !ready || len(losses) != 0 {
		t.Fatal("the restored image did not activate without a declaration", losses, err)
	}
	if err = promoted.RecordOutcome(ctx, restored, Outcome{ID: "event-0", Digest: digest("job again")}); err != nil {
		t.Fatal("the job did not run again", err)
	}
}
