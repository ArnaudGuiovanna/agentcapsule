//go:build linux && cgo

package restoreauthority

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

func accessID(c byte) string { return "arv_" + strings.Repeat(string(c), 32) }

func memberRecord(id string) AccessRecord {
	return AccessRecord{ID: id, Kind: authoritylog.AccessMember, Organization: "org_1", Objects: [][]string{{"prn_1"}}}
}

// An access revocation record is kept for good, with what the reconciliation
// replays: its kind, organization, objects, time and epoch. Appending it
// again changes nothing; another record under its ID is refused. Standalone,
// nothing more is waited for (ADR 006 wave 5).
func TestAccessRecordsAreKeptForGood(t *testing.T) {
	_, c := primary(t, t.TempDir())
	ctx := t.Context()
	before := time.Now().UnixMilli()
	r := memberRecord(accessID('a'))
	got, err := c.AppendAccess(ctx, r)
	if err != nil || !got.Known || !got.OnReplica || got.Degraded || got.Epoch != 1 || got.Seq != 0 {
		t.Fatal(got, err)
	}
	again, err := c.AppendAccess(ctx, r)
	if err != nil || again != got {
		t.Fatal("a repeated record", again, err)
	}
	other := r
	other.Objects = [][]string{{"prn_2"}}
	if _, err = c.AppendAccess(ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatal("another record under the same ID", err)
	}
	for _, bad := range []AccessRecord{
		{ID: "arv_1", Kind: authoritylog.AccessMember, Objects: [][]string{{"prn_1"}}},
		{ID: accessID('b'), Kind: "role", Objects: [][]string{{"prn_1"}}},
		{ID: accessID('b'), Kind: authoritylog.AccessMember},
		{ID: accessID('b'), Kind: authoritylog.AccessMember, Organization: "org\n1", Objects: [][]string{{"prn_1"}}},
	} {
		if _, err = c.AppendAccess(ctx, bad); !errors.Is(err, ErrInput) {
			t.Fatal("invalid record accepted", bad, err)
		}
	}
	records, err := c.AccessRecords(ctx)
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	kept := records[0]
	if kept.ID != r.ID || kept.Kind != r.Kind || kept.Organization != "org_1" || len(kept.Objects) != 1 || kept.Objects[0][0] != "prn_1" ||
		kept.RecordedAt < before || kept.RecordedAt > time.Now().UnixMilli() || kept.Epoch != 1 {
		t.Fatal("kept record", kept)
	}
	if _, err = c.db.Exec("DELETE FROM access_revocations"); err == nil {
		t.Fatal("a record was deleted")
	}
	if _, err = c.db.Exec("UPDATE access_revocations SET kind='team'"); err == nil {
		t.Fatal("a record was changed")
	}
	status, err := c.AccessStatus(ctx, r.ID)
	if err != nil || status != got {
		t.Fatal(status, err)
	}
	if status, err = c.AccessStatus(ctx, accessID('c')); err != nil || status.Known {
		t.Fatal("an unknown record", status, err)
	}
}

// Synchronous: the record returns once the replica holds it, and a
// promotion keeps it.
func TestAccessRecordReachesTheReplicaAndSurvivesThePromotion(t *testing.T) {
	p := replicated(t)
	everyWrite(t, p.keys, p.catalog)
	r := AccessRecord{ID: accessID('d'), Kind: authoritylog.AccessDelegatedToken, Organization: "org_1", Objects: [][]string{{"https://issuer.example", "jti-1"}}}
	got, err := p.catalog.AppendAccess(t.Context(), r)
	if err != nil || !got.Known || !got.OnReplica || got.Degraded || got.Epoch != 1 || got.Seq != committed(t, p.catalog) {
		t.Fatal(got, err)
	}
	p.same(t)
	held, err := p.replica.AccessRecords(t.Context())
	if err != nil || len(held) != 2 || held[1].ID != r.ID || held[1].Seq != got.Seq {
		t.Fatal("the replica's records", held, err)
	}
	_, promoted := promote(t, p)
	status, err := promoted.AccessStatus(t.Context(), r.ID)
	if err != nil || !status.Known || !status.OnReplica || status.Epoch != 1 || status.Seq != got.Seq {
		t.Fatal("the promoted authority lost the record", status, err)
	}
}

// Degraded mode: the record commits at once on the primary and says so;
// once the replica catches up, it is on the replica.
func TestAccessRecordContinuesInDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	r := memberRecord(accessID('e'))
	got, err := p.catalog.AppendAccess(within(t, 2*time.Second), r)
	if err != nil || !got.Known || got.OnReplica || !got.Degraded {
		t.Fatal("an access record in degraded mode", got, err)
	}
	if held, err := p.replica.AccessRecords(t.Context()); err != nil || len(held) != 0 {
		t.Fatal("the replica holds it already", held, err)
	}
	if status, err := p.catalog.AccessStatus(t.Context(), r.ID); err != nil || status.OnReplica || !status.Degraded {
		t.Fatal(status, err)
	}
	resync(t, p)
	if status, err := p.catalog.AccessStatus(t.Context(), r.ID); err != nil || !status.OnReplica || status.Degraded {
		t.Fatal("after the resync", status, err)
	}
	p.same(t)
}

// Before degraded mode begins, a record that the barrier holds is not
// committed: the caller commits nothing in PostgreSQL, and tries again.
func TestAccessRecordWithinTheDelayFailsUncommitted(t *testing.T) {
	p := replicated(t)
	useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	p.link.set(true)
	if err = p.catalog.RecordOutcome(within(t, 100*time.Millisecond), b, Outcome{ID: "event-probe", Digest: digest("probe")}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	r := memberRecord(accessID('f'))
	if _, err = p.catalog.AppendAccess(within(t, 200*time.Millisecond), r); !errors.Is(err, ErrUnavailable) {
		t.Fatal("an access record within the delay", err)
	}
	p.link.set(false)
	if status, err := p.catalog.AccessStatus(t.Context(), r.ID); err != nil || status.Known {
		t.Fatal("the record was committed", status, err)
	}
}

// docs/adr/006-authority-service.md §4: the standby is upgraded before the
// primary when a release adds a statement. A replica of the previous
// release does not know the access record's statement: it refuses the
// first record, and that refusal stops the primary. The record stays
// committed on the primary, not confirmed. Once the standby runs the new
// release, the primary resends it and goes on.
func TestStandbyWithoutTheAccessStatementRefusesTheFirstRecord(t *testing.T) {
	p := replicated(t)
	p.replica.knows = stmtRerun // the release before wave 5
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal("the previous release's statements replicate", err)
	}
	r := memberRecord(accessID('9'))
	got, err := p.catalog.AppendAccess(within(t, 2*time.Second), r)
	if err != nil || !got.Known || got.OnReplica || got.Degraded {
		t.Fatal("a record the standby refused", got, err)
	}
	if held, err := p.replica.AccessRecords(t.Context()); err != nil || len(held) != 0 || applied(t, p) != got.Seq-1 {
		t.Fatal("the old standby applied it", held, err)
	}
	if mode, _ := p.catalog.ReplicationMode(); mode != ModeWaiting {
		t.Fatal("the refusal did not stop the primary", mode)
	}
	if err = p.catalog.RecordOutcome(within(t, 200*time.Millisecond), b, Outcome{ID: "event-2", Digest: digest("two")}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("the primary went on behind the old standby", err)
	}
	// The standby runs the new release.
	p.replica.knows = 0
	eventually(t, "the resend", func() bool {
		status, err := p.catalog.AccessStatus(t.Context(), r.ID)
		return err == nil && status.OnReplica
	})
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-2", Digest: digest("two")}); err != nil {
		t.Fatal(err)
	}
	p.same(t)
}

// ADR 005 item 8: the outcome record keeps the event ID, and a declared
// loss names it.
func TestOutcomeRecordKeepsTheEventID(t *testing.T) {
	p := replicated(t)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	outcome := Outcome{ID: "outcome-1", Digest: sha256.Sum256([]byte("one")), Event: "mbx_1"}
	if err = p.catalog.RecordOutcome(ctx, b, outcome); err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.RecordOutcome(ctx, b, outcome); err != nil {
		t.Fatal("the same outcome again", err)
	}
	moved := outcome
	moved.Event = "mbx_2"
	if err = p.catalog.RecordOutcome(ctx, b, moved); !errors.Is(err, ErrConflict) {
		t.Fatal("another event for the same outcome", err)
	}
	next, err := p.catalog.ReserveIncarnation(ctx, b, "restore-1")
	if err != nil {
		t.Fatal(err)
	}
	r := receipt(t, p.catalog, next)
	losses, err := p.catalog.Activate(ctx, r, Restoration{Inspect: everythingMissing, Publish: func() error { return nil }})
	if err != nil || len(losses) != 1 || losses[0].ID != outcome.ID || losses[0].Event != "mbx_1" {
		t.Fatal("the declared loss", losses, err)
	}
	p.same(t)
	_, promoted := promote(t, p)
	kept, err := promoted.Losses(ctx, b.Store)
	if err != nil || len(kept) != 1 || kept[0].Event != "mbx_1" {
		t.Fatal("the promoted authority's loss", kept, err)
	}
}

// A version 3 catalogue records no access revocation until it is upgraded,
// and the authority service refuses it (CheckSchema). A version 3 replica is
// upgraded when it is opened, and then takes the new statements.
func TestVersionThreeUpgradesForAccessRecords(t *testing.T) {
	p := replicated(t)
	b := everyWrite(t, p.keys, p.catalog)
	if _, err := p.catalog.db.Exec("DROP TABLE outcome_events; DROP TABLE access_revocations; PRAGMA user_version=3"); err != nil {
		t.Fatal(err)
	}
	if err := p.catalog.CheckSchema(t.Context()); !errors.Is(err, ErrUpgradeRequired) {
		t.Fatal("a version 3 catalogue passed the check", err)
	}
	if _, err := p.catalog.AppendAccess(t.Context(), memberRecord(accessID('8'))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a version 3 catalogue recorded an access revocation", err)
	}
	// Outcomes still record, without their event.
	if err := p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-3", Digest: digest("three"), Event: "mbx_3"}); err != nil {
		t.Fatal(err)
	}
	// The standby first: its replica, as the previous release left it, is
	// opened by this one.
	root := filepath.Join(p.dir, "replica")
	p.replica.Close()
	db, err := openSQLite(filepath.Join(root, "replica.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DROP TABLE outcome_events; DROP TABLE access_revocations; PRAGMA user_version=3"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if p.replica, err = OpenReplica(t.Context(), root, p.catalog.Identity(), p.keys.Identity()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.replica.Close() })
	p.link.point(p.replica)
	// Then the primary.
	upgraded, err := Initialize(t.Context(), p.catalog.root, p.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	upgraded.Close()
	if err = p.catalog.CheckSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := p.catalog.AppendAccess(t.Context(), memberRecord(accessID('8')))
	if err != nil || !got.OnReplica {
		t.Fatal(got, err)
	}
	if held, err := p.replica.AccessRecords(t.Context()); err != nil || len(held) != 1 {
		t.Fatal(held, err)
	}
	p.same(t)
}
