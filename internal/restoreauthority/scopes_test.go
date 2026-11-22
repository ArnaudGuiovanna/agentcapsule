//go:build linux && cgo

package restoreauthority

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// beginScoped begins n subjects of the form prefix<i> in store's scope.
func beginScoped(t testing.TB, c *Catalog, prefix string, n int, stores ...string) []string {
	t.Helper()
	var subjects []string
	for i := range n {
		subjects = append(subjects, fmt.Sprintf("%s%06d", prefix, i))
	}
	for chunk := range slices.Chunk(subjects, MaxScopes) {
		scopes := make([]Scope, len(chunk))
		for i, s := range chunk {
			scopes[i] = Scope{Subject: s, Stores: stores}
		}
		if err := c.BeginRevocations(t.Context(), scopes); err != nil {
			t.Fatal(err)
		}
	}
	return subjects
}

// A store is fenced only with the subjects of its own scope: another
// organization's revocations, however many, never reach its receipt (S-01).
func TestScanNamesOnlyTheStoresScope(t *testing.T) {
	c, a := fixture(t)
	if _, err := c.Register(t.Context(), "store-b", "volume-b"); err != nil {
		t.Fatal(err)
	}
	beginScoped(t, c, "event/other-organization-", 1500, "store-b")
	own := beginScoped(t, c, "request/own-", 2, "store-a", "store-b")
	if _, err := c.BeginRevocation(t.Context(), "agent/unknown-scope"); err != nil {
		t.Fatal(err)
	}
	r, err := c.Scan(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(own), "agent/unknown-scope")
	slices.Sort(want)
	if !slices.Equal(r.Subjects, want) || r.More || r.Base != 0 {
		t.Fatalf("receipt of store-a: %v more=%v base=%d", r.Subjects, r.More, r.Base)
	}
	if err = c.RecordVerifiedFence(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	// An ACK of store-a covers the other organization's subjects only by
	// being outside their scope: store-b still owes its fences.
	for _, subject := range []string{"event/other-organization-000007", own[0]} {
		ack, _, err := c.SubjectBarrier(t.Context(), a, subject)
		if err != nil || !ack {
			t.Fatal(subject, ack, err)
		}
	}
	b, err := c.Lookup(t.Context(), "store-b")
	if err != nil {
		t.Fatal(err)
	}
	if ack, _, err := c.SubjectBarrier(t.Context(), b, "event/other-organization-000007"); err != nil || ack {
		t.Fatal("store-b acknowledged a fence it never received", ack, err)
	}
}

// A boot fences what the store has not acknowledged yet, nothing more: its
// cost does not grow with what it already holds.
func TestScanReturnsOnlyWhatTheStoreLacks(t *testing.T) {
	c, a := fixture(t)
	beginScoped(t, c, "event/old-", 100, "store-a")
	first := receipt(t, c, a)
	if len(first.Subjects) != 100 {
		t.Fatal(len(first.Subjects))
	}
	beginScoped(t, c, "event/new-", 1, "store-a")
	next, err := c.Scan(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(next.Subjects, []string{"event/new-000000"}) || next.Base != first.Revision+1 {
		t.Fatalf("second receipt: %v base=%d after %d", next.Subjects, next.Base, first.Revision)
	}
	if err = c.RecordVerifiedFence(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	empty, err := c.Scan(t.Context(), a)
	if err != nil || len(empty.Subjects) != 0 {
		t.Fatal(empty.Subjects, err)
	}
	if err = c.WithCurrentFences(t.Context(), next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A new incarnation starts again from its whole scope.
	restored, err := c.ReserveIncarnation(t.Context(), a, "restore")
	if err != nil {
		t.Fatal(err)
	}
	full, err := c.Scan(t.Context(), restored)
	if err != nil || len(full.Subjects) != 101 || full.Base != 0 {
		t.Fatal(len(full.Subjects), full.Base, err)
	}
	if err = c.RecordVerifiedFence(t.Context(), full); err != nil {
		t.Fatal(err)
	}
}

// A receipt of an earlier incarnation, or with a changed Base, is refused.
func TestReceiptFromAnUnacknowledgedBaseIsStale(t *testing.T) {
	c, a := fixture(t)
	beginScoped(t, c, "event/x-", 3, "store-a")
	r := receipt(t, c, a)
	beginScoped(t, c, "event/y-", 1, "store-a")
	next, err := c.Scan(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := c.ReserveIncarnation(t.Context(), a, "restore")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Scan(t.Context(), restored); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []Receipt{r, next} {
		if err = c.RecordVerifiedFence(t.Context(), stale); !errors.Is(err, ErrStale) {
			t.Fatal(err)
		}
	}
	// A forged Base breaks the MAC.
	forged := next
	forged.Base = 0
	if err = c.RecordVerifiedFence(t.Context(), forged); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
}

// The largest scope is fenced in pages: each receipt stays far below a frame.
func TestScanPagesALargeScope(t *testing.T) {
	c, a := fixture(t)
	beginScoped(t, c, "event/many-", ScanPage+10, "store-a")
	var receipts []Receipt
	for range 3 {
		r, err := c.Scan(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.RecordVerifiedFence(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, r)
		if !r.More {
			break
		}
	}
	if len(receipts) != 2 || len(receipts[0].Subjects) != ScanPage || len(receipts[1].Subjects) != 10 || !receipts[0].More {
		t.Fatalf("pages: %d", len(receipts))
	}
	if err := c.WithCurrentFences(t.Context(), receipts[0], func() error { t.Error("first page published"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if err := c.WithCurrentFences(t.Context(), receipts[1], func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// A revocation outside a store's scope no longer makes its boot stale; one in
// its scope, or of unknown scope, still does (activationRechecksNewRevocation).
func TestOnlyARevocationInTheScopeMakesABootStale(t *testing.T) {
	c, a := fixture(t)
	if _, err := c.Register(t.Context(), "store-b", "volume-b"); err != nil {
		t.Fatal(err)
	}
	r := receipt(t, c, a)
	beginScoped(t, c, "event/elsewhere-", 5, "store-b")
	if err := c.WithCurrentFences(t.Context(), r, func() error { return nil }); err != nil {
		t.Fatal("unrelated revocation made the boot stale", err)
	}
	beginScoped(t, c, "event/here-", 1, "store-a")
	if err := c.WithCurrentFences(t.Context(), r, func() error { t.Error("boot missed its revocation"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	r = receipt(t, c, a)
	if _, err := c.BeginRevocation(t.Context(), "agent/everywhere"); err != nil {
		t.Fatal(err)
	}
	if err := c.WithCurrentFences(t.Context(), r, func() error { t.Error("boot missed a revocation of unknown scope"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
}

// A store added to a subject's scope later owes its fence: the addition
// takes a revision above what the store acknowledged.
func TestScopeAdditionTakesANewRevision(t *testing.T) {
	c, a := fixture(t)
	b, err := c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	beginScoped(t, c, "agent/x", 1, "store-a")
	rb := receipt(t, c, b)
	if len(rb.Subjects) != 0 {
		t.Fatal(rb.Subjects)
	}
	if known, err := c.KnownScopes(t.Context(), []Scope{{Subject: "agent/x000000", Stores: []string{"store-a", "store-b"}}}); err != nil || known {
		t.Fatal(known, err)
	}
	beginScoped(t, c, "agent/x", 1, "store-a", "store-b")
	if ack, _, err := c.SubjectBarrier(t.Context(), b, "agent/x000000"); err != nil || ack {
		t.Fatal("added store inherited an acknowledgment", ack, err)
	}
	if err = c.WithCurrentFences(t.Context(), rb, func() error { t.Error("boot missed its addition"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	next, err := c.Scan(t.Context(), b)
	if err != nil || !slices.Equal(next.Subjects, []string{"agent/x000000"}) {
		t.Fatal(next.Subjects, err)
	}
	if known, err := c.KnownScopes(t.Context(), []Scope{{Subject: "agent/x000000", Stores: []string{"store-b"}}}); err != nil || !known {
		t.Fatal(known, err)
	}
	if _, err = c.Lookup(t.Context(), a.Store); err != nil {
		t.Fatal(err)
	}
}

// A worker of the previous protocol begins PostgreSQL's whole catalogue at
// each boot, without scopes: a subject already begun in its scope stays
// there, and no other store receives it.
func TestBeginWithoutScopeKeepsAKnownScope(t *testing.T) {
	c, a := fixture(t)
	b, err := c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	subject := beginScoped(t, c, "event/a-only-", 1, "store-a")[0]
	if _, err = c.BeginRevocation(t.Context(), subject); err != nil {
		t.Fatal(err)
	}
	if r, err := c.Scan(t.Context(), b); err != nil || len(r.Subjects) != 0 {
		t.Fatal("a known subject was widened to every store", r.Subjects, err)
	}
	if r, err := c.Scan(t.Context(), a); err != nil || !slices.Equal(r.Subjects, []string{subject}) {
		t.Fatal(r.Subjects, err)
	}
}

// Subjects begun before schema version 5 have no scope: they stay in every
// store's, as before the upgrade.
func TestSubjectsBeforeTheUpgradeAreInEveryScope(t *testing.T) {
	c, a := fixture(t)
	if _, err := c.Register(t.Context(), "store-b", "volume-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec("DROP TABLE revocation_scopes; PRAGMA user_version=4"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BeginRevocation(t.Context(), "agent/legacy"); err != nil {
		t.Fatal(err)
	}
	root := c.root
	c.Close()
	upgraded, err := Initialize(t.Context(), root, testKeyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	beginScoped(t, upgraded, "event/b-only-", 1, "store-b")
	ra, err := upgraded.Scan(t.Context(), a)
	if err != nil || !slices.Equal(ra.Subjects, []string{"agent/legacy"}) {
		t.Fatal(ra.Subjects, err)
	}
	b, err := upgraded.Lookup(t.Context(), "store-b")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := upgraded.Scan(t.Context(), b)
	if err != nil || !slices.Equal(rb.Subjects, []string{"agent/legacy", "event/b-only-000000"}) {
		t.Fatal(rb.Subjects, err)
	}
	if ack, _, err := upgraded.SubjectBarrier(t.Context(), a, "agent/legacy"); err != nil || ack {
		t.Fatal(ack, err)
	}
}

// One begin of many subjects is one transaction and one revision each.
func TestBeginRevocationsIsOneOperation(t *testing.T) {
	c, a := fixture(t)
	var before uint64
	if err := c.db.QueryRow("SELECT revision FROM authority").Scan(&before); err != nil {
		t.Fatal(err)
	}
	subjects := beginScoped(t, c, "event/batch-", 50, "store-a")
	var after uint64
	if err := c.db.QueryRow("SELECT revision FROM authority").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after-before != 50 {
		t.Fatal(after - before)
	}
	// Repeating it writes nothing.
	beginScoped(t, c, "event/batch-", 50, "store-a")
	var again uint64
	if err := c.db.QueryRow("SELECT revision FROM authority").Scan(&again); err != nil || again != after {
		t.Fatal(again, err)
	}
	if r, err := c.Scan(t.Context(), a); err != nil || !slices.Equal(r.Subjects, subjects) {
		t.Fatal(err)
	}
	for _, bad := range [][]Scope{nil, {{Subject: ""}}, {{Subject: "x", Stores: []string{""}}}} {
		if err := c.BeginRevocations(t.Context(), bad); !errors.Is(err, ErrInput) {
			t.Fatal(bad, err)
		}
	}
}
