//go:build linux && cgo

package restoreauthority

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// The standby's last contact and the announcement after a failover (ADR 005,
// "What the code must do", item 14; ADR 006 wave 7).

// promoteAt promotes p's replica as the failover at failover would, with the
// default degraded delay, and opens the promoted catalogue.
func promoteAt(t *testing.T, p *pair, failover time.Time) (*keyauthority.Files, *Catalog, Promotion) {
	t.Helper()
	restoreRoot, keyRoot := filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys")
	result, err := PromoteWith(t.Context(), filepath.Join(p.dir, "replica"), restoreRoot, keyRoot, p.unlock,
		PromoteOptions{Now: func() time.Time { return failover }})
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

func lastContactOf(t *testing.T, p *pair) time.Time {
	t.Helper()
	contact, err := p.replica.LastContact(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return contact
}

// The replica writes the arrival of each request it answers as its last
// contact, at most once a second, before it answers; a refused request, or
// one to a promoted replica, changes nothing.
func TestReplicaRecordsItsLastContact(t *testing.T) {
	p := replicated(t)
	ctx := t.Context()
	if contact := lastContactOf(t, p); !contact.IsZero() {
		t.Fatal("a replica the primary never reached has a last contact", contact)
	}
	start := time.Now()
	if _, err := p.catalog.Register(ctx, "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	first := lastContactOf(t, p)
	if first.Before(start.Truncate(time.Millisecond)) || first.After(time.Now()) {
		t.Fatal("the first answer did not write its contact", start, first)
	}
	k := &clock{t: first.Add(500 * time.Millisecond)}
	p.replica.now = k.now
	ask := authoritylog.Request{RestoreAuthority: p.catalog.Identity(), KeyAuthority: p.keys.Identity(), Epoch: 1}
	if _, err := p.replica.Sync(ctx, ask); err != nil {
		t.Fatal(err)
	}
	if got := lastContactOf(t, p); !got.Equal(first) {
		t.Fatal("a contact within the second was written", got)
	}
	k.advance(time.Second)
	if _, err := p.replica.Sync(ctx, ask); err != nil {
		t.Fatal(err)
	}
	second := lastContactOf(t, p)
	if !second.Equal(k.now().Truncate(time.Millisecond)) {
		t.Fatal("the contact after a second was not written", second, k.now())
	}
	k.advance(time.Minute)
	other := ask
	other.Epoch = 2
	var refusal *authoritylog.Refusal
	if _, err := p.replica.Sync(ctx, other); !errors.As(err, &refusal) {
		t.Fatal("another epoch was not refused", err)
	}
	if got := lastContactOf(t, p); !got.Equal(second) {
		t.Fatal("a refused request is a contact", got)
	}
}

// A primary that writes nothing still reaches its replica every heartbeat,
// so the standby's last contact stays recent; and with the standby gone, an
// idle primary enters degraded mode after the delay, without an operation.
func TestKeepContactReachesAnIdleReplica(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	r := &clock{t: lastContactOf(t, p).Add(time.Hour)}
	p.replica.now = r.now
	p.catalog.KeepContact(20 * time.Millisecond)
	eventually(t, "a heartbeat's contact", func() bool { return lastContactOf(t, p).Equal(r.now().Truncate(time.Millisecond)) })
	p.link.set(true)
	eventually(t, "a heartbeat that fails", func() bool {
		p.catalog.repl.mu.Lock()
		defer p.catalog.repl.mu.Unlock()
		return !p.catalog.repl.failing.IsZero()
	})
	k.advance(authoritylog.DefaultDegradedAfter)
	eventually(t, "degraded mode on an idle primary", func() bool { return isDegraded(p.catalog) })
	if HeartbeatEvery(authoritylog.DefaultDegradedAfter) != 5*time.Second || HeartbeatEvery(time.Second) != 500*time.Millisecond {
		t.Fatal("the heartbeat is not a sixth of the delay")
	}
}

func blanketOf(t *testing.T, c *Catalog, id string) AccessRecord {
	t.Helper()
	records, err := c.AccessRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.ID == id {
			return r
		}
	}
	t.Fatal("no blanket record", id, records)
	return AccessRecord{}
}

// Beyond the degraded delay after the last contact, the promotion assumes a
// degraded period ran: it writes the blanket record into the promoted
// catalogue, which announces the window from the last contact to the
// failover. A repeated promotion keeps that decision.
func TestPromotionAnnouncesADegradedPeriodBeyondTheDelay(t *testing.T) {
	p := replicated(t)
	if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	contact := lastContactOf(t, p)
	failover := contact.Add(authoritylog.DefaultDegradedAfter)
	_, promoted, result := promoteAt(t, p, failover)
	a := result.Announcement
	if !a.Degraded || a.Epoch != 2 || !a.Failover.Equal(failover) || !a.LastContact.Equal(contact) ||
		a.DegradedAfter != authoritylog.DefaultDegradedAfter || a.Blanket != authoritylog.BlanketID(p.catalog.Identity(), 2) {
		t.Fatal("the announcement", a)
	}
	record := blanketOf(t, promoted, a.Blanket)
	b, ok := authoritylog.ParseBlanket(record.Objects)
	if record.Kind != authoritylog.AccessBlanket || record.Organization != "" || record.Epoch != 2 || record.Seq != 0 ||
		!ok || !b.IssuedBefore.Equal(failover) || !b.WindowFrom.Equal(contact) {
		t.Fatal("the blanket record", record, b)
	}
	if got, err := promoted.Announcement(t.Context()); err != nil || !got.Degraded || got.Blanket != a.Blanket ||
		!got.Failover.Equal(failover) || !got.LastContact.Equal(contact) || got.Epoch != 2 {
		t.Fatal("the promoted catalogue's announcement", got, err)
	}
	receipt, err := promoted.AccessStatus(t.Context(), a.Blanket)
	if err != nil || !receipt.Known || !receipt.OnReplica {
		t.Fatal("the blanket record needs nothing more", receipt, err)
	}
	// Repeated later: the same decision, and the same record.
	again, err := PromoteWith(t.Context(), filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "promoted-restore"),
		filepath.Join(p.dir, "promoted-keys"), p.unlock, PromoteOptions{Now: func() time.Time { return failover.Add(time.Hour) }})
	if err != nil || again.Announcement != a {
		t.Fatal("a repeated promotion", again.Announcement, err)
	}
}

// Within the delay no degraded period can have run: nothing is announced,
// and no bearer token is revoked.
func TestPromotionWithinTheDelayAnnouncesNoWindow(t *testing.T) {
	p := replicated(t)
	if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	contact := lastContactOf(t, p)
	_, promoted, result := promoteAt(t, p, contact.Add(authoritylog.DefaultDegradedAfter-time.Millisecond))
	if a := result.Announcement; a.Degraded || a.Blanket != "" || !a.LastContact.Equal(contact) {
		t.Fatal("the announcement", a)
	}
	records, err := promoted.AccessRecords(t.Context())
	if err != nil || len(records) != 0 {
		t.Fatal("a record without a degraded period", records, err)
	}
	if got, err := promoted.Announcement(t.Context()); err != nil || got.Degraded || got.Epoch != 2 {
		t.Fatal("the promoted catalogue's announcement", got, err)
	}
}

// A replica its primary never reached has no last contact: that primary
// never entered degraded mode. A failover that precedes the last contact
// (the standby's clock went back) cannot be compared: a degraded period is
// assumed, from the failover.
func TestPromotionWithoutAComparableContact(t *testing.T) {
	never := replicated(t)
	_, _, result := promoteAt(t, never, time.Now().Add(24*time.Hour))
	if a := result.Announcement; a.Degraded || !a.LastContact.IsZero() {
		t.Fatal("a replica never reached", a)
	}
	back := replicated(t)
	if _, err := back.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	failover := lastContactOf(t, back).Add(-time.Hour)
	_, promoted, result := promoteAt(t, back, failover)
	if a := result.Announcement; !a.Degraded {
		t.Fatal("a clock that went back", a)
	}
	b, ok := authoritylog.ParseBlanket(blanketOf(t, promoted, result.Announcement.Blanket).Objects)
	if !ok || !b.WindowFrom.Equal(failover) || !b.IssuedBefore.Equal(failover) {
		t.Fatal("the window of a clock that went back", b, ok)
	}
}

// The reconciliation reads the records, the subjects and the stores page by
// page, each row once, in order.
func TestReconciliationReadsPageByPage(t *testing.T) {
	_, c := primary(t, t.TempDir())
	ctx := t.Context()
	var ids []string
	for i := range 5 {
		r := AccessRecord{ID: "arv_" + strings.Repeat(string("abcde"[i]), 32), Kind: authoritylog.AccessMember, Organization: "org_1",
			Objects: [][]string{{"prn_" + string("abcde"[i])}}}
		if _, err := c.AppendAccess(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
		if _, err := c.BeginRevocation(ctx, "agent/"+string("abcde"[i])); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Register(ctx, "store-"+string("abcde"[i]), "volume-"+string("abcde"[i])); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for after := int64(0); ; {
		page, next, err := c.ExportAccess(ctx, after, 2)
		if err != nil || len(page) > 2 {
			t.Fatal(page, err)
		}
		for _, r := range page {
			if !r.OnReplica || r.Degraded || r.Epoch != 1 || r.RecordedAt == 0 || len(r.Objects) != 1 {
				t.Fatal("an exported record", r)
			}
			got = append(got, r.ID)
		}
		if next == 0 {
			break
		}
		after = next
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatal("the records, page by page", got)
	}
	var subjects []string
	for after := int64(0); ; {
		page, next, err := c.ExportSubjects(ctx, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range page {
			subjects = append(subjects, s.Subject)
		}
		if next == 0 {
			break
		}
		after = next
	}
	if strings.Join(subjects, ",") != "agent/a,agent/b,agent/c,agent/d,agent/e" {
		t.Fatal("the subjects", subjects)
	}
	stores, next, err := c.ExportStores(ctx, 0, 0)
	if err != nil || next != 0 || len(stores) != 5 || stores[0] != (Store{ID: "store-a", Volume: "volume-a", Incarnation: 1}) {
		t.Fatal("the stores", stores, next, err)
	}
	if _, _, err = c.ExportStores(ctx, -1, 0); !errors.Is(err, ErrInput) {
		t.Fatal("a negative cursor", err)
	}
}
