package controlplane

import (
	"context"
	"testing"
	"time"
)

// The feed never skips an event whose transaction commits after a later
// event's (finding L-03). Until v0.1.0 a page read while the first
// transaction was open moved its cursor past the second event, and the
// first, stamped earlier, then committed behind it: no page ever gave it.
func TestAuditFeedNeverSkipsALateCommit(t *testing.T) {
	l, c, owner := agentLab(t)
	createTenantAgent(t, c, owner, "audited")
	// A consumer reads to the end of the trail, one event a page.
	walk := func(cursor string) ([]string, string) {
		t.Helper()
		var seen []string
		for range 200 {
			page, err := l.a.ListAudit(t.Context(), owner, cursor, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) == 0 {
				return seen, cursor
			}
			seen, cursor = append(seen, page.Items[0].ID), page.Next
		}
		t.Fatal("the trail does not end")
		return nil, ""
	}
	_, cursor := walk("")
	insert := `INSERT INTO application_audit(id,tenant_id,actor,target,action) VALUES($1,$2,$3,'late','application.registered')`
	first, second := newID("audit"), newID("audit")
	// The first transaction stamps its event and stays open; the second
	// stamps after it and commits.
	late, err := l.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(late)
	if _, err = late.Exec(t.Context(), insert, first, owner.TenantID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.pool.Exec(t.Context(), insert, second, owner.TenantID, owner.ID); err != nil {
		t.Fatal(err)
	}
	// While the first is open, no page is read past it.
	short, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	page, err := l.a.ListAudit(short, owner, cursor, 1)
	cancel()
	if err == nil {
		t.Fatal("a page was read while an earlier audited transaction was open:", page.Items)
	}
	// It commits while the consumer waits for its next page: the consumer
	// reads both events, in the order they were stamped.
	committed := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		committed <- late.Commit(context.Background())
	}()
	seen, _ := walk(cursor)
	if err = <-committed; err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != first || seen[1] != second {
		t.Fatal("the feed skipped or reordered the late commit:", seen, "want", first, second)
	}
}
