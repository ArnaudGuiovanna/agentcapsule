package controlplane

import (
	"slices"
	"testing"
)

// The census of a deletion (PERF-3B) and the scope of its subject (FIX-1)
// agree after the retention of finished records: both read the agent's kept
// requests (agentScope). A party that only a purged request joined to the
// agent is in neither; the closure's request/<id>, whose stores are recorded
// with it, still names both parties.
func TestDeletionCensusFollowsTheScopeAfterTheRetention(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	ctx := t.Context()
	if _, err := s.pool.Exec(ctx, `INSERT INTO agent_placements(agent_id,host_id) VALUES('a','local'),('b','local')`); err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), "a", "b")
	m.SetHandler(recordDelivery)
	r, err := s.Submit(ctx, "a", "closed", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(ctx, "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRequestClosure(ctx, r.RequestID, m); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE agent_mailboxes SET delivery_state='DELIVERED' WHERE kind='status' AND ref_id=$1`, r.RequestID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PurgeFinished(ctx, "local", pastRetention(), MinFinishedRetention, 100); err != nil || n.Requests != 1 {
		t.Fatal("the purge past the retention", n, err)
	}
	if err = s.RequestDeletion(ctx, "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(ctx, "SELECT store_agent_id FROM deletion_targets WHERE agent_id='a' ORDER BY store_agent_id")
	if err != nil {
		t.Fatal(err)
	}
	var targets []string
	for rows.Next() {
		var target string
		if err = rows.Scan(&target); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got := scopeOf(t, s, "agent/a"); !slices.Equal(targets, []string{"a"}) || !slices.Equal(got, targets) {
		t.Fatal("the census of a's deletion and its subject's scope", targets, got)
	}
	if got := scopeOf(t, s, "request/"+r.RequestID); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatal("the closed request's scope after a's deletion", got)
	}
}
