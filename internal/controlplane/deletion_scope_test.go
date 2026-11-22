package controlplane

import (
	"slices"
	"testing"
)

// Since the v0.1.0 audit (PERF-3B), a deletion's census is its subject's
// scope: the agent's store and the stores that share a request with it
// (requestDeletion, agentScope). The traces frozen before then record every
// store's fence of a deletion. The replays bind such a fence to its store's
// target when the store is in the scope; one outside it has no target, and
// its fence, which the replay still makes in SQLite, is not needed: no event
// PostgreSQL addresses to that store can name the agent.

// inDeletionScope reports whether store shares a request with agent, or is
// agent itself.
func inDeletionScope(t *testing.T, s *Store, agent, store string) bool {
	t.Helper()
	if store == agent {
		return true
	}
	var shared bool
	if err := s.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM agent_requests WHERE (sender_agent_id=$1 AND recipient_agent_id=$2)
        OR (sender_agent_id=$2 AND recipient_agent_id=$1))`, agent, store).Scan(&shared); err != nil {
		t.Fatal(err)
	}
	return shared
}

// recordDeletionFence records store's fence of agent's deletion when store
// is in its scope; a fence outside it records nothing.
func recordDeletionFence(t *testing.T, s *Store, agent, store string) error {
	t.Helper()
	if !inDeletionScope(t, s, agent, store) {
		return nil
	}
	return s.recordFence(t.Context(), agent, store)
}

// scopedAcks keeps, of a model's acknowledgments of agent's deletion, those
// of the stores in its scope.
func scopedAcks(t *testing.T, s *Store, agent string, acks []any) []any {
	t.Helper()
	return slices.DeleteFunc(slices.Clone(acks), func(store any) bool { return !inDeletionScope(t, s, agent, store.(string)) })
}

// The census of a deletion is its subject's scope, whatever the platform
// holds besides: a store that shares no request with the agent, of its
// organization or another, gets no target and no fence.
func TestDeletionCensusIsTheSubjectsScope(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	incoming(t, s) // c asks a
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(t.Context(), "SELECT store_agent_id FROM deletion_targets WHERE agent_id='a' ORDER BY store_agent_id")
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
	if !slices.Equal(targets, []string{"a", "c"}) {
		t.Fatal("the census of a's deletion", targets)
	}
	scopes, err := s.RevocationScopes(t.Context(), []string{"agent/a"})
	if err != nil || !slices.Equal(scopes[0].Stores, targets) {
		t.Fatal("the census is not the subject's scope", scopes, err)
	}
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	if err = s.ReconcileRevocation(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, s, "a", "DELETING")
}
