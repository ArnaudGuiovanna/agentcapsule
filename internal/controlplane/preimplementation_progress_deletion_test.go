package controlplane

import (
	"errors"
	"fmt"
	"testing"
)

// P3's deletion of store 0 binds to the deletion of agent a. The case
// deleted-destination-rejects-new-work has no request in flight, so the
// reciprocal binding of the other cases does not get in the way: requestDelete
// is the owner's deletion request, finishDelete the fence of agent/a in both
// stores and the tombstone's commit.

func (a *p3Replay) deletionStep(t *testing.T, op protocolAction) (bool, error) {
	t.Helper()
	switch op.Name {
	case "requestDelete":
		return true, a.s.RequestDeletion(t.Context(), a.principals[0].ID, p1Agent(0))
	case "finishDelete":
		for store := range 2 {
			if err := a.local.boots[store].client.Fence(t.Context(), "agent/"+p1Agent(0)); err != nil {
				return true, err
			}
			if err := a.s.recordFence(t.Context(), p1Agent(0), p1Agent(store)); err != nil {
				return true, err
			}
		}
		return true, a.s.commitRevocation(t.Context(), p1Agent(0))
	}
	return false, nil
}

// compareDeletion: P3's deletionPending is agent a QUIESCING, deleted its
// tombstone (DELETING, then DELETED).
func (a *p3Replay) compareDeletion(t *testing.T, w p3Observation, index int) {
	t.Helper()
	var phase string
	if err := a.s.pool.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id=$1", p1Agent(0)).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	got := []bool{phase == "QUIESCING", phase == "DELETING" || phase == "DELETED"}
	if want := []bool{w.Deletion.Pending, w.Deletion.Complete}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("P3 state %d deletion: agent a is %s; model pending, complete = %v", index, phase, want)
	}
}

// refusedArrival: no new request from a deleted agent is accepted. Its VM
// lost its authority with the deletion (ErrPlacement), though it still runs.
func (a *p3Replay) refusedArrival(t *testing.T, op protocolAction, err error) {
	t.Helper()
	if p1Int(op.Args[0]) != 0 || !errors.Is(err, ErrPlacement) {
		t.Fatal("deleted agent's request was not refused for its placement:", err)
	}
	if n := count(t, a.s, "agent_requests"); n != 0 {
		t.Fatal("refused arrival left a request:", n)
	}
}
