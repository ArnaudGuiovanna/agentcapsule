package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
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

// p3ThreeAgents is the case whose other work needs a third agent.
const p3ThreeAgents = "delete-running-agent-preserves-other-work"

// delete-running-agent-preserves-other-work (scenario7Test of
// service_progress_test.qnt). Agent a is deleted while b executes a's
// request 0 and b's request 1 waits; request 1 is unaffected. The reciprocal
// binding of the other cases would have a execute request 1, so here c does:
// request 0 is a to b, request 1 b to c. P3's store 0 is a, its store 1 b.
//
// Go closes request 0 at the deletion's tombstone, not by a closure of its
// own before it: P3's closeDeleted, fence, commitClose, finishDelete,
// cancelNotification and retireNotification are one ReconcileRevocation,
// whose fence of agent/a in every store (a, b and c) covers the request. A
// deleted sender is sent no notice: none is left to cancel.
func TestDeletionOfARunningAgentPreservesOtherWork(t *testing.T) {
	a := newP3Replay(t, p3ThreeAgents)
	submit := func(from, to int) (string, string) {
		t.Helper()
		a.serial++
		r, err := a.transit.SubmitFromVM(t.Context(), a.local.callers[from], fmt.Sprintf("progress-%d", a.serial), capsuleprotocol.Submission{
			RecipientAgentID: p1Agent(to), MandateID: "mandate-" + p1Agent(from), ExpiresAt: time.Now().Add(time.Hour),
			Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "progress request"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return r.RequestID, mailboxFor(t, a.s, r.RequestID, "request")
	}
	deliver := func(mailbox string) DeliveryAttempt {
		t.Helper()
		r, err := a.claim(t, mailbox)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.begin(t, r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// arrive(0,false), admit(0): b's writer applies request 0 and hangs.
	first, firstMailbox := submit(0, 1)
	held := deliver(firstMailbox)
	// arrive(1,true): b asks c.
	second, secondMailbox := submit(1, 2)
	// requestDelete.
	if err := a.s.RequestDeletion(t.Context(), a.principals[0].ID, "a"); err != nil {
		t.Fatal(err)
	}
	// The deletion's barrier waits while request 0 executes in b's store.
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	err := a.s.ReconcileRevocation(ctx, "a", p3Fences{a})
	cancel()
	if err == nil {
		t.Fatal("the deletion fenced b's store under request 0's open writer")
	}
	if n := a.sqliteCount(t, 1, "capsule_fences", "subject", "agent/a"); n != 0 {
		t.Fatal("b's store took the fence under the open writer:", n)
	}
	// closeDeleted(0), releaseExecution(0): the hung execution is
	// neutralized, its writer rolled back.
	a.local.stopLocal(t, 1)
	a.local.boots[1] = a.local.launchLocal(t, 1, false)
	// fence(0,0), fence(0,1), commitClose(0), finishDelete,
	// cancelNotification(0), retireNotification(0).
	if err = a.s.ReconcileRevocation(t.Context(), "a", p3Fences{a}); err != nil {
		t.Fatal(err)
	}
	var phase string
	if err = a.s.pool.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id='a'").Scan(&phase); err != nil || phase != "DELETING" {
		t.Fatal("a is not deleted:", phase, err)
	}
	for store := range 3 {
		if n := a.sqliteCount(t, store, "capsule_fences", "subject", "agent/a"); n != 1 {
			t.Fatalf("store %s has %d fences of agent/a", p1Agent(store), n)
		}
	}
	assertRequestState(t, a.s, first, "CANCELED")
	if n := a.sqliteCount(t, 1, "received", "event_id", held.ID); n != 0 {
		t.Fatal("request 0's effect committed in b's store:", n)
	}
	var toA int
	if err = a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE dest_agent_id='a' AND delivery_state<>'CANCELED'").Scan(&toA); err != nil || toA != 0 {
		t.Fatal("a delivery to the deleted agent is still open or was delivered:", toA, err)
	}
	// observe(0): a's owner reads request 0's end.
	v, err := a.catalog.Request(t.Context(), a.principals[0], first)
	if err != nil || v.State != "CANCELED" {
		t.Fatal("a's owner cannot observe request 0:", v.State, err)
	}
	// admit(1), complete(1): c executes request 1 and answers.
	executed := deliver(secondMailbox)
	if err = a.commit(t); err != nil {
		t.Fatal(err)
	}
	reply := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "progress result"}}}}
	if _, err = a.transit.ReplyFromVM(t.Context(), a.local.callers[2], second, "progress-reply", reply); err != nil {
		t.Fatal(err)
	}
	// notify(1,true): the reply reaches b.
	notice := mailboxFor(t, a.s, second, "reply")
	deliver(notice)
	if err = a.commit(t); err != nil {
		t.Fatal(err)
	}
	// expect: deleted, observed, request 0's notice cancelled, request 1's
	// notice acknowledged.
	assertRequestState(t, a.s, second, "REPLIED")
	var notified bool
	if err = a.s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", second).Scan(&notified); err != nil || !notified {
		t.Fatal("b was not notified of request 1's reply:", notified, err)
	}
	if n := a.sqliteCount(t, 2, "received", "event_id", executed.ID); n != 1 {
		t.Fatal("request 1's effects in c's store:", n)
	}
	if n := a.sqliteCount(t, 1, "received", "event_id", notice); n != 1 {
		t.Fatal("the reply's effects in b's store:", n)
	}
}
