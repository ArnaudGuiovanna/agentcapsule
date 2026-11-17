package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Go projections of the delivery and closure runs of
// concurrent_protocol_test.qnt (ADR 007) that no ITF fixture replays: the
// P1 fixture pins the model before ADR 007. Each test drives the P1 replay
// (PostgreSQL, local harness stores over mTLS) through the run's steps and
// checks its expectation. spec/projections.md lists them.
//
// An event's retirement is one production call, RetireDelivery: it marks the
// event closing (the model's expireEvent or beginRetire, once its deadline
// passed or its attempts ran out), fences it in its destination's store when
// an attempt may have reached it (fenceStore, recordFence), and retires it
// (retire); with no such attempt it retires it at once (retireUnsent). The
// model's expireEvent is the deadline passing: the replay ages it.

// p1Fences fences in the replay's local stores, as the worker's runtime
// fences in the agents' VMs.
type p1Fences struct{ a *p1Replay }

func (f p1Fences) Fence(ctx context.Context, target, subject string) error {
	return f.a.boots[p1AgentNumber(target)].client.Fence(ctx, subject)
}

func (a *p1Replay) retire(t *testing.T, label string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return a.s.RetireDelivery(ctx, a.events[label], p1Fences{a})
}

// localFences counts the fences of subject in an agent's harness store.
func localFences(t *testing.T, root, agent, subject string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(root, fmt.Sprintf("%x", sha256.Sum256([]byte(agent))), "harness.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var table, n int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='capsule_fences'").Scan(&table); err != nil {
		t.Fatal(err)
	}
	if table == 0 {
		return 0
	}
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM capsule_fences WHERE subject=?", subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func eventState(t *testing.T, s *Store, id string) string {
	t.Helper()
	var state string
	if err := s.pool.QueryRow(t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func senderNotified(t *testing.T, s *Store, request string) bool {
	t.Helper()
	var notified bool
	if err := s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", request).Scan(&notified); err != nil {
		t.Fatal(err)
	}
	return notified
}

// replied: request 0 delivered to B, and B's reply to it committed.
func (a *p1Replay) replied(t *testing.T) {
	t.Helper()
	a.submit(t, 0)
	a.deliver(t, 0, 0, 0)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"ReplyCall"},1]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	a.bind(t, 0, "reply")
}

func (a *p1Replay) barrierEverywhere(t *testing.T, subject string) {
	t.Helper()
	for store := range 3 {
		args := `[` + fmt.Sprint(store) + `,` + subject + `]`
		a.run(t, p1Act(t, "fenceStore", args), p1Act(t, "recordFence", args))
	}
}

// duplicateAfterLostAckTest, and protocolCompositionOk's
// expiredLeaseRetryDeduplicatesTest: the first worker's effect commits in
// B's store, its ACK is lost and its lease expires. A second worker
// delivers the same event: B's store deduplicates it, and the first worker's
// late ACK is refused.
func TestDuplicateAfterLostAck(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,0]}]`), p1Act(t, "authorize", `[0]`), p1Act(t, "beginEffect", `[0]`),
		p1Act(t, "commitEffect", `[0]`), p1Act(t, "expireLease", `[{"tuple":[0,0]}]`))
	a.deliver(t, 1, 0, 0)
	if n := localEffects(t, a.root, "b", a.events["request/0/request"]); n != 1 {
		t.Fatal("effects of the delivered request in B's store:", n)
	}
	assertRequestState(t, a.s, a.requests[0], "PROCESSING")
	if err := a.step(t, p1Act(t, "acknowledge", `[0]`)); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("the first worker's late ACK was accepted:", err)
	}
	assertRequestState(t, a.s, a.requests[0], "PROCESSING")
}

// statusAfterReplyRevocationTest: B answers, then B is deleted before its
// reply reaches A. The deletion cancels the reply and A gets a status
// instead; the request stays replied.
func TestStatusAfterReplyRevocation(t *testing.T) {
	a := newP1Replay(t, false)
	a.replied(t)
	a.run(t, p1Act(t, "requestDelete", `[1]`))
	a.barrierEverywhere(t, `{"variant":"AgentSubject","value":1}`)
	a.run(t, p1Act(t, "commitDelete", `[1]`))
	if got := eventState(t, a.s, a.events["request/0/reply"]); got != "CANCELED" {
		t.Fatal("the revoked reply is", got)
	}
	a.bind(t, 0, "status")
	a.deliver(t, 0, 0, 2)
	assertRequestState(t, a.s, a.requests[0], "REPLIED")
	if !senderNotified(t, a.s, a.requests[0]) {
		t.Fatal("A was not notified")
	}
}

// expiredUnsentReplyTest: B's reply to A, never sent, passes its deadline
// while A is stopped. It dies without a fence; the request stays replied and
// A is not notified.
func TestExpiredUnsentReply(t *testing.T) {
	a := newP1Replay(t, false)
	a.replied(t)
	a.run(t, p1Act(t, "stopVM", `[0]`), p1Act(t, "retireBoot", `[0]`), p1Act(t, "observeStopped", `[0]`))
	reply := a.events["request/0/reply"]
	pastDeadline(t, a.s, reply)
	if err := a.retire(t, "request/0/reply"); err != nil {
		t.Fatal("retireUnsent:", err)
	}
	if got := eventState(t, a.s, reply); got != "DEAD" {
		t.Fatal("the expired reply is", got)
	}
	assertRequestState(t, a.s, a.requests[0], "REPLIED")
	if senderNotified(t, a.s, a.requests[0]) {
		t.Fatal("A was notified of a reply it never got")
	}
	// receipts == Set() and acks == Set(): no fence, asked or given.
	var revocations int
	if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM revocation_catalogue WHERE subject=$1", "event/"+reply).Scan(&revocations); err != nil || revocations != 0 {
		t.Fatal("the unsent reply was fenced:", revocations, err)
	}
	if n := localFences(t, a.root, "a", "event/"+reply); n != 0 {
		t.Fatal("A's store holds a fence of the unsent reply:", n)
	}
}

// expiredSentReplyWaitsForFenceTest: an attempt to carry B's reply was
// authorized, then lost; the reply passes its deadline while A is stopped.
// It does not die without A's fence.
func TestExpiredSentReplyWaitsForFence(t *testing.T) {
	a := newP1Replay(t, false)
	a.replied(t)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,1]}]`), p1Act(t, "authorize", `[0]`), p1Act(t, "loseRPC", `[0]`),
		p1Act(t, "expireLease", `[{"tuple":[0,1]}]`),
		p1Act(t, "stopVM", `[0]`), p1Act(t, "retireBoot", `[0]`), p1Act(t, "observeStopped", `[0]`))
	reply := a.events["request/0/reply"]
	pastDeadline(t, a.s, reply)
	if err := a.retire(t, "request/0/reply"); err == nil {
		t.Fatal("retireUnsent: an expired reply an attempt may have carried died without its fence")
	}
	if got := eventState(t, a.s, reply); got != "PENDING" {
		t.Fatal("the expired, sent reply is", got)
	}
	assertRequestState(t, a.s, a.requests[0], "REPLIED")
}

// expiredSentReplyRetiredAfterFenceTest: the same reply, A running: A's
// store fences it, and then it dies.
func TestExpiredSentReplyRetiredAfterFence(t *testing.T) {
	a := newP1Replay(t, false)
	a.replied(t)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,1]}]`), p1Act(t, "authorize", `[0]`), p1Act(t, "loseRPC", `[0]`),
		p1Act(t, "expireLease", `[{"tuple":[0,1]}]`))
	reply := a.events["request/0/reply"]
	pastDeadline(t, a.s, reply)
	a.run(t, p1Act(t, "fenceStore", `[0,{"variant":"EventSubject","value":{"tuple":[0,1]}}]`))
	// recordFence, retire.
	if err := a.retire(t, "request/0/reply"); err != nil {
		t.Fatal(err)
	}
	if got := eventState(t, a.s, reply); got != "DEAD" {
		t.Fatal("the fenced reply is", got)
	}
	if n := localFences(t, a.root, "a", "event/"+reply); n != 1 {
		t.Fatal("A's store fences of the reply:", n)
	}
	assertRequestState(t, a.s, a.requests[0], "REPLIED")
}

// unsentReplyDiesBehindHeadTest (ADR 007 §7): C's request to A heads A's
// queue, ahead of B's reply; A is stopped. The reply, never sent, dies past
// its deadline out of order; C's request stays at the head.
func TestUnsentReplyDiesBehindHead(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.deliver(t, 0, 0, 0)
	a.submit(t, 2)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"ReplyCall"},1]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	a.bind(t, 0, "reply")
	a.run(t, p1Act(t, "stopVM", `[0]`), p1Act(t, "retireBoot", `[0]`), p1Act(t, "observeStopped", `[0]`))
	head := a.events["request/2/request"]
	if got, err := a.s.HeadDelivery(t.Context(), "a"); err != nil || got != head {
		t.Fatal("C's request does not head A's queue:", got, err)
	}
	reply := a.events["request/0/reply"]
	pastDeadline(t, a.s, reply)
	if err := a.retire(t, "request/0/reply"); err != nil {
		t.Fatal("retireUnsent behind the head:", err)
	}
	if got := eventState(t, a.s, reply); got != "DEAD" {
		t.Fatal("the reply behind the head is", got)
	}
	if got := eventState(t, a.s, head); got != "PENDING" {
		t.Fatal("C's request is", got)
	}
	if got, err := a.s.HeadDelivery(t.Context(), "a"); err != nil || got != head {
		t.Fatal("the head changed:", got, err)
	}
}

// revokedReply: B's reply to A is committed, B's deletion is requested, and
// the reply's deadline passes.
func revokedReply(t *testing.T) *p1Replay {
	t.Helper()
	a := newP1Replay(t, false)
	a.replied(t)
	a.run(t, p1Act(t, "requestDelete", `[1]`))
	pastDeadline(t, a.s, a.events["request/0/reply"])
	return a
}

// retirementLeavesDeletionTest: a reply its author's deletion revokes does
// not die at its deadline.
func TestRetirementLeavesDeletion(t *testing.T) {
	a := revokedReply(t)
	if err := a.retire(t, "request/0/reply"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("retireUnsent: a reply revoked by its author's deletion was retired:", err)
	}
	if got := eventState(t, a.s, a.events["request/0/reply"]); got != "PENDING" {
		t.Fatal("the revoked reply is", got)
	}
}

// deletionCancelsExpiredReplyTest: the deletion cancels that reply and
// queues a status for A.
func TestDeletionCancelsExpiredReply(t *testing.T) {
	a := revokedReply(t)
	a.barrierEverywhere(t, `{"variant":"AgentSubject","value":1}`)
	a.run(t, p1Act(t, "commitDelete", `[1]`))
	if got := eventState(t, a.s, a.events["request/0/reply"]); got != "CANCELED" {
		t.Fatal("the revoked reply is", got)
	}
	a.bind(t, 0, "status")
	if got := eventState(t, a.s, a.events["request/0/status"]); got != "PENDING" {
		t.Fatal("A's status is", got)
	}
}

// submittedManual: A's request 0 to B, whose inbound mode is manual.
func submittedManual(t *testing.T) *p1Replay {
	t.Helper()
	a := newP1Replay(t, true)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},0]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	assertRequestState(t, a.s, a.requests[0], "PENDING_APPROVAL")
	return a
}

// closeBlocksConsentTest: B's owner accepts after the request's expiry
// began; the acceptance is refused (Accept moves only a request with no
// closure).
func TestCloseBlocksConsent(t *testing.T) {
	a := submittedManual(t)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"AcceptCall"},1]`), p1Act(t, "closeRequest", `[0,{"variant":"ExpireRequest"}]`))
	if err := a.refusedCall(t, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("the acceptance of an expiring request:", err)
	}
	var phase string
	if err := a.s.pool.QueryRow(t.Context(), "SELECT phase FROM request_closures WHERE request_id=$1", a.requests[0]).Scan(&phase); err != nil || phase != "FENCING" {
		t.Fatal("the request's expiry is not under way:", phase, err)
	}
	assertRequestState(t, a.s, a.requests[0], "PENDING_APPROVAL")
	var mailboxes int
	if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE ref_id=$1 AND kind='request'", a.requests[0]).Scan(&mailboxes); err != nil || mailboxes != 0 {
		t.Fatal("the refused acceptance queued the request:", mailboxes, err)
	}
}

// abortedAdmissionReleasesLocksTest: B's owner's acceptance is admitted,
// then aborts; its locks go with it, and A's owner cancels the request.
func TestAbortedAdmissionReleasesLocks(t *testing.T) {
	a := submittedManual(t)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"AcceptCall"},1]`), p1Act(t, "admit", `[0]`), p1Act(t, "abortCall", `[0]`))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := a.s.RequestCancellation(ctx, "user-a", a.requests[0]); err != nil {
		t.Fatal("closeRequest after the aborted acceptance:", err)
	}
	var final string
	if err := a.s.pool.QueryRow(t.Context(), `SELECT coalesce((SELECT final_state FROM request_closures WHERE request_id=$1),
        (SELECT state FROM agent_requests WHERE id=$1))`, a.requests[0]).Scan(&final); err != nil || final != "CANCELED" {
		t.Fatal("the request's closure is not a cancellation:", final, err)
	}
}

// concurrentWitnessNoFifoGuard.guardTest: A's request 0, then C's request 1,
// both to B. Request 1 cannot be claimed before request 0.
func TestConcurrentWitnessNoFifoGuard(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.submit(t, 1)
	if _, err := a.s.ClaimDelivery(t.Context(), a.events["request/1/request"], time.Hour); !errors.Is(err, ErrNotHead) {
		t.Fatal("request 1 overtook B's queue:", err)
	}
}
