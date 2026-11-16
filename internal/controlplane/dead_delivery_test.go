package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// deadReplyLab is a request from a's VM to b's that b answered, with real
// owners for a and b: the reply waits in a's mailbox (ADR 007).
type deadReplyLab struct {
	s       *Store
	tr      *Transit
	catalog *AgentCatalog
	owners  [2]Principal
	a, b, c VMCaller
	rt      *peerRuntime
	request string
	reply   string
}

func newDeadReplyLab(t *testing.T) *deadReplyLab {
	t.Helper()
	s, _ := freshStore(t, "auto", 3)
	accounts, err := NewAccounts(s, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "dead-reply-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	l := &deadReplyLab{s: s, tr: peerTransit(t, s), rt: peerRuntimeLab(t)}
	for i, id := range []string{"a", "b"} {
		u := createAccount(t, accounts, admin, "owner-"+id, "Owner "+id)
		token := issueAccountToken(t, accounts, admin, u, "token-"+id)
		if l.owners[i], err = s.Authenticate(t.Context(), token.Token); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "UPDATE agents SET owner_user_id=$2 WHERE id=$1", id, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if l.catalog, err = NewAgentCatalogWithTransit(accounts, "host", l.tr); err != nil {
		t.Fatal(err)
	}
	l.a, l.b, l.c = confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b"), confirmedCaller(t, s, "c")
	r, err := l.tr.SubmitFromVM(t.Context(), l.a, "request", peerSubmission("a question"))
	if err != nil {
		t.Fatal(err)
	}
	l.request = r.RequestID
	if err = l.tr.DispatchMailbox(t.Context(), mailboxFor(t, s, l.request, "request"), time.Minute, l.rt); err != nil {
		t.Fatal(err)
	}
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "the answer"}}}}
	if _, err = l.tr.ReplyFromVM(t.Context(), l.b, l.request, "reply", answer); err != nil {
		t.Fatal(err)
	}
	l.reply = mailboxFor(t, s, l.request, "reply")
	return l
}

// unreachable loses every send before it reaches the agent's store.
type unreachable struct{ *peerRuntime }

func (unreachable) Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
}

// killReply makes the reply's three attempts fail, then retires it.
func (l *deadReplyLab) killReply(t *testing.T) {
	t.Helper()
	down := unreachable{l.rt}
	for range 3 {
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("a failed attempt", err)
		}
		expireLease(t, l.s, l.reply)
	}
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); err != nil {
		t.Fatal(err)
	}
	l.deliveryState(t, "DEAD")
}

func (l *deadReplyLab) deliveryState(t *testing.T, want string) {
	t.Helper()
	var got string
	if err := l.s.pool.QueryRow(t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", l.reply).Scan(&got); err != nil || got != want {
		t.Fatalf("reply delivery %s, want %s (%v)", got, want, err)
	}
}

// purgeLater moves the reply's retention to its end, as time would.
func (l *deadReplyLab) purgeLater(t *testing.T) {
	t.Helper()
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second'
        WHERE id=(SELECT reply_ref FROM agent_requests WHERE id=$1) AND purge_after IS NOT NULL`, l.request); err != nil {
		t.Fatal(err)
	}
	if _, err := l.tr.PurgeExpired(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}

// A reply whose delivery dies is kept for the transit retention from its
// death, as a delivered reply is from its delivery, then purged.
func TestDeadReplyStartsRetention(t *testing.T) {
	l := newDeadReplyLab(t)
	l.killReply(t)
	var after time.Duration
	if err := l.s.pool.QueryRow(t.Context(), `SELECT coalesce(extract(epoch FROM p.purge_after-clock_timestamp()),0)*interval '1 second'
        FROM transit_payloads p JOIN agent_requests r ON r.reply_ref=p.id WHERE r.id=$1`, l.request).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after < 7*24*time.Hour-time.Minute || after > 7*24*time.Hour {
		t.Fatalf("the dead reply is kept %v from now, want 7 days", after)
	}
	view, err := l.catalog.Request(t.Context(), l.owners[0], l.request)
	if err != nil || view.State != "REPLIED" || view.Reply == nil || view.Reply.Content[0].Text != "the answer" {
		t.Fatal("the sender's owner cannot read the kept reply", view, err)
	}
	l.purgeLater(t)
	var purged bool
	if err = l.s.pool.QueryRow(t.Context(), `SELECT p.purged_at IS NOT NULL AND p.ciphertext IS NULL
        FROM transit_payloads p JOIN agent_requests r ON r.reply_ref=p.id WHERE r.id=$1`, l.request).Scan(&purged); err != nil || !purged {
		t.Fatal("the dead reply outlived its retention", err)
	}
	for _, owner := range l.owners {
		view, err = l.catalog.Request(t.Context(), owner, l.request)
		if err != nil || view.State != "REPLIED" || view.Reply != nil {
			t.Fatal("a purged reply is still readable", view, err)
		}
	}
}

// The sender's agent reads its reply through the request's status, whether
// the reply's delivery is pending or dead; nobody else does. Once the reply
// is purged, or revoked by the deletion of its author, the read says why.
func TestSenderReadsReplyAfterDeadDelivery(t *testing.T) {
	l := newDeadReplyLab(t)
	read := func(want, reason string) {
		t.Helper()
		got, err := l.tr.RequestStateFromVM(t.Context(), l.a, l.request)
		if err != nil || got.State != "REPLIED" || got.Reason != reason {
			t.Fatalf("status %+v %v, want reason %q", got, err, reason)
		}
		if want == "" && got.Reply != nil || want != "" && (got.Reply == nil || got.Reply.Content[0].Text != want) {
			t.Fatalf("reply %+v, want %q", got.Reply, want)
		}
	}
	read("the answer", "")
	l.killReply(t)
	read("the answer", "")
	for _, vm := range []VMCaller{l.b, l.c} {
		if _, err := l.tr.RequestStateFromVM(t.Context(), vm, l.request); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s read another agent's reply: %v", vm.AgentID, err)
		}
	}
	l.purgeLater(t)
	read("", "content_purged")

	revoked := newDeadReplyLab(t)
	revoked.killReply(t)
	if err := revoked.s.RequestDeletion(t.Context(), revoked.owners[1].ID, "b"); err != nil {
		t.Fatal(err)
	}
	got, err := revoked.tr.RequestStateFromVM(t.Context(), revoked.a, revoked.request)
	if err != nil || got.State != "REPLIED" || got.Reply != nil || got.Reason != "content_revoked" {
		t.Fatalf("status after the replier's deletion %+v %v", got, err)
	}
}

// unbootable is a destination that never boots: preparation fails before any
// attempt is spent, and so does a boot for a barrier.
type unbootable struct{ *peerRuntime }

var errNeverBoots = errors.New("the agent's VM does not boot")

func (unbootable) WithPreparedDelivery(context.Context, string, func(context.Context) error) error {
	return errNeverBoots
}
func (unbootable) Fence(context.Context, string, string) error { return errNeverBoots }

type unbootableInstructions struct{ instructionRuntime }

func (unbootableInstructions) WithPreparedDelivery(context.Context, string, func(context.Context) error) error {
	return errNeverBoots
}
func (unbootableInstructions) Fence(context.Context, string, string) error { return errNeverBoots }

// pastDeadline moves a delivery's deadline to the past, as time would.
func pastDeadline(t *testing.T, s *Store, id string) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
}

func attempts(t *testing.T, s *Store, id string) (int, bool) {
	t.Helper()
	var n int
	var reached bool
	if err := s.pool.QueryRow(t.Context(), "SELECT attempts,may_have_reached FROM agent_mailboxes WHERE id=$1", id).Scan(&n, &reached); err != nil {
		t.Fatal(err)
	}
	return n, reached
}

// A reply, a status or an instruction to an agent that never boots dies at
// its deadline, without a claim and without booting the agent: no attempt
// was allowed to reach it, so there is nothing to fence (EVT-005, EVT-006,
// ADR 007). Until then it waits, and preparation spends no attempt. The
// agent reads its dead reply when it comes back.
func TestExpiredDeliveryDiesWithoutItsRecipient(t *testing.T) {
	l := newDeadReplyLab(t)
	down := unbootable{l.rt}
	for range 5 {
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); !errors.Is(err, errNeverBoots) {
			t.Fatal("a recipient that does not boot", err)
		}
	}
	if n, _ := attempts(t, l.s, l.reply); n != 0 {
		t.Fatalf("preparation spent %d attempts", n)
	}
	pastDeadline(t, l.s, l.reply)
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); err != nil {
		t.Fatal("an expired delivery waits for its recipient to boot", err)
	}
	l.deliveryState(t, "DEAD")
	if n, _ := attempts(t, l.s, l.reply); n != 0 || count(t, l.s, "revocation_catalogue") != 0 {
		t.Fatal("a delivery that reached nobody was claimed or fenced", n)
	}
	got, err := l.tr.RequestStateFromVM(t.Context(), l.a, l.request)
	if err != nil || got.State != "REPLIED" || got.Reply == nil || got.Reply.Content[0].Text != "the answer" {
		t.Fatal("the agent cannot read its dead reply when it returns", got, err)
	}
	var kept bool
	if err = l.s.pool.QueryRow(t.Context(), `SELECT p.purge_after>clock_timestamp()+interval '6 days'
        FROM transit_payloads p JOIN agent_requests r ON r.reply_ref=p.id WHERE r.id=$1`, l.request).Scan(&kept); err != nil || !kept {
		t.Fatal("the dead reply's retention did not start", err)
	}

	// A declined request's status, behind the dead reply in a's mailbox.
	declined, err := l.tr.SubmitFromVM(t.Context(), l.a, "declined", peerSubmission("another question"))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.tr.DispatchMailbox(t.Context(), mailboxFor(t, l.s, declined.RequestID, "request"), time.Minute, l.rt); err != nil {
		t.Fatal(err)
	}
	if _, err = l.tr.ReplyFromVM(t.Context(), l.b, declined.RequestID, "decline", capsuleprotocol.Reply{Outcome: "declined"}); err != nil {
		t.Fatal(err)
	}
	status := mailboxFor(t, l.s, declined.RequestID, "status")
	if err = l.tr.DispatchMailbox(t.Context(), status, time.Minute, down); !errors.Is(err, errNeverBoots) {
		t.Fatal(err)
	}
	pastDeadline(t, l.s, status)
	if err = l.tr.DispatchMailbox(t.Context(), status, time.Minute, down); err != nil {
		t.Fatal("an expired status waits for its recipient to boot", err)
	}
	var state string
	if err = l.s.pool.QueryRow(t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", status).Scan(&state); err != nil || state != "DEAD" {
		t.Fatal("expired status", state, err)
	}
	assertRequestState(t, l.s, declined.RequestID, "DECLINED")

	// An owner's instruction stays accepted until its deadline, then fails.
	s, c, tr, _, owner, e := instructionLab(t)
	id, op := queueInstruction(t, c, owner, e.AgentID, "never-boots")
	stuck := unbootableInstructions{instructionRuntimeLab(t, e.AgentID)}
	if err = tr.DispatchMailbox(t.Context(), id, time.Minute, stuck); !errors.Is(err, errNeverBoots) {
		t.Fatal(err)
	}
	pastDeadline(t, s, id)
	if err = tr.DispatchMailbox(t.Context(), id, time.Minute, stuck); err != nil {
		t.Fatal("an expired instruction waits for its agent to boot", err)
	}
	operation, err := c.Operation(t.Context(), owner, op)
	if err != nil || operation.Status != "FAILED" || operation.ErrorCode != "delivery_failed" {
		t.Fatal("expired instruction", operation, err)
	}
	var reason string
	var inputKept bool
	if err = s.pool.QueryRow(t.Context(), `SELECT i.close_reason,p.purge_after IS NOT NULL FROM owner_instructions i
        JOIN transit_payloads p ON p.id=i.input_payload_id WHERE i.operation_id=$1`, op).Scan(&reason, &inputKept); err != nil || reason != "expired" || !inputKept {
		t.Fatal("expired instruction's reason and retention", reason, inputKept, err)
	}
}

// A delivery to an agent being deleted does not die at its deadline: the
// deletion cancels it, and nobody is to be told (ADR 007 §1).
func TestExpiredDeliveryToADeletedAgentIsCanceled(t *testing.T) {
	l := newDeadReplyLab(t)
	if err := l.s.RequestDeletion(t.Context(), l.owners[0].ID, "a"); err != nil {
		t.Fatal(err)
	}
	pastDeadline(t, l.s, l.reply)
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, unbootable{l.rt}); !errors.Is(err, errNeverBoots) {
		t.Fatal("a delivery to an agent being deleted died", err)
	}
	l.deliveryState(t, "PENDING")
	if err := l.s.ReconcileRevocation(t.Context(), "a", l.rt); err != nil {
		t.Fatal(err)
	}
	l.deliveryState(t, "CANCELED")
}

// A reply that an attempt may have reached is fenced before it dies: a
// delayed send could still apply it. Past its deadline it waits for the
// agent to boot for that barrier, and dies then.
func TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence(t *testing.T) {
	l := newDeadReplyLab(t)
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, unreachable{l.rt}); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal(err)
	}
	expireLease(t, l.s, l.reply)
	pastDeadline(t, l.s, l.reply)
	if n, reached := attempts(t, l.s, l.reply); n != 1 || !reached {
		t.Fatal("the attempt was not allowed to reach the agent", n, reached)
	}
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, unbootable{l.rt}); !errors.Is(err, errNeverBoots) {
		t.Fatal("retired without its fence", err)
	}
	l.deliveryState(t, "PENDING")
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, l.rt); err != nil {
		t.Fatal(err)
	}
	l.deliveryState(t, "DEAD")
}

// deathWitness records the deaths its dispatcher reports.
type deathWitness struct{ deaths []DeadDelivery }

func (w *deathWitness) DeliveryDead(_ context.Context, d DeadDelivery) {
	w.deaths = append(w.deaths, d)
}

type witnessedReplies struct {
	unreachable
	*deathWitness
}

type witnessedInstructions struct {
	unbootableInstructions
	*deathWitness
}

// Each death is reported once it has committed, with its kind and reason, to
// a runtime that observes them (ADR 007 §4): through the fence, and without.
func TestDeliveryDeathsAreReported(t *testing.T) {
	l := newDeadReplyLab(t)
	replies := witnessedReplies{unreachable{l.rt}, &deathWitness{}}
	for range 3 {
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, replies); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal(err)
		}
		expireLease(t, l.s, l.reply)
	}
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, replies); err != nil {
		t.Fatal(err)
	}
	if err := l.s.RetireDelivery(t.Context(), l.reply, replies); err != nil {
		t.Fatal(err)
	}
	if want := []DeadDelivery{{l.reply, "reply", "attempts_exhausted"}}; fmt.Sprint(replies.deaths) != fmt.Sprint(want) {
		t.Fatal("reported", replies.deaths, "want", want)
	}

	s, c, tr, _, owner, e := instructionLab(t)
	id, _ := queueInstruction(t, c, owner, e.AgentID, "witnessed")
	instructions := witnessedInstructions{unbootableInstructions{instructionRuntimeLab(t, e.AgentID)}, &deathWitness{}}
	pastDeadline(t, s, id)
	if err := tr.DispatchMailbox(t.Context(), id, time.Minute, instructions); err != nil {
		t.Fatal(err)
	}
	if want := []DeadDelivery{{id, "instruction", "expired"}}; fmt.Sprint(instructions.deaths) != fmt.Sprint(want) {
		t.Fatal("reported", instructions.deaths, "want", want)
	}
}

// A reply or an instruction past its deadline that no attempt reached dies
// even while another delivery heads its agent's mailbox: an agent that never
// boots keeps neither alive (EVT-005). It never reached the agent, so it
// dies out of order without breaking the order of what the agent receives.
// The worker discovers it although it is not the head; a delivery that is
// not due waits for its turn.
func TestExpiredDeliveryBehindAStuckHeadDies(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	tr := peerTransit(t, s)
	prt := peerRuntimeLab(t)
	a, b, c := confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b"), confirmedCaller(t, s, "c")
	r, err := tr.SubmitFromVM(t.Context(), a, "request", peerSubmission("a question"))
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(t.Context(), mailboxFor(t, s, r.RequestID, "request"), time.Minute, prt); err != nil {
		t.Fatal(err)
	}
	// c asks a something: a request delivery to a, ahead of b's reply.
	toA := peerSubmission("c asks a")
	toA.RecipientAgentID, toA.MandateID = "a", "mandate-c"
	head, err := tr.SubmitFromVM(t.Context(), c, "from-c", toA)
	if err != nil {
		t.Fatal(err)
	}
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "the answer"}}}}
	if _, err = tr.ReplyFromVM(t.Context(), b, r.RequestID, "reply", answer); err != nil {
		t.Fatal(err)
	}
	reply := mailboxFor(t, s, r.RequestID, "reply")
	discovered := func() bool {
		t.Helper()
		if err := s.DiscoverWork(t.Context(), "host", 100); err != nil {
			t.Fatal(err)
		}
		var found bool
		if err := s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM worker_jobs WHERE kind='delivery' AND object_id=$1)", reply).Scan(&found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	if discovered() {
		t.Fatal("a delivery behind the head was discovered before its deadline")
	}
	pastDeadline(t, s, reply)
	if !discovered() {
		t.Fatal("an expired delivery behind the head is never discovered")
	}
	w := &deathWitness{}
	if err = tr.DispatchMailbox(t.Context(), reply, time.Minute, struct {
		unbootable
		*deathWitness
	}{unbootable{prt}, w}); err != nil {
		t.Fatal("an expired reply waits behind a request delivery to an agent that never boots:", err)
	}
	var state string
	if err = s.pool.QueryRow(t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", reply).Scan(&state); err != nil || state != "DEAD" {
		t.Fatal("expired reply behind the head", state, err)
	}
	if want := []DeadDelivery{{reply, "reply", "expired"}}; fmt.Sprint(w.deaths) != fmt.Sprint(want) {
		t.Fatal("reported", w.deaths, "want", want)
	}
	if got, err := s.HeadDelivery(t.Context(), "a"); err != nil || got != mailboxFor(t, s, head.RequestID, "request") {
		t.Fatal("the head changed", got, err)
	}

	// An instruction behind an instruction an attempt may have reached.
	is, ic, itr, _, owner, e := instructionLab(t)
	first, _ := queueInstruction(t, ic, owner, e.AgentID, "first")
	second, op := queueInstruction(t, ic, owner, e.AgentID, "second")
	claimInstruction(t, itr, first)
	pastDeadline(t, is, second)
	stuck := unbootableInstructions{instructionRuntimeLab(t, e.AgentID)}
	if err = itr.DispatchMailbox(t.Context(), second, time.Minute, stuck); err != nil {
		t.Fatal("an expired instruction waits behind the head:", err)
	}
	operation, err := ic.Operation(t.Context(), owner, op)
	if err != nil || operation.Status != "FAILED" || operation.ErrorCode != "delivery_failed" {
		t.Fatal("expired instruction behind the head", operation, err)
	}
	if got, err := is.HeadDelivery(t.Context(), e.AgentID); err != nil || got != first {
		t.Fatal("the head changed", got, err)
	}
}

// A delivery whose destination, or whose reply's author, is being deleted is
// canceled by that deletion, which tells the sender of a revoked reply. It
// does not die, nor count as a dead delivery, though it is past its deadline:
// the retirement checks the agents under their locks, whatever its caller
// saw, and again once its fence is done.
func TestRetirementLeavesADeletionToCancel(t *testing.T) {
	t.Run("destination deleted after the dispatcher's check", func(t *testing.T) {
		l := newDeadReplyLab(t)
		w := &deathWitness{}
		pastDeadline(t, l.s, l.reply)
		if due, err := l.s.retirementDue(t.Context(), l.reply); err != nil || !due {
			t.Fatal(due, err)
		}
		if err := l.s.RequestDeletion(t.Context(), l.owners[0].ID, "a"); err != nil {
			t.Fatal(err)
		}
		if err := l.s.retireDelivery(t.Context(), l.reply, witnessedReplies{unreachable{l.rt}, w}, l.tr); !errors.Is(err, ErrUnavailable) {
			t.Fatal("a delivery to an agent being deleted was retired", err)
		}
		l.deliveryState(t, "PENDING")
		if len(w.deaths) != 0 {
			t.Fatal("reported", w.deaths)
		}
		if err := l.s.ReconcileRevocation(t.Context(), "a", l.rt); err != nil {
			t.Fatal(err)
		}
		l.deliveryState(t, "CANCELED")
	})
	t.Run("reply's author being deleted", func(t *testing.T) {
		l := newDeadReplyLab(t)
		w := &deathWitness{}
		if err := l.s.RequestDeletion(t.Context(), l.owners[1].ID, "b"); err != nil {
			t.Fatal(err)
		}
		pastDeadline(t, l.s, l.reply)
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, struct {
			unbootable
			*deathWitness
		}{unbootable{l.rt}, w}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("a reply revoked by its author's deletion was retired", err)
		}
		l.deliveryState(t, "PENDING")
		if len(w.deaths) != 0 {
			t.Fatal("reported", w.deaths)
		}
		if err := l.s.ReconcileRevocation(t.Context(), "b", l.rt); err != nil {
			t.Fatal(err)
		}
		l.deliveryState(t, "CANCELED")
		var reason string
		if err := l.s.pool.QueryRow(t.Context(), "SELECT status_reason FROM agent_mailboxes WHERE ref_id=$1 AND kind='status'", l.request).Scan(&reason); err != nil || reason != "content_revoked" {
			t.Fatal("the sender is not told of the revoked reply", reason, err)
		}
	})
	t.Run("destination deleted during the fence", func(t *testing.T) {
		l := newDeadReplyLab(t)
		w := &deathWitness{}
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, unreachable{l.rt}); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal(err)
		}
		expireLease(t, l.s, l.reply)
		pastDeadline(t, l.s, l.reply)
		l.rt.SetFenceHook(func(stage, target, subject string) error {
			if stage == "after_commit" && subject == "event/"+l.reply {
				return l.s.RequestDeletion(t.Context(), l.owners[0].ID, "a")
			}
			return nil
		})
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, struct {
			*peerRuntime
			*deathWitness
		}{l.rt, w}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("a delivery to an agent being deleted was retired after its fence", err)
		}
		l.rt.SetFenceHook(nil)
		l.deliveryState(t, "PENDING")
		if len(w.deaths) != 0 {
			t.Fatal("reported", w.deaths)
		}
		if err := l.s.ReconcileRevocation(t.Context(), "a", l.rt); err != nil {
			t.Fatal(err)
		}
		l.deliveryState(t, "CANCELED")
	})
	t.Run("instruction's agent deleted after the dispatcher's check", func(t *testing.T) {
		s, c, tr, _, owner, e := instructionLab(t)
		id, op := queueInstruction(t, c, owner, e.AgentID, "deleted")
		pastDeadline(t, s, id)
		if due, err := s.retirementDue(t.Context(), id); err != nil || !due {
			t.Fatal(due, err)
		}
		if err := s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
			t.Fatal(err)
		}
		rt := instructionRuntimeLab(t, e.AgentID)
		w := &deathWitness{}
		if err := tr.RetireInstruction(t.Context(), id, struct {
			instructionRuntime
			*deathWitness
		}{rt, w}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("an instruction to an agent being deleted was retired", err)
		}
		if len(w.deaths) != 0 {
			t.Fatal("reported", w.deaths)
		}
		if err := s.ReconcileRevocation(t.Context(), e.AgentID, rt); err != nil {
			t.Fatal(err)
		}
		if operation, err := c.Operation(t.Context(), owner, op); err != nil || operation.Status != "CANCELED" {
			t.Fatal("the deletion did not cancel the instruction", operation, err)
		}
	})
}

// Offboarding the person a reply is bound to does not revoke it: the request
// is work accepted before the revocation, which may complete for the
// organization (ADR 002). The sender's agent still reads its reply; the
// person reads nothing (docs/api/agents-assignments.md).
func TestOffboardingLeavesTheReplyToTheAgent(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "peer-b")
	if _, err := il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vmA := il.vm(t)
	vmB := il.runAgent(t, b)
	inv, _, err := il.create(t, alice, "ask-b", "ask b about France")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	var mandate string
	if err = il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", inv.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	in := capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond),
		Payload: text("what is the capital of France?")}
	r, err := il.tr.SubmitFromVM(ctx, vmA, "peer-1", in)
	if err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), il.agent, b)
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		_, err := capsuleprotocol.DecodePeerEvent(event, target)
		return []byte(`{"received":true}`), err
	})
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, r.RequestID, "request"), time.Minute, &peerRuntime{MockRuntime: m}); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ReplyFromVM(ctx, vmB, r.RequestID, "answer-1", capsuleprotocol.Reply{Outcome: "completed", Payload: text("Paris")}); err != nil {
		t.Fatal(err)
	}
	var principal string
	if err = il.s.pool.QueryRow(ctx, "SELECT requested_by_principal_id FROM platform_operations WHERE id=$1", inv.ID).Scan(&principal); err != nil {
		t.Fatal(err)
	}
	if _, err = il.a.RevokeMember(ctx, il.owner, principal, "revoke-alice"); err != nil {
		t.Fatal(err)
	}
	got, err := il.tr.RequestStateFromVM(ctx, vmA, r.RequestID)
	if err != nil || got.State != "REPLIED" || got.Reply == nil || got.Reply.Content[0].Text != "Paris" || got.Reason != "" {
		t.Fatal("the agent lost its reply when its requester was offboarded", got, err)
	}
}

// The status read decides why a reply is gone under the reply's lock: a purge
// at the end of its retention, committed while the read runs, is reported as
// such, not as a revocation.
func TestStatusReadReportsAPurgeUnderWay(t *testing.T) {
	l := newDeadReplyLab(t)
	l.killReply(t)
	purge, err := l.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer purge.Rollback(context.Background())
	var pid int
	if err = purge.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = purge.Exec(t.Context(), `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp(),
        purge_after=clock_timestamp()-interval '1 second' WHERE id=(SELECT reply_ref FROM agent_requests WHERE id=$1)`, l.request); err != nil {
		t.Fatal(err)
	}
	type result struct {
		state RequestState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		got, err := l.tr.RequestStateFromVM(t.Context(), l.a, l.request)
		done <- result{got, err}
	}()
	waitUntil(t, func() bool {
		var waits bool
		if err := l.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&waits); err != nil {
			t.Fatal(err)
		}
		return waits
	})
	if err = purge.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.state.Reply != nil || got.state.Reason != "content_purged" {
		t.Fatalf("status during a purge %+v %v, want reason content_purged", got.state, got.err)
	}
}

// The status read, which capsule-adapter polls, takes no lock on the
// recipient's agent nor on the request: it waits for neither.
func TestStatusReadLeavesTheRecipientUnlocked(t *testing.T) {
	l := newDeadReplyLab(t)
	busy, err := l.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Rollback(context.Background())
	if _, err = busy.Exec(t.Context(), "SELECT 1 FROM agents WHERE id='b' FOR NO KEY UPDATE"); err != nil {
		t.Fatal(err)
	}
	if _, err = busy.Exec(t.Context(), "SELECT 1 FROM agent_requests WHERE id=$1 FOR UPDATE", l.request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	got, err := l.tr.RequestStateFromVM(ctx, l.a, l.request)
	if err != nil || got.State != "REPLIED" || got.Reply == nil || got.Reply.Content[0].Text != "the answer" {
		t.Fatal("the status read waits for the recipient's work", got, err)
	}
}
