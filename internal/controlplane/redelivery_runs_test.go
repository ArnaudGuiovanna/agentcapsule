package controlplane

import "testing"

// Go projections of re-delivery runs (ADR 008) that the tests of
// peer_redeliveries_test.go do not drive step by step. spec/projections.md
// lists every run and the test that projects it.

// closingRequestIsNotRedeliveredTest (concurrent_protocol_test.qnt): the
// request's expiry has begun (its closure fences) when its recipient loses
// it in a restore. It is not sent again; its closure ends it.
func TestClosingRequestIsNotRedelivered(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.ask(t, "expiring when b is restored")
	request := mailboxFor(t, l.s, r, "request")
	l.deliver(t, request)
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", r); err != nil {
		t.Fatal(err)
	}
	if err := l.s.RequestExpiration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	losses := l.restore(t, l.b, request)
	wantDecision(t, losses[request], "skipped", "request_closed")
	if m := l.mailbox(t, request); m.State != "DELIVERED" || m.Outbox {
		t.Fatal("the closing request was queued again:", m)
	}
	if err := l.s.ReconcileRequestClosure(t.Context(), r, l.rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, l.s, r, "EXPIRED")
}

// scenario23Test (service_progress_test.qnt): arrive(0), admit(0): a's
// request reaches b, which works on it (PROCESSING is P3's Executing until
// complete). redeliverRequest(0): b is restored from an archive that lacks
// it; the request is accepted again, queued, and nothing executes it.
// admit(0), complete(0): b gets it again and answers; the outcome is in a's
// owner's inbox.
func TestRestoredStoreGetsItsRequestAgain(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.ask(t, "lost by b's restore")
	request := mailboxFor(t, l.s, r, "request")
	l.deliver(t, request)
	assertRequestState(t, l.s, r, "PROCESSING")
	wantDecision(t, l.restore(t, l.b, request)[request], "queued", "")
	// expect: stage == Accepted, running == Set(), admissionQueue == List(0).
	assertRequestState(t, l.s, r, "DELIVERING")
	if m := l.mailbox(t, request); m.State != "PENDING" || m.Reached || !m.Outbox {
		t.Fatal("the request is not queued again, or an attempt may still carry it:", m)
	}
	if head, err := l.s.HeadDelivery(t.Context(), l.b); err != nil || head != request {
		t.Fatal("the request does not head b's queue:", head, err)
	}
	l.deliver(t, request)
	l.answer(t, r, "completed")
	// expect: result == Success and inbox.
	assertRequestState(t, l.s, r, "REPLIED")
	var inbox bool
	if err := l.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM inbox_items WHERE ref_id=$1 AND kind='request_update' AND user_id=$2)",
		r, l.owners[l.a].ID).Scan(&inbox); err != nil || !inbox {
		t.Fatal("the outcome is not in a's owner's inbox:", inbox, err)
	}
}

// scenario24Test (service_progress_test.qnt): arrive(0), admit(0),
// complete(0), notify(0,true): b's reply reaches a. redeliverNotification(0):
// a is restored from an archive that lacks it; the reply is pending again,
// queued, the request still replied. notify(0,true): it reaches a again, on
// its first attempt.
func TestRestoredStoreGetsItsNotificationAgain(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.replied(t, "reply lost by a's restore")
	reply := mailboxFor(t, l.s, r, "reply")
	wantDecision(t, l.restore(t, l.a, reply)[reply], "queued", "")
	// expect: delivery == Pending, notificationQueue == List(0), result == Success.
	if m := l.mailbox(t, reply); m.State != "PENDING" || m.Attempts != 0 || !m.Outbox {
		t.Fatal("the reply is not pending again:", m)
	}
	assertRequestState(t, l.s, r, "REPLIED")
	if l.senderNotified(t, r) {
		t.Fatal("the lost reply still counts as received")
	}
	l.deliver(t, reply)
	// expect: delivery == Acked and attempts == 1.
	if m := l.mailbox(t, reply); m.State != "DELIVERED" || m.Attempts != 1 {
		t.Fatal("the reply did not reach a on one attempt:", m)
	}
	if !l.senderNotified(t, r) {
		t.Fatal("a is not notified")
	}
}

// scenario23x1Test (service_progress_test.qnt): a request delivered again
// after its recipient's restore still ends at its own deadline.
func TestRedeliveredRequestEndsAtItsDeadline(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.ask(t, "redelivered, then too late")
	request := mailboxFor(t, l.s, r, "request")
	l.deliver(t, request)
	wantDecision(t, l.restore(t, l.b, request)[request], "queued", "")
	assertRequestState(t, l.s, r, "DELIVERING")
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", r); err != nil {
		t.Fatal(err)
	}
	if err := l.s.RequestExpiration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := l.s.ReconcileRequestClosure(t.Context(), r, l.rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, l.s, r, "EXPIRED")
	if m := l.mailbox(t, request); m.State == "DELIVERED" || m.Outbox {
		t.Fatal("the expired request was still delivered or queued:", m)
	}
	sent := len(l.rt.sent)
	l.deliver(t, mailboxFor(t, l.s, r, "status"))
	if got := l.rt.sent[sent:]; len(got) != 1 || got[0] == request {
		t.Fatal("the sender was not told of the expiry, or the request went out:", got)
	}
}
