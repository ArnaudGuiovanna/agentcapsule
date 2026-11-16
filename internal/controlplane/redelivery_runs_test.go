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
