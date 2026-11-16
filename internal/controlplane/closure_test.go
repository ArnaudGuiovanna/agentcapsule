package controlplane

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func closureTargets(t *testing.T, s *Store, requestID string) []string {
	t.Helper()
	rows, err := s.pool.Query(t.Context(), "SELECT store_agent_id FROM request_closure_targets WHERE request_id=$1 ORDER BY store_agent_id", requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err = rows.Scan(&target); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return targets
}

// A request's closure fences the stores of its two parties, and no other: an
// event that carries the request goes only to them, so no other store can
// hold an effect of it. An agent that never boots and is not a party holds
// neither its expiry nor its cancellation (ADR 007, P1 closedSafe).
func TestRequestClosureFencesOnlyItsParties(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	// c's store is unavailable: c never boots, and no fence reaches it.
	m := mockStores(t, t.TempDir(), "a", "b")
	m.SetHandler(recordDelivery)
	expiring, err := s.Submit(t.Context(), "a", "expiring", submission())
	if err != nil {
		t.Fatal(err)
	}
	// A send to b that may still be under way when the request expires.
	id := mailboxFor(t, s, expiring.RequestID, "request")
	attempt, err := s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AuthorizeDispatch(t.Context(), id, attempt.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", expiring.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.RequestExpiration(t.Context(), expiring.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRequestClosure(t.Context(), expiring.RequestID, m); err != nil {
		t.Fatal("the closure waits for a store that is not a party:", err)
	}
	assertRequestState(t, s, expiring.RequestID, "EXPIRED")
	if got := closureTargets(t, s, expiring.RequestID); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatal("closure targets", got)
	}
	// The send under way is refused by the recipient's fence.
	if _, err = m.Send(t.Context(), "b", attempt.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("a delayed request reached its recipient after its expiry", err)
	}

	canceled, err := s.Submit(t.Context(), "a", "canceled", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(t.Context(), "user-a", canceled.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRequestClosure(t.Context(), canceled.RequestID, m); err != nil {
		t.Fatal("the cancellation waits for a store that is not a party:", err)
	}
	assertRequestState(t, s, canceled.RequestID, "CANCELED")
}

// The private content of a request closed before it was delivered gets the
// retention of a delivered request's content, from its closure, then is
// purged: refused by its recipient's owner, canceled by its sender, or
// expired (docs/api/README.md). Default pending the product owner (ADR 007).
func TestRequestClosedBeforeDeliveryIsPurged(t *testing.T) {
	s, _ := freshStore(t, "manual", 5)
	tr := peerTransit(t, s)
	a := confirmedCaller(t, s, "a")
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	payload := func(request string) (deadline *time.Time, purged bool) {
		t.Helper()
		if err := s.pool.QueryRow(t.Context(), `SELECT p.purge_after,p.purged_at IS NOT NULL FROM transit_payloads p
            JOIN agent_requests r ON r.payload_ref=p.id WHERE r.id=$1`, request).Scan(&deadline, &purged); err != nil {
			t.Fatal(err)
		}
		return deadline, purged
	}
	var closed []string
	for _, end := range []string{"declined", "canceled", "expired"} {
		r, err := tr.SubmitFromVM(t.Context(), a, end, peerSubmission("a private question"))
		if err != nil {
			t.Fatal(err)
		}
		switch end {
		case "declined":
			_, err = s.DeclineRequest(t.Context(), "user-b", r.RequestID, "decline")
		case "canceled":
			if err = s.RequestCancellation(t.Context(), "user-a", r.RequestID); err == nil {
				err = s.ReconcileRequestClosure(t.Context(), r.RequestID, m)
			}
		case "expired":
			if _, err = s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", r.RequestID); err != nil {
				t.Fatal(err)
			}
			if err = s.RequestExpiration(t.Context(), r.RequestID); err == nil {
				err = s.ReconcileRequestClosure(t.Context(), r.RequestID, m)
			}
		}
		if err != nil {
			t.Fatal(end, err)
		}
		closed = append(closed, r.RequestID)
	}
	// A request still waiting for consent keeps its content, with no deadline.
	waiting, err := tr.SubmitFromVM(t.Context(), a, "waiting", peerSubmission("a pending question"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tr.PurgeExpired(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	for _, id := range closed {
		deadline, purged := payload(id)
		if deadline == nil || purged || time.Until(*deadline) < 7*24*time.Hour-time.Minute || time.Until(*deadline) > 7*24*time.Hour {
			t.Fatalf("content of request %s closed before delivery: purge deadline %v, purged %v; want 7 days from its closure", id, deadline, purged)
		}
	}
	if deadline, purged := payload(waiting.RequestID); deadline != nil || purged {
		t.Fatal("a request waiting for consent lost its content", deadline, purged)
	}
	if _, err = s.pool.Exec(t.Context(), `UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second' WHERE purge_after IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.PurgeExpired(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	for _, id := range closed {
		if _, purged := payload(id); !purged {
			t.Fatalf("content of request %s outlived its retention", id)
		}
	}
}
