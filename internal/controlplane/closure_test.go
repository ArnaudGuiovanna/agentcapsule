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
