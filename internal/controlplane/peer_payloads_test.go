package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func peerTransit(t *testing.T, s *Store) *Transit {
	t.Helper()
	tr, err := NewTransit(s, "test", map[string][]byte{"test": bytes.Repeat([]byte{0x61}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	return tr
}
func peerSubmission(text string) capsuleprotocol.Submission {
	return capsuleprotocol.Submission{RecipientAgentID: "b", MandateID: "mandate-a", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), Subject: "Private subject", CorrelationID: "mission-one", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}}}
}

type peerRuntime struct {
	*vmruntime.MockRuntime
	lost   bool
	events []harnessstore.Event
}

func (r *peerRuntime) Invoke(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, errors.New("peer event must never invoke owner instruction")
}
func (r *peerRuntime) Send(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	r.events = append(r.events, harnessstore.Event{ID: event.ID, Subjects: append([]string{}, event.Subjects...), Body: bytes.Clone(event.Body)})
	receipt, err := r.MockRuntime.Send(ctx, target, event)
	if err == nil && r.lost {
		r.lost = false
		return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
	}
	return receipt, err
}
func peerRuntimeLab(t *testing.T) *peerRuntime {
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if _, err := capsuleprotocol.DecodePeerEvent(event, target); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS peer_effects(id TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO peer_effects VALUES(?)", event.ID)
		return []byte(`{"received":true}`), err
	})
	return &peerRuntime{MockRuntime: m}
}

func TestPrivatePeerRequestConsentDeliveryAndReply(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	tr := peerTransit(t, s)
	a := confirmedCaller(t, s, "a")
	b := confirmedCaller(t, s, "b")
	in := peerSubmission("only the intended parties may read this request")
	r, err := tr.SubmitFromVM(t.Context(), a, "request", in)
	if err != nil || r.State != PendingApproval {
		t.Fatal(r, err)
	}
	if count(t, s, "transit_payloads") != 1 || count(t, s, "agent_mailboxes") != 0 || remaining(t, s, "mandate-a") != 2 {
		t.Fatal("private request admission not atomic/consented")
	}
	var ciphertext []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE ref_id=$1", r.RequestID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte(in.Subject)) || bytes.Contains(ciphertext, []byte(in.Payload.Content[0].Text)) {
		t.Fatal("plaintext persisted", err)
	}
	for range 4 {
		again, err := tr.SubmitFromVM(t.Context(), a, "request", in)
		if err != nil || !again.Replayed || again.RequestID != r.RequestID {
			t.Fatal("private replay", again, err)
		}
	}
	changed := in
	changed.Subject = "changed subject"
	if _, err = tr.SubmitFromVM(t.Context(), a, "request", changed); !errors.Is(err, ErrConflict) {
		t.Fatal("content omitted from replay identity", err)
	}
	forged := in
	forged.RecipientAgentID = "c"
	if _, err = tr.SubmitFromVM(t.Context(), b, "forged", forged); !errors.Is(err, ErrMandate) {
		t.Fatal("foreign mandate accepted", err)
	}
	if _, err = s.Accept(t.Context(), "user-a", r.RequestID, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatal("sender supplied recipient consent", err)
	}
	if _, err = s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil {
		t.Fatal(err)
	}
	mailbox := mailboxFor(t, s, r.RequestID, "request")
	rt := peerRuntimeLab(t)
	rt.lost = true
	if err = tr.DispatchMailbox(t.Context(), mailbox, time.Minute, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("lost request ACK", err)
	}
	assertRequestState(t, s, r.RequestID, "DELIVERING")
	expireLease(t, s, mailbox)
	if err = tr.DispatchMailbox(t.Context(), mailbox, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if len(rt.events) != 2 || !bytes.Equal(rt.events[0].Body, rt.events[1].Body) {
		t.Fatal("replayed peer envelope changed")
	}
	delivered, err := capsuleprotocol.DecodePeerEvent(rt.events[1], "b")
	if err != nil || delivered.Payload.Content[0].Text != in.Payload.Content[0].Text || delivered.Subject != in.Subject || delivered.CorrelationID != in.CorrelationID {
		t.Fatal("private delivery mismatch", err)
	}
	assertRequestState(t, s, r.RequestID, "PROCESSING")
	if count(t, s, "mandates") != 3 {
		t.Fatal("received peer event minted mandate")
	}
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private answer"}}}}
	if _, err = tr.ReplyFromVM(t.Context(), a, r.RequestID, "reply", answer); !errors.Is(err, ErrNotFound) {
		t.Fatal("sender impersonated replier", err)
	}
	if _, err = tr.ReplyFromVM(t.Context(), b, r.RequestID, "reply", answer); err != nil {
		t.Fatal(err)
	}
	if again, err := tr.ReplyFromVM(t.Context(), b, r.RequestID, "reply", answer); err != nil || !again.Replayed {
		t.Fatal("reply replay", err)
	}
	if _, err = tr.ReplyFromVM(t.Context(), b, r.RequestID, "another-reply", answer); !errors.Is(err, ErrTransition) {
		t.Fatal("second terminal reply", err)
	}
	if err = tr.DispatchMailbox(t.Context(), mailboxFor(t, s, r.RequestID, "reply"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	response, err := capsuleprotocol.DecodePeerEvent(rt.events[2], "a")
	if err != nil || response.Kind != "reply" || response.Payload.Content[0].Text != "private answer" {
		t.Fatal("reply private content", err)
	}
	var deliveredPayloads int
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM transit_payloads WHERE delivered_at IS NOT NULL AND purge_after IS NOT NULL").Scan(&deliveredPayloads); err != nil || deliveredPayloads != 2 {
		t.Fatal("delivery did not begin retention", err)
	}
	if remaining(t, s, "mandate-a") != 2 || count(t, s, "transit_payloads") != 2 {
		t.Fatal("replay consumed grant or duplicated private content")
	}
}

func TestPrivatePeerAtomicRollbackAndCurrentBootReplay(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	tr := peerTransit(t, s)
	a := confirmedCaller(t, s, "a")
	in := peerSubmission("atomic content")
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_private_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$;
        CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_private_outbox()`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.SubmitFromVM(t.Context(), a, "atomic", in); err == nil {
		t.Fatal("partial private admission acknowledged")
	}
	if count(t, s, "transit_payloads") != 0 || count(t, s, "agent_requests") != 0 || remaining(t, s, "mandate-a") != 3 {
		t.Fatal("private rollback leaked state")
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_outbox ON outbox"); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		r   Receipt
		err error
	}
	results := make(chan outcome, 8)
	for range 8 {
		go func() { r, err := tr.SubmitFromVM(t.Context(), a, "atomic", in); results <- outcome{r, err} }()
	}
	id := ""
	for range 8 {
		o := <-results
		if o.err != nil {
			t.Fatal(o.err)
		}
		if id == "" {
			id = o.r.RequestID
		}
		if o.r.RequestID != id {
			t.Fatal("concurrent content duplicated")
		}
	}
	if count(t, s, "transit_payloads") != 1 || remaining(t, s, "mandate-a") != 2 {
		t.Fatal("concurrent grant consumption")
	}
	if err := s.BeginPlacementStop(t.Context(), "a", "host", a.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.ObservePlacementStopped(t.Context(), "a", "host", a.Generation, false); err != nil {
		t.Fatal(err)
	}
	current := confirmedCaller(t, s, "a")
	if _, err := tr.SubmitFromVM(t.Context(), a, "atomic", in); !errors.Is(err, ErrPlacement) {
		t.Fatal("stale private replay", err)
	}
	if r, err := tr.SubmitFromVM(t.Context(), current, "atomic", in); err != nil || !r.Replayed || r.RequestID != id {
		t.Fatal(r, err)
	}
	if err := s.RevokeMandate(t.Context(), "user-a", in.MandateID); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.SubmitFromVM(t.Context(), current, "new", in); !errors.Is(err, ErrMandate) {
		t.Fatal("revoked grant", err)
	}
	if r, err := tr.SubmitFromVM(t.Context(), current, "atomic", in); err != nil || !r.Replayed {
		t.Fatal("already committed receipt lost after revoke", err)
	}
}

func TestPrivateDeliveryRequiresPermissionAndAuthenticCiphertext(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	tr := peerTransit(t, s)
	a := confirmedCaller(t, s, "a")
	r, err := tr.SubmitFromVM(t.Context(), a, "one", peerSubmission("sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	id := mailboxFor(t, s, r.RequestID, "request")
	attempt, err := s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tr.resolveDelivery(t.Context(), attempt); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("plaintext before permission", err)
	}
	if err = s.AuthorizeDispatch(t.Context(), id, attempt.Token); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE ref_id=$1", r.RequestID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corrupted := bytes.Clone(original)
	corrupted[len(corrupted)-1] ^= 1
	if _, err = s.pool.Exec(t.Context(), "UPDATE transit_payloads SET ciphertext=$2 WHERE ref_id=$1", r.RequestID, corrupted); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.resolveDelivery(t.Context(), attempt); !errors.Is(err, ErrTransitPayload) {
		t.Fatal("unauthenticated content returned", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE transit_payloads SET ciphertext=$2 WHERE ref_id=$1", r.RequestID, original); err != nil {
		t.Fatal(err)
	}
	if event, err := tr.resolveDelivery(t.Context(), attempt); err != nil {
		t.Fatal(err)
	} else {
		clear(event.Body)
	}
	expireLease(t, s, id)
	if _, err = tr.resolveDelivery(t.Context(), attempt); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale worker decrypted content", err)
	}
	if err = s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.resolveDelivery(t.Context(), attempt); err == nil {
		t.Fatal("deleting party private content returned")
	}
	var remainingContent int
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM transit_payloads WHERE ciphertext IS NOT NULL").Scan(&remainingContent); err != nil || remainingContent != 0 {
		t.Fatal("deletion retained private peer content", err)
	}
}

func TestPeerEnvelopeCannotCarryOwnerAuthority(t *testing.T) {
	body, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "request", RequestID: "r", SenderAgentID: "a", RecipientAgentID: "b", Sequence: 1, Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "untrusted instruction"}}}})
	event := harnessstore.Event{ID: "e", Subjects: []string{"agent/a", "agent/b", "request/r", "event/e"}, Body: body}
	if _, err := capsuleprotocol.DecodePeerEvent(event, "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := capsuleprotocol.DecodeInvocation(event, "b"); err == nil {
		t.Fatal("peer content became owner authority")
	}
	event.Body = append(body[:len(body)-1], []byte(`,"mandate":{"id":"forged","max_agent_requests":3}}`)...)
	if _, err := capsuleprotocol.DecodePeerEvent(event, "b"); err == nil {
		t.Fatal("peer supplied a mandate")
	}
}
