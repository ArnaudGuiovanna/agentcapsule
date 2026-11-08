package controlplane

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func messageCaller(t *testing.T, s *Store, e Enrollment) VMCaller {
	t.Helper()
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: vm}
}
func TestOwnerMessageAtomicReceiptContentAndBootAuthority(t *testing.T) {
	s, c, tr, admin, owner, e := instructionLab(t)
	caller := messageCaller(t, s, e)
	in := capsuleprotocol.OwnerPost{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "confidential summary 985c05"}}}
	before := map[string]int{}
	for _, table := range []string{"owner_messages", "transit_payloads", "inbox_items", "mandates"} {
		before[table] = count(t, s, table)
	}
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_owner_notification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected notification failure'; END $$;
        CREATE TRIGGER reject_owner_notification BEFORE INSERT ON inbox_items FOR EACH ROW EXECUTE FUNCTION reject_owner_notification()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tr.PostOwnerFromVM(t.Context(), caller, "once", in); err == nil {
		t.Fatal("partial publication acknowledged")
	}
	for table, n := range before {
		if count(t, s, table) != n {
			t.Fatal("partial owner message", table)
		}
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_owner_notification ON inbox_items"); err != nil {
		t.Fatal(err)
	}
	results := make(chan capsuleprotocol.OwnerPostReceipt, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := tr.PostOwnerFromVM(t.Context(), caller, "once", in)
			if err != nil {
				failures <- err
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	id := ""
	fresh := 0
	for r := range results {
		if id != "" && id != r.MessageID {
			t.Fatal("different replay IDs")
		}
		id = r.MessageID
		if !r.Replayed {
			fresh++
		}
	}
	if id == "" || fresh != 1 || count(t, s, "owner_messages") != 1 || count(t, s, "inbox_items") != 1 || count(t, s, "mandates") != before["mandates"] {
		t.Fatal("duplicate notification or new authority")
	}
	changed := capsuleprotocol.OwnerPost{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "changed"}}}
	if _, err = tr.PostOwnerFromVM(t.Context(), caller, "once", changed); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	var payload string
	var ciphertext []byte
	if err = s.pool.QueryRow(t.Context(), `SELECT m.payload_id,p.ciphertext FROM owner_messages m JOIN transit_payloads p ON p.id=m.payload_id WHERE m.id=$1`, id).Scan(&payload, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(in.Content[0].Text)) {
		t.Fatal("plaintext persisted")
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE owner_messages SET owner_user_id='foreign' WHERE id=$1", id); err == nil {
		t.Fatal("owner summary rebound")
	}
	if _, err = s.pool.Exec(t.Context(), "DELETE FROM owner_messages WHERE id=$1", id); err == nil {
		t.Fatal("stable receipt deleted")
	}
	var delivered *time.Time
	if err = s.pool.QueryRow(t.Context(), "SELECT delivered_at FROM transit_payloads WHERE id=$1", payload).Scan(&delivered); err != nil || delivered != nil {
		t.Fatal("publication mistaken for owner read", err)
	}
	if _, err = c.OwnerMessage(t.Context(), admin, id); !errors.Is(err, ErrForbidden) {
		t.Fatal("admin read summary", err)
	}
	view, err := c.OwnerMessage(t.Context(), owner, id)
	if err != nil || view.Content[0].Text != in.Content[0].Text {
		t.Fatal("owner read", err)
	}
	var deadline, timeAgain time.Time
	if err = s.pool.QueryRow(t.Context(), "SELECT purge_after FROM transit_payloads WHERE id=$1", payload).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration with owner notifications", err)
	}
	if _, err = c.OwnerMessage(t.Context(), owner, id); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(t.Context(), "SELECT purge_after FROM transit_payloads WHERE id=$1", payload).Scan(&timeAgain); err != nil || !timeAgain.Equal(deadline) {
		t.Fatal("read reset retention", err)
	}
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, caller.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, caller.Generation, false); err != nil {
		t.Fatal(err)
	}
	current := messageCaller(t, s, e)
	if _, err = tr.PostOwnerFromVM(t.Context(), caller, "once", in); !errors.Is(err, ErrPlacement) {
		t.Fatal("stale boot replay", err)
	}
	if r, err := tr.PostOwnerFromVM(t.Context(), current, "once", in); err != nil || !r.Replayed || r.MessageID != id {
		t.Fatal("current boot lost receipt", err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.OwnerMessage(t.Context(), owner, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted content readable", err)
	}
	if _, err = tr.PostOwnerFromVM(t.Context(), current, "once", in); !errors.Is(err, ErrPlacement) {
		t.Fatal("deleted caller replay", err)
	}
}

func TestLinkedOwnerSummaryRequiresCompletedOutgoingRequest(t *testing.T) {
	s, _, _, _, request := processingRequest(t, "auto")
	tr := peerTransit(t, s)
	a, b := confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b")
	in := capsuleprotocol.OwnerPost{RequestID: request.RequestID, Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private linked summary"}}}
	if _, err := tr.PostOwnerFromVM(t.Context(), b, "wrong-side", in); !errors.Is(err, ErrNotFound) {
		t.Fatal("recipient supplied sender summary", err)
	}
	if _, err := tr.PostOwnerFromVM(t.Context(), a, "early", in); !errors.Is(err, ErrTransition) {
		t.Fatal("summary before response", err)
	}
	if _, err := s.ReplyToRequest(t.Context(), "b", request.RequestID, "reply", completedReply()); err != nil {
		t.Fatal(err)
	}
	r, err := tr.PostOwnerFromVM(t.Context(), a, "summary", in)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.pool.QueryRow(t.Context(), `SELECT count(*) FROM transit_parties p JOIN owner_messages m ON m.payload_id=p.payload_id WHERE m.id=$1`, r.MessageID).Scan(&n); err != nil || n != 2 {
		t.Fatal("peer revocation binding missing", n, err)
	}
	if err = s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.PostOwnerFromVM(t.Context(), a, "new-after-delete", in); !errors.Is(err, ErrUnavailable) {
		t.Fatal("recreated revoked summary", err)
	}
	if replay, err := tr.PostOwnerFromVM(t.Context(), a, "summary", in); err != nil || !replay.Replayed || replay.MessageID != r.MessageID {
		t.Fatal("historical receipt lost", err)
	}
	var purged bool
	if err = s.pool.QueryRow(t.Context(), `SELECT p.ciphertext IS NULL FROM transit_payloads p JOIN owner_messages m ON m.payload_id=p.id WHERE m.id=$1`, r.MessageID).Scan(&purged); err != nil || !purged {
		t.Fatal("replay recreated ciphertext", err)
	}
}
