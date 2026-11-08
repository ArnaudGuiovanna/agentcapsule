package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func instructionLab(t *testing.T) (*Store, *AgentCatalog, *Transit, Principal, Principal, Enrollment) {
	t.Helper()
	s, a, base, admin, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, base, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	transit, err := NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x73}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.CheckKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("startup created a missing key registry", err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, err := NewAgentCatalogWithTransit(a, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, transit, admin, owner, e
}

func privateInstruction(text string) OwnerInstruction {
	return OwnerInstruction{Content: []TextContent{{Type: "text", Text: text}}}
}
func instructionRef(t *testing.T, s *Store, op string) string {
	t.Helper()
	var id string
	if err := s.pool.QueryRow(t.Context(), "SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1", op).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type acknowledgedInstructionFence struct{}

func (acknowledgedInstructionFence) Fence(context.Context, string, string) error { return nil }

func TestInstructionAtomicContentReceiptAndRevocation(t *testing.T) {
	s, c, transit, admin, owner, e := instructionLab(t)
	in := privateInstruction("private owner content 8a849f")
	r, err := c.Instruct(t.Context(), owner, e.AgentID, "message", in)
	op := acceptedOperation(t, r, err)
	ref := instructionRef(t, s, op.OperationID)
	plain, err := transit.ReadForOwner(t.Context(), owner, ref)
	want, _ := json.Marshal(in)
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatal("owner content unavailable", err)
	}
	var encrypted []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE id=$1", ref).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(in.Content[0].Text)) || bytes.Contains(r.Body, []byte(in.Content[0].Text)) {
		t.Fatal("private body persisted as public content")
	}
	var grants int
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM mandates WHERE agent_id=$1", e.AgentID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatal("HTTP admission minted a mandate")
	}
	if _, err = c.Instruct(t.Context(), admin, e.AgentID, "admin", in); !errors.Is(err, ErrForbidden) {
		t.Fatal("service issued owner instruction", err)
	}
	if _, err = transit.ReadForOwner(t.Context(), admin, ref); !errors.Is(err, ErrForbidden) {
		t.Fatal("service read private content", err)
	}
	otherUser := createAccount(t, c.accounts, admin, "other", "Marc")
	otherToken := issueAccountToken(t, c.accounts, admin, otherUser, "other-token")
	other, err := s.Authenticate(t.Context(), otherToken.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Instruct(t.Context(), other, e.AgentID, "foreign", in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign owner issued instruction", err)
	}
	if _, err = transit.ReadForOwner(t.Context(), other, ref); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign owner read content", err)
	}
	again, err := c.Instruct(t.Context(), owner, e.AgentID, "message", in)
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, r.Body) {
		t.Fatal("unstable instruction receipt", err)
	}
	if _, err = c.Instruct(t.Context(), owner, e.AgentID, "message", privateInstruction("changed")); !errors.Is(err, ErrConflict) {
		t.Fatal("idempotency conflict lost", err)
	}
	if count(t, s, "owner_instructions") != 1 || count(t, s, "transit_payloads") != 1 || count(t, s, "outbox") != 1 {
		t.Fatal("atomic instruction duplicated")
	}
	if _, err = c.InstructionResult(t.Context(), owner, op.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("pending operation exposed a result", err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err = transit.ReadForOwner(t.Context(), owner, ref); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleting party's content exposed", err)
	}
	if err = s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE id=$1", ref).Scan(&encrypted); err != nil || encrypted != nil {
		t.Fatal("deletion retained current ciphertext", err)
	}
	state, err := c.Operation(t.Context(), owner, op.OperationID)
	if err != nil || state.Status != "PENDING" {
		t.Fatal("instruction terminal before barrier", state, err)
	}
	again, err = c.Instruct(t.Context(), owner, e.AgentID, "message", in)
	if err != nil || !again.Replayed {
		t.Fatal("historical receipt lost", err)
	}
	if _, err = c.Instruct(t.Context(), owner, e.AgentID, "new", in); !errors.Is(err, ErrUnavailable) {
		t.Fatal("new content accepted during deletion", err)
	}
	// Explicit SQL barrier observation fixture; this does not execute a VM.
	if err = s.ReconcileRevocation(t.Context(), e.AgentID, acknowledgedInstructionFence{}); err != nil {
		t.Fatal(err)
	}
	state, err = c.Operation(t.Context(), owner, op.OperationID)
	if err != nil || state.Status != "CANCELED" {
		t.Fatal("instruction not canceled after barrier", state, err)
	}
	if _, err = s.HeadDelivery(t.Context(), e.AgentID); !errors.Is(err, ErrNoDelivery) {
		t.Fatal("canceled instruction retained queue head", err)
	}
}

func TestInstructionRollbackConcurrentReplayAndSharedSequence(t *testing.T) {
	s, c, _, _, owner, e := instructionLab(t)
	before := map[string]int{}
	for _, table := range []string{"platform_operations", "http_receipts", "transit_payloads", "owner_instructions", "outbox", "agent_mailboxes"} {
		before[table] = count(t, s, table)
	}
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_instruction_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$;
        CREATE TRIGGER reject_instruction BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_instruction_outbox()`)
	if err != nil {
		t.Fatal(err)
	}
	in := privateInstruction("committed only with the outbox")
	if _, err = c.Instruct(t.Context(), owner, e.AgentID, "once", in); err == nil {
		t.Fatal("failed outbox acknowledged")
	}
	for table, n := range before {
		if count(t, s, table) != n {
			t.Fatal("partial instruction committed", table)
		}
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_instruction ON outbox"); err != nil {
		t.Fatal(err)
	}
	results := make(chan APIReceipt, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				r, err := c.Instruct(t.Context(), owner, e.AgentID, "once", in)
				if errors.Is(err, ErrInProgress) {
					time.Sleep(time.Millisecond)
					continue
				}
				results <- r
				failures <- err
				return
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var original []byte
	for r := range results {
		if original == nil {
			original = r.Body
		}
		if !bytes.Equal(original, r.Body) {
			t.Fatal("concurrent receipt diverged")
		}
	}
	if count(t, s, "owner_instructions") != 1 || count(t, s, "transit_payloads") != 1 {
		t.Fatal("concurrent instruction duplicated")
	}
	var first string
	if err = s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE dest_agent_id=$1 AND seq=1", e.AgentID).Scan(&first); err != nil {
		t.Fatal("failed insertion consumed a sequence", err)
	}
	if _, err = c.Instruct(t.Context(), owner, e.AgentID, "second", in); err != nil {
		t.Fatal(err)
	}
	if head, err := s.HeadDelivery(t.Context(), e.AgentID); err != nil || head != first {
		t.Fatal("instruction skipped shared FIFO", head, err)
	}
	if _, err = s.ClaimDelivery(t.Context(), first, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatal("legacy dispatcher interpreted instruction as request", err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration cannot reopen instructions", err)
	}
}

func TestInstructionResultRequiresOwnerAndMatchingOperation(t *testing.T) {
	s, c, transit, admin, owner, e := instructionLab(t)
	r, err := c.Instruct(t.Context(), owner, e.AgentID, "input", privateInstruction("hello"))
	op := acceptedOperation(t, r, err)
	body := []byte(`{"content":[{"type":"text","text":"private response"}]}`)
	// The producer/ACK path is not exercised here: publish an explicit SQL
	// result fixture to test the independent owner read/retention boundary.
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	wrong, err := transit.put(t.Context(), tx, "instruction_result", "other-operation", []string{e.AgentID}, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "UPDATE owner_instructions SET result_payload_id=$2 WHERE operation_id=$1", op.OperationID, wrong.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1", op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	if _, err = c.InstructionResult(t.Context(), owner, op.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("different operation's result accepted", err)
	}
	tx, err = s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	valid, err := transit.put(t.Context(), tx, "instruction_result", op.OperationID, []string{e.AgentID}, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "UPDATE owner_instructions SET result_payload_id=$2 WHERE operation_id=$1", op.OperationID, valid.ID); err != nil {
		t.Fatal(err)
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	result, err := c.InstructionResult(t.Context(), owner, op.OperationID)
	if err != nil || !bytes.Equal(result, body) {
		t.Fatal("owner cannot read private result", err)
	}
	if _, err = c.InstructionResult(t.Context(), admin, op.OperationID); !errors.Is(err, ErrForbidden) {
		t.Fatal("administrative status access granted private result", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE id=$1", owner.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.InstructionResult(t.Context(), owner, op.OperationID); !errors.Is(err, ErrAuthentication) {
		t.Fatal("stale principal read private result", err)
	}
}
