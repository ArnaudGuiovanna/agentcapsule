package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func TestOwnerDeletionReceiptRollbackConcurrencyAndHonestProgress(t *testing.T) {
	s, c, _, admin, owner, e := instructionLab(t)
	r, err := c.Instruct(t.Context(), owner, e.AgentID, "instruction", privateInstruction("erase this private content"))
	instruction := acceptedOperation(t, r, err)
	r, err = c.RequestLifecycle(t.Context(), owner, e.AgentID, "wake", "wake")
	wake := acceptedOperation(t, r, err)
	before := map[string]int{}
	for _, table := range []string{"platform_operations", "deletion_operations", "deletion_targets", "revocation_catalogue", "http_receipts"} {
		before[table] = count(t, s, table)
	}
	_, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_delete_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.method='DELETE' THEN RAISE EXCEPTION 'injected receipt failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_delete_receipt BEFORE INSERT ON http_receipts FOR EACH ROW EXECUTE FUNCTION reject_delete_receipt()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Delete(t.Context(), owner, e.AgentID, "delete"); err == nil {
		t.Fatal("failed receipt acknowledged deletion")
	}
	for table, n := range before {
		if count(t, s, table) != n {
			t.Fatal("partial deletion", table)
		}
	}
	if _, err = c.InstructionResult(t.Context(), owner, instruction.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("unfinished instruction exposed", err)
	}
	if _, err = c.transit.ReadForOwner(t.Context(), owner, instructionRef(t, s, instruction.OperationID)); err != nil {
		t.Fatal("failed delete purged content", err)
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_delete_receipt ON http_receipts"); err != nil {
		t.Fatal(err)
	}
	results := make(chan APIReceipt, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := owner
			if i%2 == 1 {
				p = admin
			}
			r, err := c.Delete(t.Context(), p, e.AgentID, fmt.Sprintf("delete-%d", i))
			if err != nil {
				failures <- err
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	id := ""
	for r := range results {
		var accepted AgentCreation
		if r.Status != 202 || json.Unmarshal(r.Body, &accepted) != nil {
			t.Fatal("invalid delete receipt")
		}
		if id != "" && id != accepted.OperationID {
			t.Fatal("multiple deletion operations")
		}
		id = accepted.OperationID
	}
	if count(t, s, "deletion_operations") != 1 || count(t, s, "platform_operations") != before["platform_operations"]+1 {
		t.Fatal("deletion not coalesced")
	}
	if _, err = c.transit.ReadForOwner(t.Context(), owner, instructionRef(t, s, instruction.OperationID)); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete retained transit", err)
	}
	assertOp := func(op, status, phase string) {
		t.Helper()
		v, err := c.Operation(t.Context(), owner, op)
		if err != nil || v.Status != status || v.DeletionPhase != phase {
			t.Fatal("operation progress", v, err)
		}
	}
	assertOp(id, "PENDING", "FENCING")
	assertOp(wake.OperationID, "CANCELED", "")
	assertOp(instruction.OperationID, "PENDING", "")
	// The shared database fixture already contains a, b and c. Every enrolled
	// store must participate in the deletion census, not just the new subject.
	m := mockStores(t, t.TempDir(), "a", "b", "c", e.AgentID)
	lost := true
	m.SetFenceHook(func(stage, target, subject string) error {
		if stage == "after_commit" && lost {
			lost = false
			return capsuleprotocol.ErrTransport
		}
		return nil
	})
	if err = s.ReconcileRevocation(t.Context(), e.AgentID, m); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal(err)
	}
	assertOp(id, "RUNNING", "FENCING")
	assertOp(instruction.OperationID, "PENDING", "")
	m.SetFenceHook(nil)
	if err = s.ReconcileRevocation(t.Context(), e.AgentID, m); err != nil {
		t.Fatal(err)
	}
	assertOp(id, "RUNNING", "RETIRING")
	assertOp(instruction.OperationID, "CANCELED", "")
	// Explicit physical-observation fixture: this checks only SQL publication
	// and must not turn the execution seal into a key/volume destruction claim.
	p, _, err := s.StoreSealTarget(t.Context(), e.AgentID, e.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordStoreSeal(t.Context(), StoreSeal{AgentID: e.AgentID, HostID: e.HostID, ID: strings.Repeat("1", 32), Generation: p.Generation, Device: 1, Inode: 100}); err != nil {
		t.Fatal(err)
	}
	assertOp(id, "RUNNING", "CLEANUP_PENDING")
	if v, err := c.Get(t.Context(), owner, e.AgentID); err != nil || v.State != "DELETING" {
		t.Fatal("seal advertised deleted", v.State, err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err = c.Delete(t.Context(), owner, e.AgentID, "delete-0")
	if err != nil || !r.Replayed {
		t.Fatal("delete replay after barrier", err)
	}
}
