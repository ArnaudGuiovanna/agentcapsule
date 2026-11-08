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

// This adapter uses real SQLite effects, but does not simulate a physical VM.
type instructionRuntime struct{ *vmruntime.MockRuntime }

func (r instructionRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.Send(ctx, target, e)
}
func instructionRuntimeLab(t *testing.T, target string) instructionRuntime {
	m := mockStores(t, t.TempDir(), "a", "b", "c", target)
	m.SetHandler(func(ctx context.Context, target string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		i, err := capsuleprotocol.DecodeInvocation(e, target)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS instruction_effects(id TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO instruction_effects VALUES(?)", e.ID); err != nil {
			return nil, err
		}
		return json.Marshal(OwnerInstruction{Content: i.Content})
	})
	return instructionRuntime{m}
}
func queueInstruction(t *testing.T, c *AgentCatalog, p Principal, target, key string) (string, string) {
	t.Helper()
	r, err := c.Instruct(t.Context(), p, target, key, privateInstruction("private instruction "+key))
	op := acceptedOperation(t, r, err)
	var id string
	if err = c.accounts.store.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op.OperationID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id, op.OperationID
}
func claimInstruction(t *testing.T, tr *Transit, id string) (InstructionAttempt, harnessstore.Event) {
	t.Helper()
	a, err := tr.ClaimInstruction(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e, err := tr.AuthorizeInstruction(t.Context(), id, a.Token)
	if err != nil {
		t.Fatal(err)
	}
	return a, e
}

func TestInstructionConcurrentClaimStableMandateLostACKAndFIFO(t *testing.T) {
	s, c, tr, admin, owner, e := instructionLab(t)
	first, op := queueInstruction(t, c, owner, e.AgentID, "one")
	second, _ := queueInstruction(t, c, owner, e.AgentID, "two")
	if _, err := tr.ClaimInstruction(t.Context(), second, time.Minute); !errors.Is(err, ErrNotHead) {
		t.Fatal("FIFO bypass", err)
	}
	type outcome struct {
		a   InstructionAttempt
		err error
	}
	results := make(chan outcome, 8)
	for range 8 {
		go func() { a, err := tr.ClaimInstruction(t.Context(), first, time.Minute); results <- outcome{a, err} }()
	}
	var a InstructionAttempt
	winners := 0
	for range 8 {
		r := <-results
		if r.err == nil {
			a = r.a
			winners++
		} else if !errors.Is(r.err, ErrDeliveryBusy) {
			t.Fatal(r.err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent owners", winners)
	}
	var grants int
	if err := s.pool.QueryRow(t.Context(), "SELECT count(*) FROM mandates WHERE agent_id=$1", e.AgentID).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("claim created grant", grants, err)
	}
	envelope, err := tr.AuthorizeInstruction(t.Context(), first, a.Token)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := capsuleprotocol.DecodeInvocation(envelope, e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	rt := instructionRuntimeLab(t, e.AgentID)
	r, err := rt.Invoke(t.Context(), e.AgentID, envelope)
	if err != nil || r.Replayed {
		t.Fatal(err)
	}
	// Model a consumed/revoked grant between retries: it must not be revived.
	if _, err = s.pool.Exec(t.Context(), "UPDATE mandates SET remaining=1,valid=false WHERE id=$1", inv.Mandate.ID); err != nil {
		t.Fatal(err)
	}
	expireLease(t, s, first)
	retry, err := tr.ClaimInstruction(t.Context(), first, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{a.Token, retry.Token} {
		if err = tr.AcknowledgeInstruction(t.Context(), first, token, r.Result); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("stale/unapproved ACK", err)
		}
	}
	again, err := tr.AuthorizeInstruction(t.Context(), first, retry.Token)
	if err != nil || !bytes.Equal(envelope.Body, again.Body) {
		t.Fatal("unstable invocation", err)
	}
	var valid bool
	var remaining int
	if err = s.pool.QueryRow(t.Context(), "SELECT valid,remaining FROM mandates WHERE id=$1", inv.Mandate.ID).Scan(&valid, &remaining); err != nil || valid || remaining != 1 {
		t.Fatal("grant replenished", err)
	}
	r, err = rt.Invoke(t.Context(), e.AgentID, again)
	if err != nil || !r.Replayed {
		t.Fatal("effect repeated", err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), first, retry.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	result, err := c.InstructionResult(t.Context(), owner, op)
	if err != nil || !bytes.Equal(result, r.Result) {
		t.Fatal("actual result not published", err)
	}
	if _, err = c.InstructionResult(t.Context(), admin, op); !errors.Is(err, ErrForbidden) {
		t.Fatal("admin private result", err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), first, retry.Token, []byte(`{"changed":true}`)); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("terminal result replaced", err)
	}
	if err = tr.DispatchMailbox(t.Context(), second, time.Minute, rt); err != nil {
		t.Fatal("next instruction", err)
	}
	if _, err = s.HeadDelivery(t.Context(), e.AgentID); !errors.Is(err, ErrNoDelivery) {
		t.Fatal("queue not empty", err)
	}
}

func TestInstructionACKRollbackAndKeyRotation(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	id, op := queueInstruction(t, c, owner, e.AgentID, "atomic")
	a, event := claimInstruction(t, tr, id)
	rt := instructionRuntimeLab(t, e.AgentID)
	receipt, err := rt.Invoke(t.Context(), e.AgentID, event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_instruction_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ack failure'; END $$;
        CREATE TRIGGER reject_ack BEFORE DELETE ON outbox FOR EACH ROW EXECUTE FUNCTION reject_instruction_ack()`); err != nil {
		t.Fatal(err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), id, a.Token, receipt.Result); err == nil {
		t.Fatal("partial result acknowledged")
	}
	if count(t, s, "transit_payloads") != 1 {
		t.Fatal("failed ACK retained ciphertext")
	}
	state, err := c.Operation(t.Context(), owner, op)
	if err != nil || state.Status != "RUNNING" {
		t.Fatal("terminal before commit", state, err)
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_ack ON outbox"); err != nil {
		t.Fatal(err)
	}
	rotated, err := NewTransit(s, "v2", map[string][]byte{"v1": bytes.Repeat([]byte{0x73}, 32), "v2": bytes.Repeat([]byte{0x74}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = rotated.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), id, a.Token, receipt.Result); !errors.Is(err, ErrTransitKey) {
		t.Fatal("stale encryptor published result", err)
	}
	expireLease(t, s, id)
	if err = rotated.DispatchMailbox(t.Context(), id, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	var key string
	if err = s.pool.QueryRow(t.Context(), "SELECT key_id FROM transit_payloads WHERE kind='instruction_result' AND ref_id=$1", op).Scan(&key); err != nil || key != "v2" {
		t.Fatal(key, err)
	}
	c, err = NewAgentCatalogWithTransit(c.accounts, "local", rotated)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.InstructionResult(t.Context(), owner, op)
	if err != nil || !bytes.Equal(got, receipt.Result) {
		t.Fatal("rotation changed durable result", err)
	}
}

type instructionFence struct {
	instructionRuntime
	before func() error
	fail   bool
}

func (f instructionFence) Fence(ctx context.Context, target, subject string) error {
	if f.before != nil {
		if err := f.before(); err != nil {
			return err
		}
	}
	if f.fail {
		return errors.New("lost fence ACK")
	}
	return f.instructionRuntime.Fence(ctx, target, subject)
}
func TestInstructionRetirementFencesDelayedEffectAndKeepsUnknownOutcome(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed", true: "lost_ack"}[applied], func(t *testing.T) {
			s, c, tr, _, owner, e := instructionLab(t)
			id, op := queueInstruction(t, c, owner, e.AgentID, "uncertain")
			next, _ := queueInstruction(t, c, owner, e.AgentID, "next")
			if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET attempt_limit=1 WHERE id=$1", id); err != nil {
				t.Fatal(err)
			}
			a, event := claimInstruction(t, tr, id)
			rt := instructionRuntimeLab(t, e.AgentID)
			if applied {
				if _, err := rt.Invoke(t.Context(), e.AgentID, event); err != nil {
					t.Fatal(err)
				}
			}
			expireLease(t, s, id)
			f := instructionFence{instructionRuntime: rt, fail: true, before: func() error {
				if err := tr.AcknowledgeInstruction(t.Context(), id, a.Token, []byte(`{}`)); !errors.Is(err, ErrLeaseLost) {
					t.Fatal("ACK crossed closing", err)
				}
				if _, err := tr.ClaimInstruction(t.Context(), next, time.Minute); !errors.Is(err, ErrNotHead) {
					t.Fatal("head advanced before barrier", err)
				}
				state, err := c.Operation(t.Context(), owner, op)
				if err != nil || state.Status != "RUNNING" {
					t.Fatal("early terminal outcome", state, err)
				}
				return nil
			}}
			if err := tr.DispatchMailbox(t.Context(), id, time.Minute, f); err == nil {
				t.Fatal("missing fence acknowledged")
			}
			f.fail = false
			if err := tr.DispatchMailbox(t.Context(), id, time.Minute, f); err != nil {
				t.Fatal(err)
			}
			if _, err := rt.Invoke(t.Context(), e.AgentID, event); !errors.Is(err, harnessstore.ErrFenced) {
				t.Fatal("late effect/replay after retirement", err)
			}
			state, err := c.Operation(t.Context(), owner, op)
			if err != nil || state.Status != "FAILED" || state.ErrorCode != "delivery_outcome_unknown" {
				t.Fatal(state, err)
			}
			inv, err := capsuleprotocol.DecodeInvocation(event, e.AgentID)
			if err != nil {
				t.Fatal(err)
			}
			var valid bool
			if err = s.pool.QueryRow(t.Context(), "SELECT valid FROM mandates WHERE id=$1", inv.Mandate.ID).Scan(&valid); err != nil || valid {
				t.Fatal("retired grant valid", err)
			}
			if err = tr.DispatchMailbox(t.Context(), next, time.Minute, rt); err != nil {
				t.Fatal("barrier did not release FIFO", err)
			}
		})
	}
}

func TestInstructionNeverAuthorizedAndDeletionRefuseResults(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	id, op := queueInstruction(t, c, owner, e.AgentID, "never")
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	rt := instructionRuntimeLab(t, e.AgentID)
	if err := tr.DispatchMailbox(t.Context(), id, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	state, err := c.Operation(t.Context(), owner, op)
	if err != nil || state.ErrorCode != "delivery_failed" {
		t.Fatal(state, err)
	}
	id, op = queueInstruction(t, c, owner, e.AgentID, "delete")
	a, event := claimInstruction(t, tr, id)
	receipt, err := rt.Invoke(t.Context(), e.AgentID, event)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), id, a.Token, receipt.Result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("result published after deletion intent", err)
	}
	if err = s.ReconcileRevocation(t.Context(), e.AgentID, rt); err != nil {
		t.Fatal(err)
	}
	state, err = c.Operation(t.Context(), owner, op)
	if err != nil || state.Status != "CANCELED" {
		t.Fatal(state, err)
	}
	if _, err = c.InstructionResult(t.Context(), owner, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted content exposed", err)
	}
}

func TestInstructionResultAndRetirementRaceHasOneTerminalOutcome(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	rt := instructionRuntimeLab(t, e.AgentID)
	for _, key := range []string{"race1", "race2", "race3", "race4", "race5", "race6"} {
		id, op := queueInstruction(t, c, owner, e.AgentID, key)
		a, event := claimInstruction(t, tr, id)
		r, err := rt.Invoke(t.Context(), e.AgentID, event)
		if err != nil {
			t.Fatal(err)
		}
		// Expiry allows retirement while the active lease may still ACK. The
		// shared agent lock must serialize publication against beginning closure.
		if _, err = s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		ack := make(chan error, 1)
		fence := make(chan error, 1)
		go func() { <-start; ack <- tr.AcknowledgeInstruction(t.Context(), id, a.Token, r.Result) }()
		go func() { <-start; fence <- tr.RetireInstruction(t.Context(), id, rt) }()
		close(start)
		ackErr, fenceErr := <-ack, <-fence
		if fenceErr != nil {
			t.Fatal(fenceErr)
		}
		state, err := c.Operation(t.Context(), owner, op)
		if err != nil {
			t.Fatal(err)
		}
		switch state.Status {
		case "SUCCEEDED":
			if ackErr != nil {
				t.Fatal("success without ACK commit", ackErr)
			}
			got, err := c.InstructionResult(t.Context(), owner, op)
			if err != nil || !bytes.Equal(got, r.Result) {
				t.Fatal("lost committed result", err)
			}
		case "FAILED":
			if !errors.Is(ackErr, ErrLeaseLost) {
				t.Fatal("retirement allowed result commit", ackErr)
			}
			if _, err = c.InstructionResult(t.Context(), owner, op); !errors.Is(err, ErrNotFound) {
				t.Fatal("failed operation exposed result", err)
			}
		default:
			t.Fatal("nonterminal race", state)
		}
	}
}
