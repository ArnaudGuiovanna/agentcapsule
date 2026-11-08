package controlplane

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// ackWorking delivers the invocation and has the agent answer "working".
func (il *invocationLab) ackWorking(t *testing.T, op string) string {
	t.Helper()
	var mbx string
	if err := il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	attempt, _ := claimInstruction(t, il.tr, mbx)
	if err := il.tr.AcknowledgeInstruction(t.Context(), mbx, attempt.Token, capsuleprotocol.WorkingResult()); err != nil {
		t.Fatal("working acknowledgment", err)
	}
	return mbx
}

func (il *invocationLab) vm(t *testing.T) VMCaller {
	t.Helper()
	gen := il.run(t)
	return VMCaller{AgentID: il.agent, HostID: "local", VMID: fmt.Sprintf("%016x", gen), Generation: gen}
}

func answer(op, text string) capsuleprotocol.InvocationCompletion {
	return capsuleprotocol.InvocationCompletion{OperationID: op, Outcome: "completed", Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}}
}

func TestWorkingInvocationIsCompletedLaterExactlyOnce(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	first, _, err := il.create(t, alice, "w1", "summarize")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := il.create(t, alice, "w2", "next")
	if err != nil {
		t.Fatal(err)
	}
	mbx := il.ackWorking(t, first.ID)
	// Delivery is final: the next instruction is at the head of the FIFO.
	if il.count(t, "SELECT count(*) FROM agent_mailboxes WHERE id=$1 AND delivery_state='DELIVERED'", mbx) != 1 {
		t.Fatal("a working acknowledgment did not end the delivery")
	}
	var next string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", second.ID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ClaimInstruction(t.Context(), next, time.Minute); err != nil {
		t.Fatal("FIFO blocked by a working invocation", err)
	}
	got := mustGet(t, il, alice, first.ID)
	if got.State != "working" || got.ResultAvailable || got.ResultDueAt == nil || time.Until(*got.ResultDueAt) < 50*time.Minute {
		t.Fatal("working invocation view", got)
	}
	if _, err = il.c.InstructionResult(t.Context(), alice, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("a working invocation already has a result", err)
	}

	// Only the destination's current boot may post, and only a well-formed outcome.
	stale := vm
	stale.Generation++
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), stale, "done", answer(first.ID, "x")); !errors.Is(err, ErrPlacement) {
		t.Fatal("a stale boot completed it", err)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer("op-unknown", "x")); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown operation", err)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", capsuleprotocol.InvocationCompletion{OperationID: first.ID, Outcome: "completed"}); !errors.Is(err, ErrInput) {
		t.Fatal("empty answer accepted", err)
	}
	// Second instruction is being delivered, not working: it cannot be completed this way.
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "early", answer(second.ID, "x")); !errors.Is(err, ErrTransition) {
		t.Fatal("an undelivered invocation was completed", err)
	}

	r, err := il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(first.ID, "the summary"))
	if err != nil || r.State != "completed" || r.Replayed {
		t.Fatal("completion", r, err)
	}
	again, err := il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(first.ID, "the summary"))
	if err != nil || !again.Replayed {
		t.Fatal("same key and body must replay", again, err)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(first.ID, "another summary")); !errors.Is(err, ErrConflict) {
		t.Fatal("same key, other answer", err)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "other", answer(first.ID, "the summary")); !errors.Is(err, ErrConflict) {
		t.Fatal("a second completion was accepted", err)
	}
	if v := mustGet(t, il, alice, first.ID); v.State != "completed" || !v.ResultAvailable {
		t.Fatal("completed view", v)
	}
	result, err := il.c.InstructionResult(t.Context(), alice, first.ID)
	if err != nil || !strings.Contains(string(result), "the summary") {
		t.Fatal("requester cannot read the later result", err)
	}
	// Bound to the requester as any result: another member never reads it.
	carol := il.invoker(t, "carol")
	if _, err = il.c.InstructionResult(t.Context(), carol, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member read the result", err)
	}
}

func TestWorkingInvocationTimesOutIsCanceledOrDiesWithItsAgent(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	if r, err := il.c.CreateInvocation(t.Context(), alice, il.agent, "bad", InvocationInput{OwnerInstruction: privateInstruction("x"), WorkTimeoutSeconds: 30}); err == nil {
		t.Fatal("work timeout below a minute accepted", r)
	}
	r, err := il.c.CreateInvocation(t.Context(), alice, il.agent, "slow", InvocationInput{OwnerInstruction: privateInstruction("slow"), WorkTimeoutSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	slow := decodeInvocation(t, r)
	il.ackWorking(t, slow.ID)
	if v := mustGet(t, il, alice, slow.ID); v.ResultDueAt == nil || time.Until(*v.ResultDueAt) > 3*time.Minute {
		t.Fatal("work timeout not applied", v)
	}
	// Not due yet: nothing expires.
	if n, err := il.s.ExpireWorkingInvocations(t.Context(), nil, 10); err != nil || n != 0 {
		t.Fatal("expired early", n, err)
	}
	later := time.Now().Add(3 * time.Minute)
	if n, err := il.s.ExpireWorkingInvocations(t.Context(), &later, 10); err != nil || n != 1 {
		t.Fatal("not expired", n, err)
	}
	if v := mustGet(t, il, alice, slow.ID); v.State != "failed" || v.ErrorCode != "work_timeout" {
		t.Fatal("expired view", v)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "late", answer(slow.ID, "too late")); !errors.Is(err, ErrExpired) {
		t.Fatal("a late outcome was accepted", err)
	}

	// The requester cancels a working invocation; the agent's outcome is then refused.
	canceled, _, err := il.create(t, alice, "c1", "never mind")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, canceled.ID)
	carol := il.invoker(t, "carol")
	if _, err = il.c.CancelInvocation(t.Context(), carol, canceled.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member canceled it", err)
	}
	if _, err = il.c.CancelInvocation(t.Context(), alice, canceled.ID, "cancel"); err != nil {
		t.Fatal(err)
	}
	if v := mustGet(t, il, alice, canceled.ID); v.State != "canceled" {
		t.Fatal("cancel view", v)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "after-cancel", answer(canceled.ID, "x")); !errors.Is(err, ErrTransition) {
		t.Fatal("a canceled invocation was completed", err)
	}
	// Queued (not yet delivered) work is not canceled from here.
	queued, _, err := il.create(t, alice, "q1", "queued")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.CancelInvocation(t.Context(), alice, queued.ID, "cancel-q"); !errors.Is(err, ErrTransition) {
		t.Fatal("queued delivery was canceled", err)
	}

	// Deleting the agent closes what it was still working on.
	il.ackWorking(t, queued.ID)
	if _, err = il.c.Delete(t.Context(), il.owner, il.agent, "delete"); err != nil {
		t.Fatal(err)
	}
	if v := mustGet(t, il, alice, queued.ID); v.State != "canceled" || v.ErrorCode != "agent_unavailable" {
		t.Fatal("deletion left a working invocation", v)
	}
}

func TestCompletionAndTimeoutRaceToExactlyOneOutcome(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	for round := range 6 {
		inv, _, err := il.create(t, alice, fmt.Sprintf("race-%d", round), "race")
		if err != nil {
			t.Fatal(err)
		}
		il.ackWorking(t, inv.ID)
		// Due now: completion and expiry both find it eligible by their own clocks.
		if _, err = il.s.pool.Exec(t.Context(), `UPDATE owner_instructions SET result_due_at=clock_timestamp()+interval '200 milliseconds' WHERE operation_id=$1`, inv.ID); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(time.Second)
		var wg sync.WaitGroup
		var completed, expired int
		var mu sync.Mutex
		for range 3 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, err := il.tr.CompleteInvocationFromVM(t.Context(), vm, fmt.Sprintf("k-%d", round), answer(inv.ID, "done")); err == nil {
					mu.Lock()
					completed++
					mu.Unlock()
				} else if !errors.Is(err, ErrExpired) && !errors.Is(err, ErrConflict) {
					t.Error(err)
				}
			}()
			go func() {
				defer wg.Done()
				n, err := il.s.ExpireWorkingInvocations(t.Context(), &at, 10)
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				expired += n
				mu.Unlock()
			}()
		}
		wg.Wait()
		v := mustGet(t, il, alice, inv.ID)
		switch {
		case expired == 1 && v.State == "failed" && v.ErrorCode == "work_timeout":
		case expired == 0 && completed >= 1 && v.State == "completed":
		default:
			t.Fatalf("round %d: completed=%d expired=%d state=%s", round, completed, expired, v.State)
		}
	}
}

func TestAttachmentIsReadableWhileItsInvocationWorks(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	data := randomBytes(t, 1000)
	att, _, err := il.upload(t, alice, "u", "a.bin", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := il.invokeWith(t, alice, "i", att.ID)
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	// After the exclusive delivery turn: this is when a real guest can read.
	seg, err := il.tr.ReadAttachmentFromVM(t.Context(), vm, att.ID, 0)
	if err != nil || string(seg.Data) != string(data) {
		t.Fatal("working invocation cannot read its file", err)
	}
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(inv.ID, "read")); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), vm, att.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("readable after completion", err)
	}
	if n, err := il.s.PurgeAttachments(t.Context(), nil, 10); err != nil || n != 1 {
		t.Fatal("bytes kept after completion", n, err)
	}
}

func TestWorkingAgentIsNotPutToSleepByItsIdlePolicy(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	il.run(t)
	il.idle(t, 60, "idle")
	inv, _, err := il.create(t, alice, "w", "long task")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	il.idleSleeps(t, time.Now()) // starts the idle clock
	if n := il.idleSleeps(t, time.Now().Add(10*time.Minute)); n != 0 {
		t.Fatal("an agent still working was put to sleep", n)
	}
}
