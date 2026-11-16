package controlplane

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// mailboxOf returns the queue entry of invocation op: its event ID.
func (il *invocationLab) mailboxOf(t *testing.T, op string) (string, int64) {
	t.Helper()
	var id string
	var seq int64
	if err := il.s.pool.QueryRow(t.Context(), "SELECT id,seq FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&id, &seq); err != nil {
		t.Fatal(err)
	}
	return id, seq
}

// kill makes invocation op die without reaching its agent: its attempts are
// spent, or its deadline passes.
func (il *invocationLab) kill(t *testing.T, op string, expire bool) {
	t.Helper()
	mbx, _ := il.mailboxOf(t, op)
	change := "attempts=attempt_limit"
	if expire {
		change = "expires_at=clock_timestamp()-interval '1 second'"
	}
	if _, err := il.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET "+change+" WHERE id=$1", mbx); err != nil {
		t.Fatal(err)
	}
	if err := il.tr.DispatchMailbox(t.Context(), mbx, time.Minute, instructionRuntimeLab(t, il.agent)); err != nil {
		t.Fatal(err)
	}
}

func (il *invocationLab) replay(t *testing.T, p Principal, op, key string, ttl int) (Invocation, APIReceipt, error) {
	t.Helper()
	r, err := il.c.ReplayInvocation(t.Context(), p, op, key, ReplayInput{TTLSeconds: ttl})
	if err != nil {
		return Invocation{}, r, err
	}
	var v Invocation
	if err = json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	return v, r, nil
}

func refusedFor(err error, reason string) bool {
	var refusal *ReplayRefusal
	return errors.As(err, &refusal) && refusal.Reason == reason
}

// An administrator of the organization replays a dead letter: the same
// invocation, the same event ID, a new attempt budget, its deadline kept, at
// the end of its agent's queue. Only owners and administrators may; the
// requester alone reads the result. The replay is audited and idempotent.
func TestAnAdministratorReplaysADeadLetter(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	dead, _, err := il.create(t, alice, "first", "one")
	if err != nil {
		t.Fatal(err)
	}
	later, _, err := il.create(t, alice, "later", "two")
	if err != nil {
		t.Fatal(err)
	}
	mbx, seq := il.mailboxOf(t, dead.ID)
	il.kill(t, dead.ID, false)
	before := mustGet(t, il, alice, dead.ID)
	if before.State != "failed" || before.CloseReason != "attempts_exhausted" {
		t.Fatal("not a dead letter", before)
	}
	il.complete(t, later.ID)

	// Who may replay: owners and administrators, not the requester, an
	// operator or an auditor.
	addMember(t, il.tenantLab, il.owner, "admin", authorization.OrgAdmin)
	admin := agentPrincipal(t, il.tenantLab, "admin", agentScopes)
	for subject, role := range map[string]authorization.Role{"operator": authorization.AgentOperator, "auditor": authorization.Auditor} {
		addMember(t, il.tenantLab, il.owner, subject, role)
		if _, _, err = il.replay(t, agentPrincipal(t, il.tenantLab, subject, agentScopes), dead.ID, "k", 0); !errors.Is(err, ErrForbidden) {
			t.Fatal("replayed by", subject, err)
		}
	}
	if _, _, err = il.replay(t, alice, dead.ID, "k", 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("replayed by the requester", err)
	}
	if _, _, err = il.replay(t, agentPrincipal(t, il.tenantLab, "admin", "org:read agent:read"), dead.ID, "k", 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("replayed without quota:manage", err)
	}

	v, r, err := il.replay(t, admin, dead.ID, "k", 0)
	if err != nil || r.Status != 202 {
		t.Fatal(err)
	}
	if v.ID != dead.ID || v.State != "accepted" || v.ErrorCode != "" || v.CloseReason != "" || v.ReplayedAt == nil ||
		!v.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatal("replayed invocation", v)
	}
	again, err := il.c.ReplayInvocation(t.Context(), admin, dead.ID, "k", ReplayInput{})
	if err != nil || !again.Replayed || string(again.Body) != string(r.Body) {
		t.Fatal("the same key replayed again", err)
	}
	if _, _, err = il.replay(t, admin, dead.ID, "k2", 0); !errors.Is(err, ErrTransition) {
		t.Fatal("a pending instruction was replayed", err)
	}
	var attempts int
	var newSeq, laterSeq int64
	var state string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT attempts,seq,delivery_state FROM agent_mailboxes WHERE id=$1", mbx).Scan(&attempts, &newSeq, &state); err != nil {
		t.Fatal(err)
	}
	_, laterSeq = il.mailboxOf(t, later.ID)
	if attempts != 0 || state != "PENDING" || newSeq <= laterSeq || newSeq <= seq {
		t.Fatal("not a fresh budget at the end of the queue", attempts, state, seq, laterSeq, newSeq)
	}
	var actor, previous string
	if err = il.s.pool.QueryRow(t.Context(), `SELECT actor_principal_id,previous_reason FROM instruction_replays WHERE operation_id=$1`, dead.ID).Scan(&actor, &previous); err != nil ||
		actor != admin.ID || previous != "attempts_exhausted" {
		t.Fatal("replay not audited", actor, previous, err)
	}

	// The agent receives the same event ID; the requester reads the result,
	// the administrator does not.
	attempt, envelope := claimInstruction(t, il.tr, mbx)
	if envelope.ID != mbx {
		t.Fatal("a replay changed the event ID", envelope.ID, mbx)
	}
	inv, err := capsuleprotocol.DecodeInvocation(envelope, il.agent)
	if err != nil || inv.OperationID != dead.ID {
		t.Fatal("a replay changed the invocation", err)
	}
	rt := instructionRuntimeLab(t, il.agent)
	result, err := rt.Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mbx, attempt.Token, result.Result); err != nil {
		t.Fatal(err)
	}
	if v := mustGet(t, il, alice, dead.ID); v.State != "completed" || v.ReplayedAt == nil {
		t.Fatal("the replay did not complete", v)
	}
	if _, err = il.c.InstructionResult(t.Context(), alice, dead.ID); err != nil {
		t.Fatal("the requester cannot read the replay's result", err)
	}
	if _, err = il.c.InstructionResult(t.Context(), admin, dead.ID); err == nil {
		t.Fatal("the administrator read the content")
	}
}

// After its deadline, a dead letter runs again only with a new window, counted
// from the replay.
func TestAReplayAfterTheDeadlineNeedsANewWindow(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	dead, _, err := il.create(t, alice, "first", "one")
	if err != nil {
		t.Fatal(err)
	}
	il.kill(t, dead.ID, true)
	if _, _, err = il.replay(t, il.owner, dead.ID, "late", 0); !errors.Is(err, ErrExpired) {
		t.Fatal("a dead letter past its deadline replayed without a new window", err)
	}
	for _, ttl := range []int{-1, 86401} {
		if _, _, err = il.replay(t, il.owner, dead.ID, "bad", ttl); !errors.Is(err, ErrInput) {
			t.Fatal("window out of range", ttl, err)
		}
	}
	v, _, err := il.replay(t, il.owner, dead.ID, "window", 600)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(v.ExpiresAt); d < 590*time.Second || d > 601*time.Second || v.State != "accepted" {
		t.Fatal("new window", v.State, d)
	}
	var previous string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT previous_reason FROM instruction_replays WHERE operation_id=$1", dead.ID).Scan(&previous); err != nil || previous != "expired" {
		t.Fatal(previous, err)
	}
}

// What cannot be replayed stays as it was: work that is not a dead letter, a
// dead letter that may have reached its agent, one whose requester can no
// longer invoke the agent or whose content is gone, one that does not fit the
// queue, one of an agent being deleted.
func TestWhatCannotBeReplayed(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	live, _, err := il.create(t, alice, "live", "zero")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.replay(t, il.owner, live.ID, "live", 0); !errors.Is(err, ErrTransition) {
		t.Fatal("accepted work replayed", err)
	}
	if _, _, err = il.replay(t, il.owner, "op_missing", "x", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown invocation", err)
	}
	il.complete(t, live.ID)
	if _, _, err = il.replay(t, il.owner, live.ID, "done", 0); !errors.Is(err, ErrTransition) {
		t.Fatal("completed work replayed", err)
	}

	dead := func(key string) string {
		t.Helper()
		v, _, err := il.create(t, alice, key, key)
		if err != nil {
			t.Fatal(err)
		}
		il.kill(t, v.ID, false)
		return v.ID
	}
	unchanged := func(op string) {
		t.Helper()
		if v := mustGet(t, il, alice, op); v.State != "failed" || v.ReplayedAt != nil {
			t.Fatal("a refused replay changed the invocation", v)
		}
	}
	// May have reached the agent: its store fenced the event for good.
	reached := dead("reached")
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET may_have_reached=true WHERE instruction_id=$1", reached); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.replay(t, il.owner, reached, "reached", 0); !refusedFor(err, ReplayOutcomeUnknown) {
		t.Fatal("an outcome unknown was replayed", err)
	}
	unchanged(reached)
	// Its content was purged.
	purged := dead("purged")
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
        WHERE id=(SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1)`, purged); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.replay(t, il.owner, purged, "purged", 0); !refusedFor(err, SkipInputPurged) {
		t.Fatal("purged content replayed", err)
	}
	unchanged(purged)
	// The queue is full.
	full := dead("full")
	if err = il.setLimits(t, il.owner, "limits", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.create(t, alice, "filler", "filler"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.replay(t, il.owner, full, "full", 0); !errors.Is(err, ErrQueueFull) {
		t.Fatal("a replay ignored the queue limits", err)
	}
	unchanged(full)
	// The requester lost the right to invoke the agent.
	var assignment string
	if err = il.s.pool.QueryRow(t.Context(), `SELECT id FROM agent_assignments WHERE agent_id=$1 AND principal_id=$2 AND status='active'`, il.agent, alice.ID).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	if _, err = il.owner.revoke(t, il, assignment); err != nil {
		t.Fatal(err)
	}
	if err = il.setLimits(t, il.owner, "roomy", 100, 1000); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.replay(t, il.owner, full, "revoked", 0); !refusedFor(err, SkipRequesterRevoked) {
		t.Fatal("the work of a revoked requester was replayed", err)
	}
	// The agent is being deleted.
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agents SET phase='DELETING' WHERE id=$1", il.agent); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.ReplayDeadInstruction(t.Context(), full, "deleting", ReplayInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a dead letter of an agent being deleted was replayed", err)
	}
	if n := il.count(t, "SELECT count(*) FROM instruction_replays"); n != 0 {
		t.Fatal("refused replays were recorded", n)
	}
}

// The operator replays from agentcapsule-admin: idempotent by its key, and
// audited without a principal.
func TestTheOperatorReplaysADeadLetter(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	dead, _, err := il.create(t, alice, "first", "one")
	if err != nil {
		t.Fatal(err)
	}
	il.kill(t, dead.ID, true)
	if _, err = il.s.ReplayDeadInstruction(t.Context(), dead.ID, "op-1", ReplayInput{}); !errors.Is(err, ErrExpired) {
		t.Fatal("replayed past its deadline", err)
	}
	r, err := il.s.ReplayDeadInstruction(t.Context(), dead.ID, "op-1", ReplayInput{TTLSeconds: 120})
	if err != nil || r.Replayed || r.OperationID != dead.ID || time.Until(r.ExpiresAt) < 100*time.Second {
		t.Fatal("operator replay", r, err)
	}
	again, err := il.s.ReplayDeadInstruction(t.Context(), dead.ID, "op-1", ReplayInput{TTLSeconds: 120})
	if err != nil || !again.Replayed || !again.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatal("the same key replayed again", again, err)
	}
	if _, err = il.s.ReplayDeadInstruction(t.Context(), dead.ID, "op-2", ReplayInput{}); !errors.Is(err, ErrTransition) {
		t.Fatal("a pending instruction was replayed", err)
	}
	var kind string
	var principal *string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT actor_kind,actor_principal_id FROM instruction_replays WHERE operation_id=$1", dead.ID).Scan(&kind, &principal); err != nil ||
		kind != "operator" || principal != nil {
		t.Fatal("operator replay not audited", kind, principal, err)
	}
	if v := mustGet(t, il, alice, dead.ID); v.State != "accepted" || v.ReplayedAt == nil {
		t.Fatal(v)
	}
}
