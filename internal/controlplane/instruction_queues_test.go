package controlplane

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func (il *invocationLab) setLimits(t *testing.T, p Principal, key string, perAgent, tenant int) error {
	t.Helper()
	_, err := il.a.SetQueueLimits(t.Context(), p, key, QueueLimits{MaxPendingPerAgent: perAgent, MaxPendingTenant: tenant})
	return err
}

func (il *invocationLab) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := il.s.pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestQueueDepthRefusesBeforeAnythingIsAccepted(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")

	// A plain member cannot change limits; a bad shape is refused.
	if err := il.setLimits(t, aliceP, "x", 1, 2); !errors.Is(err, ErrForbidden) {
		t.Fatal("a member changed the queue limits", err)
	}
	if err := il.setLimits(t, il.owner, "bad", 5, 2); !errors.Is(err, ErrInput) {
		t.Fatal("per-agent limit above the tenant limit accepted", err)
	}
	if err := il.setLimits(t, il.owner, "ok", 2, 3); err != nil {
		t.Fatal(err)
	}
	first, _, err := il.create(t, aliceP, "q1", "one")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.create(t, aliceP, "q2", "two"); err != nil {
		t.Fatal(err)
	}
	ops := il.count(t, "SELECT count(*) FROM platform_operations WHERE kind='instruction'")
	mbx := il.count(t, "SELECT count(*) FROM agent_mailboxes WHERE kind='instruction'")
	if _, _, err = il.create(t, aliceP, "q3", "three"); !errors.Is(err, ErrQueueFull) {
		t.Fatal("a full queue accepted work", err)
	}
	// Refusal leaves nothing behind and does not poison the key's later use.
	if il.count(t, "SELECT count(*) FROM platform_operations WHERE kind='instruction'") != ops ||
		il.count(t, "SELECT count(*) FROM agent_mailboxes WHERE kind='instruction'") != mbx {
		t.Fatal("a refused invocation left a trace")
	}
	// A replay of accepted work is never refused for being full.
	if again, ar, err := il.create(t, aliceP, "q1", "one"); err != nil || !ar.Replayed || again.ID != first.ID {
		t.Fatal("replay refused by a full queue", err)
	}
	view, err := il.a.QueueStatus(t.Context(), il.owner)
	if err != nil || view.PendingTenant != 2 || len(view.Agents) != 1 || view.Agents[0].Pending != 2 || view.Limits.Default || view.Limits.MaxPendingPerAgent != 2 {
		t.Fatal("queue view", view, err)
	}
	if _, err = il.a.QueueStatus(t.Context(), aliceP); !errors.Is(err, ErrForbidden) {
		t.Fatal("a member read the queue view", err)
	}

	// Capacity comes back when work leaves the queue.
	il.complete(t, first.ID)
	if _, _, err = il.create(t, aliceP, "q3", "three"); err != nil {
		t.Fatal("capacity was not returned after completion", err)
	}
	// Lowering the limit refuses new work but drops nothing already accepted.
	if err = il.setLimits(t, il.owner, "low", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = il.create(t, aliceP, "q4", "four"); !errors.Is(err, ErrQueueFull) {
		t.Fatal("lowered limit not applied", err)
	}
	if il.count(t, "SELECT count(*) FROM agent_mailboxes WHERE kind='instruction' AND delivery_state='PENDING'") != 2 {
		t.Fatal("lowering the limit dropped accepted work")
	}
}

func TestQueueTenantLimitSpansAgentsAndIsolatesTenants(t *testing.T) {
	il := newInvocationLab(t)
	second := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "second")
	alice, aliceP := il.person(t, "alice")
	for _, a := range []string{il.agent, second} {
		assign(t, il.tenantLab, il.owner, a, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "as-"+a)
	}
	if err := il.setLimits(t, il.owner, "lim", 2, 2); err != nil {
		t.Fatal(err)
	}
	send := func(agent, key string) error {
		_, err := il.c.CreateInvocation(t.Context(), aliceP, agent, key, InvocationInput{OwnerInstruction: privateInstruction("x")})
		return err
	}
	if err := send(il.agent, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := send(second, "b1"); err != nil {
		t.Fatal(err)
	}
	if err := send(second, "b2"); !errors.Is(err, ErrQueueFull) {
		t.Fatal("the tenant-wide limit was not applied across agents", err)
	}
}

func TestInvocationTTLAndExpiryAreVisibleAndDistinct(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")

	for i, ttl := range []int{-1, 86401} {
		in := InvocationInput{OwnerInstruction: privateInstruction("x"), TTLSeconds: ttl}
		if _, err := il.c.CreateInvocation(t.Context(), aliceP, il.agent, "bad"+string(rune('a'+i)), in); !errors.Is(err, ErrInput) {
			t.Fatal("out-of-range ttl accepted", ttl, err)
		}
	}
	short, err := il.c.CreateInvocation(t.Context(), aliceP, il.agent, "short", InvocationInput{OwnerInstruction: privateInstruction("short"), TTLSeconds: 30})
	var sv Invocation
	if err != nil || json.Unmarshal(short.Body, &sv) != nil {
		t.Fatal(err)
	}
	got, err := il.c.GetInvocation(t.Context(), aliceP, sv.ID)
	if err != nil || time.Until(got.ExpiresAt) > 31*time.Second || time.Until(got.ExpiresAt) < 25*time.Second {
		t.Fatal("ttl not applied", got.ExpiresAt, err)
	}
	// Same key, different ttl is a different request.
	if _, err = il.c.CreateInvocation(t.Context(), aliceP, il.agent, "short", InvocationInput{OwnerInstruction: privateInstruction("short"), TTLSeconds: 60}); !errors.Is(err, ErrConflict) {
		t.Fatal("same key with another ttl accepted", err)
	}
	long, _, err := il.create(t, aliceP, "long", "long")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(mustGet(t, il, aliceP, long.ID).ExpiresAt); d < 59*time.Minute {
		t.Fatal("default ttl is not an hour", d)
	}

	// Let the short one lapse. The FIFO head must be retired first, so it closes.
	var mbx string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", sv.ID).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", mbx); err != nil {
		t.Fatal(err)
	}
	if err = il.tr.DispatchMailbox(t.Context(), mbx, time.Minute, instructionRuntimeLab(t, il.agent)); err != nil {
		t.Fatal(err)
	}
	dead := mustGet(t, il, aliceP, sv.ID)
	if dead.State != "expired" || dead.CloseReason != "expired" || dead.ErrorCode != "delivery_failed" || dead.ResultAvailable {
		t.Fatal("expiry not visible", dead)
	}
	// The dead-letter view separates expired from other failures, and a live
	// instruction in the same queue is untouched.
	expired, err := il.c.ListInvocations(t.Context(), aliceP, il.agent, "", "expired", 10)
	if err != nil || len(expired) != 1 || expired[0].ID != sv.ID {
		t.Fatal("expired filter", expired, err)
	}
	failed, err := il.c.ListInvocations(t.Context(), aliceP, il.agent, "", "failed", 10)
	if err != nil || len(failed) != 0 {
		t.Fatal("expired counted as failed", failed, err)
	}
	if st := mustGet(t, il, aliceP, long.ID).State; st != "accepted" {
		t.Fatal("a live instruction was disturbed", st)
	}
	if _, err = il.c.ListInvocations(t.Context(), aliceP, il.agent, "", "bogus", 10); !errors.Is(err, ErrInput) {
		t.Fatal("unknown state filter accepted", err)
	}
}

func mustGet(t *testing.T, il *invocationLab, p Principal, id string) Invocation {
	t.Helper()
	v, err := il.c.GetInvocation(t.Context(), p, id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDesiredStateFollowsTheLifecycleLedgerNotTheWish(t *testing.T) {
	l, c, owner := agentLab(t)
	id := activateTenantAgent(t, l, c, owner, "desired")
	view := func() TenantAgent {
		t.Helper()
		v, err := c.GetTenantAgent(t.Context(), owner, id)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// Created cold: nothing is running and nothing is wanted.
	if v := view(); v.DesiredState != "stopped" || v.State != "STOPPED" || !v.Converged {
		t.Fatal("a cold-created agent is not stopped and converged", v)
	}
	// A wake is accepted: wanted but not yet observed.
	r, err := c.RequestLifecycle(t.Context(), owner, id, "w1", "wake")
	var op AgentCreation
	if err != nil || json.Unmarshal(r.Body, &op) != nil {
		t.Fatal(err)
	}
	if v := view(); v.DesiredState != "running" || v.Converged {
		t.Fatal("an accepted wake is not reported as pending", v)
	}
	// A failed or canceled wake is no longer wanted.
	if _, err = l.s.pool.Exec(t.Context(), "UPDATE platform_operations SET status='FAILED' WHERE id=$1", op.OperationID); err != nil {
		t.Fatal(err)
	}
	if v := view(); v.DesiredState != "stopped" || !v.Converged {
		t.Fatal("a failed wake still counts as wanted", v)
	}
	// The latest accepted command wins.
	if _, err = c.RequestLifecycle(t.Context(), owner, id, "w2", "wake"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.RequestLifecycle(t.Context(), owner, id, "s1", "sleep"); err != nil {
		t.Fatal(err)
	}
	if v := view(); v.DesiredState != "stopped" || !v.Converged {
		t.Fatal("sleep after wake not honoured", v)
	}
	// Deletion is wanted from the moment it is requested, converged only at the end.
	if _, err = c.Delete(t.Context(), owner, id, "d1"); err != nil {
		t.Fatal(err)
	}
	if v := view(); v.DesiredState != "deleted" || v.Converged {
		t.Fatal("a requested deletion is not reported as pending", v)
	}
}

func TestLifecycleCommandsAreAuditedOnceAndRaceSafely(t *testing.T) {
	l, c, owner := agentLab(t)
	id := activateTenantAgent(t, l, c, owner, "audited")
	audits := func(action string) int {
		t.Helper()
		var n int
		if err := l.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND action=$2 AND actor_principal_id=$3", id, action, owner.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Same key from many callers at once: one operation, one audit row.
	const callers = 8
	ops := make(chan string, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			r, err := c.RequestLifecycle(t.Context(), owner, id, "same", "wake")
			var op AgentCreation
			if err == nil {
				err = json.Unmarshal(r.Body, &op)
			}
			errs <- err
			ops <- op.OperationID
		}()
	}
	seen := map[string]bool{}
	for range callers {
		if err := <-errs; err != nil && !errors.Is(err, ErrInProgress) {
			t.Fatal(err)
		}
		if op := <-ops; op != "" {
			seen[op] = true
		}
	}
	if len(seen) != 1 || audits("agent.wake_requested") != 1 {
		t.Fatal("one idempotent wake produced several operations or audit rows", seen, audits("agent.wake_requested"))
	}
	// Distinct keys are distinct, strictly ordered commands, each audited.
	for i := range callers {
		go func() {
			_, err := c.RequestLifecycle(t.Context(), owner, id, "sleep-"+string(rune('a'+i)), "sleep")
			errs <- err
		}()
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var distinct, total int
	if err := l.s.pool.QueryRow(t.Context(), "SELECT count(DISTINCT seq),count(*) FROM platform_operations WHERE agent_id=$1 AND kind='sleep'", id).Scan(&distinct, &total); err != nil || distinct != callers || total != callers {
		t.Fatal("concurrent commands are not strictly ordered", distinct, total, err)
	}
	if audits("agent.sleep_requested") != callers {
		t.Fatal("not every command was audited", audits("agent.sleep_requested"))
	}
	// Deletion requested twice with different keys: one operation, one audit row.
	for _, k := range []string{"d1", "d2"} {
		if _, err := c.Delete(t.Context(), owner, id, k); err != nil {
			t.Fatal(err)
		}
	}
	if audits("agent.delete_requested") != 1 {
		t.Fatal("deletion audited more than once", audits("agent.delete_requested"))
	}
	// A refused command leaves no audit trace.
	before := audits("agent.wake_requested")
	if _, err := c.RequestLifecycle(t.Context(), owner, id, "after-delete", "wake"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if audits("agent.wake_requested") != before {
		t.Fatal("a refused wake was audited as accepted")
	}
}
