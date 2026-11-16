package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// failBoot claims a boot of id and records that its guest failed.
func failBoot(t *testing.T, s *Store, id string, budget RestartBudget) (Placement, bool) {
	t.Helper()
	p, err := s.ClaimPlacement(t.Context(), id, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal("claim", err)
	}
	failed, err := s.ObserveGuestFailure(t.Context(), GuestFailure{AgentID: id, HostID: "local", Kind: GuestBootFailed, Generation: p.Generation}, budget)
	if err != nil {
		t.Fatal("boot failure", err)
	}
	return p, failed
}

func agentState(t *testing.T, c *AgentCatalog, p Principal, id string) (string, string) {
	t.Helper()
	v, err := c.GetTenantAgent(t.Context(), p, id)
	if err != nil {
		t.Fatal(err)
	}
	reason := ""
	if v.FailureReason != nil {
		reason = *v.FailureReason
	}
	return v.State, reason
}

// A guest that keeps failing to boot is not booted again and again (CAP-03,
// RUN-011, ADR 012): after its budget of failures within the window, the
// agent is FAILED, says why, and no boot of it is claimed until a wake.
func TestAnAgentWhoseGuestKeepsFailingIsFailed(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	id := activateTenantAgent(t, l, c, owner, "failing")
	budget := RestartBudget{Failures: 3, Window: time.Hour}

	p, failed := failBoot(t, l.s, id, budget)
	if failed {
		t.Fatal("FAILED after one failure")
	}
	var state string
	var unclean bool
	if err := l.s.pool.QueryRow(ctx, "SELECT state,unclean_stop FROM agent_placements WHERE agent_id=$1", id).Scan(&state, &unclean); err != nil || state != "STOPPED" || !unclean {
		t.Fatal("the failed boot is not stopped, unclean", state, unclean, err)
	}
	// Recording the same boot again, a retried transaction, counts once.
	if again, err := l.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: id, HostID: "local", Kind: GuestBootFailed, Generation: p.Generation}, budget); err != nil || again {
		t.Fatal("a retry", again, err)
	}
	if n := count(t, l.s, "guest_failures"); n != 1 {
		t.Fatal("a generation counted twice", n)
	}
	// A failure outside the window no longer counts.
	if _, err := l.s.pool.Exec(ctx, "UPDATE guest_failures SET failed_at=clock_timestamp()-interval '61 minutes'"); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, failed = failBoot(t, l.s, id, budget); failed {
			t.Fatal("FAILED with an old failure counted", i)
		}
	}
	if n := count(t, l.s, "guest_failures"); n != 2 {
		t.Fatal("failures out of the window are kept", n)
	}
	if state, reason := agentState(t, c, owner, id); state != "STOPPED" || reason != "" {
		t.Fatal("not yet failed", state, reason)
	}
	if _, failed = failBoot(t, l.s, id, budget); !failed {
		t.Fatal("not FAILED after its budget")
	}
	if state, reason := agentState(t, c, owner, id); state != "FAILED" || reason != "boot_failed" {
		t.Fatal("state of a FAILED agent", state, reason)
	}
	// No boot of any kind is claimed for it.
	if _, err := l.s.ClaimPlacement(ctx, id, "local", "worker", time.Minute); !errors.Is(err, ErrAgentFailed) {
		t.Fatal("work boot of a FAILED agent", err)
	}
	if _, err := l.s.ClaimFencePlacement(ctx, id, "local", "worker", time.Minute); !errors.Is(err, ErrAgentFailed) {
		t.Fatal("barrier boot of a FAILED agent", err)
	}
	if n, err := l.s.FailedAgents(ctx, "local"); err != nil || n != 1 {
		t.Fatal("failed agents of the host", n, err)
	}

	// An explicit wake gives it a new budget.
	r, err := c.RequestLifecycle(ctx, owner, id, "wake-failed", "wake")
	if err != nil || r.Status != 202 {
		t.Fatal("wake", r.Status, err)
	}
	if state, reason := agentState(t, c, owner, id); state != "STOPPED" || reason != "" {
		t.Fatal("still failed after a wake", state, reason)
	}
	if n := count(t, l.s, "guest_failures"); n != 0 {
		t.Fatal("old failures count against the new budget", n)
	}
	if _, failed = failBoot(t, l.s, id, budget); failed {
		t.Fatal("the new budget is spent at once")
	}
	// A replayed wake request does not clear the budget again.
	if _, err = l.s.pool.Exec(ctx, "INSERT INTO failed_agents(agent_id,reason,failures) VALUES($1,'boot_failed',3)", id); err != nil {
		t.Fatal(err)
	}
	if r, err = c.RequestLifecycle(ctx, owner, id, "wake-failed", "wake"); err != nil {
		t.Fatal("replay", err)
	}
	if state, _ := agentState(t, c, owner, id); state != "FAILED" {
		t.Fatal("a replayed request cleared the agent", state)
	}
	// So does the operator.
	if cleared, err := l.s.ClearAgentFailure(ctx, id); err != nil || !cleared {
		t.Fatal("operator clear", cleared, err)
	}
	if cleared, err := l.s.ClearAgentFailure(ctx, id); err != nil || cleared {
		t.Fatal("clearing an agent that is not FAILED", cleared, err)
	}
	if _, err := l.s.ClearAgentFailure(ctx, "agt_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("clearing an unknown agent", err)
	}
	if _, err = l.s.ClaimPlacement(ctx, id, "local", "worker", time.Minute); err != nil {
		t.Fatal("boot after the operator cleared it", err)
	}
}

// A confirmed guest that goes away by itself is a crash: it counts like a
// failed boot, and the reason says which kind spent the budget.
func TestCrashesSpendTheRestartBudget(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	id := activateTenantAgent(t, l, c, owner, "crashing")
	budget := RestartBudget{Failures: 2, Window: time.Hour}
	failBoot(t, l.s, id, budget)
	p, err := l.s.ClaimPlacement(ctx, id, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = l.s.ConfirmPlacement(ctx, id, "local", "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	// Another generation's failure is refused.
	if _, err = l.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: id, HostID: "local", Kind: GuestCrashed, Generation: p.Generation - 1}, budget); !errors.Is(err, ErrPlacement) {
		t.Fatal("an older generation's crash", err)
	}
	failed, err := l.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: id, HostID: "local", Kind: GuestCrashed, Generation: p.Generation}, budget)
	if err != nil || !failed {
		t.Fatal("crash", failed, err)
	}
	if state, reason := agentState(t, c, owner, id); state != "FAILED" || reason != "crashed" {
		t.Fatal("crashed agent", state, reason)
	}
	for _, bad := range []GuestFailure{{AgentID: id, HostID: "local", Kind: "oom", Generation: p.Generation}, {AgentID: id, HostID: "local", Kind: GuestCrashed}} {
		if _, err = l.s.ObserveGuestFailure(ctx, bad, budget); !errors.Is(err, ErrInput) {
			t.Fatal("invalid failure", bad, err)
		}
	}
	if _, err = l.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: id, HostID: "local", Kind: GuestCrashed, Generation: p.Generation}, RestartBudget{}); !errors.Is(err, ErrInput) {
		t.Fatal("invalid budget", err)
	}
}

// Only a live agent's own boots count. A restore boots its agent even when
// FAILED, and its failures do not count: the restore is the operator's act.
// A deleted agent is not held by an earlier failure.
func TestRestoresAndDeletionsAreNotHeld(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	id := activateTenantAgent(t, l, c, owner, "restored")
	budget := RestartBudget{Failures: 1, Window: time.Hour}
	if _, failed := failBoot(t, l.s, id, budget); !failed {
		t.Fatal("not FAILED")
	}
	plan, err := l.s.BeginVolumeRestore(ctx, restoreID(1), id, "local", archiveID(1))
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.s.ClaimFencePlacement(ctx, id, "local", "restorer", time.Minute)
	if err != nil {
		t.Fatal("restricted boot of a restore", err)
	}
	if failed, err := l.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: id, HostID: "local", Kind: GuestBootFailed, Generation: p.Generation}, budget); err != nil || failed {
		t.Fatal("a restore's boot failure", failed, err)
	}
	if n := count(t, l.s, "guest_failures"); n != 1 {
		t.Fatal("a restore's failure counted", n)
	}
	if state, reason := agentState(t, c, owner, id); state != "FAILED" || reason != "boot_failed" || plan.Restore.AgentID != id {
		t.Fatal("a restore clears the agent", state, reason)
	}
	if _, err = l.s.pool.Exec(ctx, "UPDATE agents SET phase='QUIESCING' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.ClaimFencePlacement(ctx, id, "local", "deleter", time.Minute); err != nil {
		t.Fatal("a deletion's barrier boot of a FAILED agent", err)
	}
}

// A wake that cannot boot its FAILED agent ends FAILED, without a loop; if
// the agent was cleared meanwhile, it stays open for its job to try again.
func TestAWakeOfAFailedAgentFails(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	id := activateTenantAgent(t, l, c, owner, "woken")
	r, err := c.RequestLifecycle(ctx, owner, id, "wake-1", "wake")
	if err != nil {
		t.Fatal(err)
	}
	var created AgentCreation
	if err = json.Unmarshal(r.Body, &created); err != nil {
		t.Fatal(err)
	}
	op, err := l.s.BeginLifecycleOperation(ctx, created.OperationID, id, "local")
	if err != nil || op.Status != "RUNNING" {
		t.Fatal("begin", op.Status, err)
	}
	if err = l.s.FailWakeOfFailedAgent(ctx, op); !errors.Is(err, ErrTransition) {
		t.Fatal("failed a wake whose agent can boot", err)
	}
	if _, failed := failBoot(t, l.s, id, RestartBudget{Failures: 1, Window: time.Hour}); !failed {
		t.Fatal("not FAILED")
	}
	if err = l.s.FailWakeOfFailedAgent(ctx, op); err != nil {
		t.Fatal(err)
	}
	var status, code string
	if err = l.s.pool.QueryRow(ctx, "SELECT status,error_code FROM platform_operations WHERE id=$1", op.ID).Scan(&status, &code); err != nil ||
		status != "FAILED" || code != "restart_budget_exhausted" {
		t.Fatal("wake of a FAILED agent", status, code, err)
	}
	if err = l.s.FailWakeOfFailedAgent(ctx, op); err != nil {
		t.Fatal("ending it again", err)
	}
	if v, err := c.GetTenantAgent(ctx, owner, id); err != nil || v.State != "FAILED" || v.Converged {
		t.Fatal("a FAILED agent", v.State, v.Converged, err)
	}
}

// A person's own agent is held and woken the same way.
func TestAPersonsFailedAgent(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	ctx := t.Context()
	e := reserveEnrollment(t, s, c, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, failed := failBoot(t, s, e.AgentID, RestartBudget{Failures: 1, Window: time.Minute}); !failed {
		t.Fatal("not FAILED")
	}
	v, err := c.Get(ctx, owner, e.AgentID)
	if err != nil || v.State != "FAILED" || v.FailureReason == nil || *v.FailureReason != "boot_failed" {
		t.Fatal("a person's FAILED agent", v.State, v.FailureReason, err)
	}
	if _, err = c.RequestLifecycle(ctx, owner, e.AgentID, "wake", "wake"); err != nil {
		t.Fatal(err)
	}
	if v, err = c.Get(ctx, owner, e.AgentID); err != nil || v.State != "STOPPED" || v.FailureReason != nil {
		t.Fatal("woken", v.State, v.FailureReason, err)
	}
}
