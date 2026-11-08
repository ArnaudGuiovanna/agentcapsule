package controlplane

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// run makes the lab agent's placement RUNNING on the catalog host.
func (il *invocationLab) run(t *testing.T) uint64 {
	t.Helper()
	_ = il.s.RegisterPlacement(t.Context(), il.agent, "local")
	p, err := il.s.ClaimPlacement(t.Context(), il.agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.s.ConfirmPlacement(t.Context(), il.agent, "local", "worker", p.Generation, fmt.Sprintf("%016x", p.Generation)); err != nil {
		t.Fatal(err)
	}
	return p.Generation
}

func (il *invocationLab) idle(t *testing.T, seconds int, key string) {
	t.Helper()
	if _, err := il.c.SetIdlePolicy(t.Context(), il.owner, il.agent, key, seconds); err != nil {
		t.Fatal(err)
	}
}

func (il *invocationLab) idleSleeps(t *testing.T, at time.Time) int {
	t.Helper()
	n, err := il.s.ScheduleIdleSleeps(t.Context(), "local", &at, 10)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (il *invocationLab) sleepOps(t *testing.T) int {
	t.Helper()
	return il.count(t, "SELECT count(*) FROM platform_operations WHERE kind='sleep' AND cause='idle_policy' AND agent_id='"+il.agent+"'")
}

func TestIdlePolicyIsAnExplicitAuditedChoice(t *testing.T) {
	il := newInvocationLab(t)
	_, aliceP := il.person(t, "alice")
	for _, bad := range []int{-1, 30, 604801} {
		if _, err := il.c.SetIdlePolicy(t.Context(), il.owner, il.agent, fmt.Sprintf("bad%d", bad), bad); !errors.Is(err, ErrInput) {
			t.Fatal("out-of-range idle timeout accepted", bad, err)
		}
	}
	if _, err := il.c.SetIdlePolicy(t.Context(), aliceP, il.agent, "x", 300); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrNotFound) {
		t.Fatal("a plain member set an idle policy", err)
	}
	il.idle(t, 300, "p1")
	v, err := il.c.GetTenantAgent(t.Context(), il.owner, il.agent)
	if err != nil || v.IdleTimeoutSeconds == nil || *v.IdleTimeoutSeconds != 300 {
		t.Fatal("policy not visible", v, err)
	}
	if il.count(t, "SELECT count(*) FROM tenant_agent_audit WHERE action='agent.idle_policy_set' AND agent_id='"+il.agent+"'") != 1 {
		t.Fatal("policy change not audited")
	}
	il.idle(t, 0, "p2")
	if v, _ = il.c.GetTenantAgent(t.Context(), il.owner, il.agent); v.IdleTimeoutSeconds != nil {
		t.Fatal("policy not cleared")
	}
}

func TestIdleAgentSleepsOnceAfterItsDelayAndNeverBefore(t *testing.T) {
	il := newInvocationLab(t)
	il.idle(t, 120, "p")
	t0 := time.Now().UTC()
	// A stopped agent is not watched: no clock, no sleep, however late.
	if il.idleSleeps(t, t0.Add(24*time.Hour)) != 0 {
		t.Fatal("a stopped agent was put to sleep")
	}
	il.run(t)
	if il.idleSleeps(t, t0) != 0 {
		t.Fatal("slept at the moment it was first seen running")
	}
	if il.idleSleeps(t, t0.Add(119*time.Second)) != 0 {
		t.Fatal("slept before the idle delay")
	}
	if il.idleSleeps(t, t0.Add(121*time.Second)) != 1 || il.sleepOps(t) != 1 {
		t.Fatal("did not sleep after the idle delay")
	}
	var by string
	if err := il.s.pool.QueryRow(t.Context(), "SELECT requested_by_principal_id FROM platform_operations WHERE cause='idle_policy' AND agent_id=$1", il.agent).Scan(&by); err != nil || by != il.owner.ID {
		t.Fatal("the idle sleep is not attributed to the principal who set the policy", by, err)
	}
	if il.count(t, "SELECT count(*) FROM tenant_agent_audit WHERE action='agent.idle_sleep_requested' AND agent_id='"+il.agent+"'") != 1 {
		t.Fatal("idle sleep not audited")
	}
	// The open sleep is itself work: repeating produces no second one.
	if il.idleSleeps(t, t0.Add(10*time.Minute)) != 0 || il.sleepOps(t) != 1 {
		t.Fatal("idle sleep duplicated")
	}
	v, err := il.c.GetTenantAgent(t.Context(), il.owner, il.agent)
	if err != nil || v.DesiredState != "stopped" {
		t.Fatal("idle sleep not reflected in the desired state", v, err)
	}
}

func TestWorkKeepsAnAgentAwake(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")
	il.idle(t, 120, "p")
	il.run(t)
	t0 := time.Now().UTC()
	il.idleSleeps(t, t0) // starts the clock
	far := t0.Add(30 * time.Minute)

	// Queued work blocks the stop however long it has been quiet.
	v, _, err := il.create(t, aliceP, "q", "pending")
	if err != nil {
		t.Fatal(err)
	}
	if il.idleSleeps(t, far) != 0 {
		t.Fatal("slept with an instruction waiting")
	}
	// Finishing it is activity: the idle delay restarts from completion.
	il.complete(t, v.ID)
	done := time.Now().UTC()
	if il.idleSleeps(t, done.Add(119*time.Second)) != 0 {
		t.Fatal("completion did not restart the idle clock")
	}
	// A scheduled instruction due inside the window blocks the stop; one far away does not.
	soon, err := il.schedule(t, aliceP, "soon", "x", done.Add(150*time.Second), 0)
	if err != nil {
		t.Fatal(err)
	}
	if il.idleSleeps(t, done.Add(130*time.Second)) != 0 {
		t.Fatal("slept although work is due before the idle window ends")
	}
	cancel, err := il.c.CancelInvocation(t.Context(), aliceP, soon.ID, "c")
	if err != nil || cancel.Status != 200 {
		t.Fatal(err)
	}
	if _, err = il.schedule(t, aliceP, "far", "x", done.Add(3*time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	// A pending lifecycle command is work too.
	if _, err = il.c.RequestLifecycle(t.Context(), il.owner, il.agent, "w", "wake"); err != nil {
		t.Fatal(err)
	}
	if il.idleSleeps(t, done.Add(10*time.Minute)) != 0 {
		t.Fatal("slept with a wake command open")
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE agent_id=$1 AND kind='wake'", il.agent); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if il.idleSleeps(t, after.Add(121*time.Second)) != 1 {
		t.Fatal("did not sleep once all work was done, despite a far-future schedule")
	}
	// Disabling the policy stops further sleeps.
	il.idle(t, 0, "off")
	if il.idleSleeps(t, after.Add(48*time.Hour)) != 0 {
		t.Fatal("slept after the policy was disabled")
	}
}

func TestANewGenerationRestartsTheIdleClock(t *testing.T) {
	il := newInvocationLab(t)
	il.idle(t, 120, "p")
	g1 := il.run(t)
	t0 := time.Now().UTC()
	il.idleSleeps(t, t0)
	// Replace the running generation shortly before the delay would elapse.
	if err := il.s.BeginPlacementStop(t.Context(), il.agent, "local", g1); err != nil {
		t.Fatal(err)
	}
	if err := il.s.ObservePlacementStopped(t.Context(), il.agent, "local", g1, false); err != nil {
		t.Fatal(err)
	}
	g2 := il.run(t)
	if g2 == g1 {
		t.Fatal("generation did not change")
	}
	mid := t0.Add(100 * time.Second)
	il.idleSleeps(t, mid) // observes the new generation at mid
	if il.idleSleeps(t, mid.Add(119*time.Second)) != 0 {
		t.Fatal("the old generation's idle time was charged to the new one")
	}
	if il.idleSleeps(t, mid.Add(121*time.Second)) != 1 {
		t.Fatal("the new generation never became idle")
	}
}
