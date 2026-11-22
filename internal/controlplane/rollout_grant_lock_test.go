package controlplane

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A rollout that installs a template without the previous one's model alias
// revokes the agent's template grant (installRolloutTemplate). As every
// revocation of a row an admission reads (P-07), its transaction holds the
// organization's row FOR UPDATE (FIX-2): a model call's reservation, which
// holds that row FOR KEY SHARE before it reads the grant (reserveLLM), ends
// before the revocation commits, or starts after it and sees it. Until then
// the rollout took no such lock, and a reservation could read the grant
// while the revocation committed.
func TestARolloutRevokesItsTemplateGrantUnderTheOrganizationsRow(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	provider := createProvider(t, l, owner, "bp")
	if _, err := l.a.CreateLLMAlias(ctx, owner, "al1", CreateLLMAliasInput{Alias: "fast", ProviderID: provider.ID, UpstreamModel: "m"}); err != nil {
		t.Fatal(err)
	}
	if r, err := l.a.SetLLMAliasAccess(ctx, owner, "fast", "listed", SetLLMAliasAccessInput{Access: "listed"}); err != nil || r.Status != 200 {
		t.Fatal("set access", err, r.Status)
	}
	spec := rev.TemplateSpec
	spec.LLMProfile = "fast"
	if _, err := c.PublishTemplate(ctx, owner, "with-model", spec); err != nil {
		t.Fatal(err)
	}
	plan := testDeploymentPlan(t, c, owner, "plan", DeploymentRequest{Template: "support@2", Count: 1})
	if _, err := c.ApplyDeployment(ctx, owner, plan.ID, "apply"); err != nil {
		t.Fatal(err)
	}
	enrollments, err := l.s.PendingProvisioning(ctx, c.host, 10)
	if err != nil || len(enrollments) != 1 {
		t.Fatal(len(enrollments), err)
	}
	e := enrollments[0]
	if err = l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: 100}); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
	if err = l.s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	var grant string
	if err = l.s.pool.QueryRow(ctx, `SELECT template_grant_id FROM agent_specs WHERE agent_id=$1`, e.AgentID).Scan(&grant); err != nil {
		t.Fatal("the deployment's template grant", err)
	}
	// The next revision names no model alias: its install revokes the grant.
	spec.LLMProfile = ""
	if _, err = c.PublishTemplate(ctx, owner, "without-model", spec); err != nil {
		t.Fatal(err)
	}
	r, err := c.StartRollout(ctx, owner, plan.ID, "roll", RolloutInput{"support@3", 1})
	var roll Rollout
	if err != nil || json.Unmarshal(r.Body, &roll) != nil {
		t.Fatal(string(r.Body), err)
	}
	id, agent, err := l.s.NextRollout(ctx, c.host)
	if err != nil || id != roll.ID || agent != e.AgentID {
		t.Fatal(id, agent, err)
	}
	st, err := l.s.RolloutStep(ctx, id, agent, c.host, false)
	if err != nil || st.Stage != "draining" {
		t.Fatal(st, err)
	}
	// A reservation holds the organization's row, as reserveLLM does before
	// it reads the grant.
	admission, err := l.s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(admission)
	if _, err = admission.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR KEY SHARE`, owner.TenantID); err != nil {
		t.Fatal(err)
	}
	installed := make(chan error, 1)
	go func() { installed <- l.s.InstallRolloutSpec(context.Background(), st) }()
	select {
	case err = <-installed:
		t.Fatal("the rollout revoked the template grant while a reservation held the organization's row:", err)
	case <-time.After(500 * time.Millisecond):
	}
	// The reservation still sees the grant, and ends.
	if granted, err := aliasGranted(ctx, admission, owner.TenantID, "fast", agent); err != nil || !granted {
		t.Fatal("the reservation's grant", granted, err)
	}
	if err = admission.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-installed; err != nil {
		t.Fatal(err)
	}
	var status string
	if err = l.s.pool.QueryRow(ctx, `SELECT status FROM llm_alias_grants WHERE id=$1`, grant).Scan(&status); err != nil || status != "revoked" {
		t.Fatal("the template grant after the install", status, err)
	}
}
