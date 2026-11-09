package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
)

const agentScopes = "org:read member:read member:manage team:read team:manage agent:read agent:create agent:assign agent:operate agent:manage agent:delete identity:manage audit:read agent:invoke agent:content:read provider:manage quota:manage usage:read"

func agentLab(t *testing.T) (*tenantLab, *AgentCatalog, Principal) {
	t.Helper()
	l := newTenantLab(t, false)
	l.trust.AllowedScopes = strings.Fields(agentScopes)
	var err error
	l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.cutoff = l.change(t, "install", "agents-install", "", &l.trust).MinimumIAT
	waitTenantClock(t, l.s, l.cutoff)
	c, err := NewAgentCatalog(l.a, "local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = l.s.ConfigureHostStorage(t.Context(), "local", 4096); err != nil {
		t.Fatal(err)
	}
	return l, c, agentPrincipal(t, l, organizationInput().InitialOwner.Subject, agentScopes)
}

func agentPrincipal(t *testing.T, l *tenantLab, subject, scopes string) Principal {
	t.Helper()
	raw := l.sign(t, newID("jti"), l.cutoff, func(c jwt.MapClaims) { c["sub"] = subject; c["scope"] = scopes })
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tenantAgentInput(name string) CreateAgentInput {
	return CreateAgentInput{Name: name, Harness: HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: AgentResources{1, 256, 256}}
}

func createTenantAgent(t *testing.T, c *AgentCatalog, p Principal, name string) string {
	t.Helper()
	r, err := c.Reserve(t.Context(), p, "create-"+name, tenantAgentInput(name))
	var created AgentCreation
	if err != nil || r.Status != 202 || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("create tenant agent", err, r.Status)
	}
	return created.AgentID
}

func assign(t *testing.T, l *tenantLab, p Principal, agent string, in CreateAssignmentInput, key string) AgentAssignment {
	t.Helper()
	r, err := l.a.CreateAgentAssignment(t.Context(), p, agent, key, in)
	var s AgentAssignment
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &s) != nil {
		t.Fatal("create assignment", err, r.Status)
	}
	return s
}

func visibleAgents(t *testing.T, c *AgentCatalog, p Principal) []string {
	t.Helper()
	items, err := c.ListTenantAgents(t.Context(), p, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, a := range items {
		ids = append(ids, a.ID)
	}
	return ids
}

// The first demonstration of the plan: several agents per tenant, a shared
// assignment through a team, and a revoked member who loses access while the
// agent survives.
func TestTenantAgentsAssignmentsAndRevokedMemberKeepsAgent(t *testing.T) {
	l, c, owner := agentLab(t)
	a1 := createTenantAgent(t, c, owner, "alpha")
	a2 := createTenantAgent(t, c, owner, "beta")
	a3 := createTenantAgent(t, c, owner, "gamma")
	if a1 == a2 || a2 == a3 {
		t.Fatal("agents are not distinct")
	}
	alice := addMember(t, l, owner, "alice", authorization.AgentUser)
	bob := addMember(t, l, owner, "bob", authorization.AgentUser)
	addMember(t, l, owner, "carol", authorization.AgentUser)
	as := func(subject string) Principal { return agentPrincipal(t, l, subject, "org:read agent:read") }

	// Without any assignment an ordinary member sees and learns nothing.
	if got := visibleAgents(t, c, as("alice")); len(got) != 0 {
		t.Fatal("unassigned member sees agents", got)
	}
	if _, err := c.GetTenantAgent(t.Context(), as("alice"), a1); !errors.Is(err, ErrNotFound) {
		t.Fatal("unassigned member can distinguish an agent", err)
	}
	// An administrative role sees metadata of every agent of its tenant.
	if got := visibleAgents(t, c, owner); len(got) != 3 {
		t.Fatal("owner does not see its tenant agents", got)
	}

	team := createTeam(t, l, owner, "ops")
	if r, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "join-bob", AddTeamMemberInput{PrincipalID: bob.PrincipalID}); err != nil || r.Status != 201 {
		t.Fatal("add team member", err, r.Status)
	}
	direct := assign(t, l, owner, a1, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "asg-alice")
	shared := assign(t, l, owner, a2, CreateAssignmentInput{TeamID: team.ID, Permissions: []string{"read_metadata"}}, "asg-team")
	if got := visibleAgents(t, c, as("alice")); len(got) != 1 || got[0] != a1 {
		t.Fatal("direct assignment not honored", got)
	}
	if got := visibleAgents(t, c, as("bob")); len(got) != 1 || got[0] != a2 {
		t.Fatal("team assignment not honored", got)
	}
	if got := visibleAgents(t, c, as("carol")); len(got) != 0 {
		t.Fatal("assignment leaked to an unrelated member", got)
	}
	if _, err := l.a.CreateAgentAssignment(t.Context(), owner, a1, "again", CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"invoke"}}); !errors.Is(err, ErrTransition) {
		t.Fatal("duplicate active assignment accepted", err)
	}

	// Removing bob from the team removes the access it conferred.
	if _, err := l.a.RevokeTeamMember(t.Context(), owner, team.ID, bob.PrincipalID, "leave-bob"); err != nil {
		t.Fatal(err)
	}
	if got := visibleAgents(t, c, as("bob")); len(got) != 0 {
		t.Fatal("team access survived leaving the team", got)
	}

	// Revoking the member ends the credential; the agent remains. A principal
	// authenticated before the revocation is refused by the transactional
	// recheck, and a new authentication fails outright.
	before := as("alice")
	if _, err := l.a.RevokeMember(t.Context(), owner, alice.PrincipalID, "revoke-alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListTenantAgents(t.Context(), before, "", 100); err == nil {
		t.Fatal("revoked member can still read through an earlier authentication")
	}
	raw := l.sign(t, newID("jti"), l.cutoff, func(c jwt.MapClaims) { c["sub"] = "alice"; c["scope"] = "org:read agent:read" })
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw); err == nil {
		t.Fatal("revoked member authenticates again")
	}
	if got := visibleAgents(t, c, owner); len(got) != 3 {
		t.Fatal("offboarding removed or hid an organization agent", got)
	}

	// Revoking an assignment is explicit, audited and idempotent.
	r, err := l.a.RevokeAgentAssignment(t.Context(), owner, a2, shared.ID, "revoke-shared")
	if err != nil || r.Status != 200 {
		t.Fatal("revoke assignment", err, r.Status)
	}
	if again, err := l.a.RevokeAgentAssignment(t.Context(), owner, a2, shared.ID, "revoke-shared-2"); err != nil || again.Status != 200 {
		t.Fatal("second revoke is not idempotent", err)
	}
	var audits int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM tenant_agent_audit WHERE tenant_id=$1`, l.org.ID).Scan(&audits); err != nil || audits != 3+2+1 {
		t.Fatal("audit trail incomplete", audits, err)
	}
	_ = direct
}

func TestTenantAgentsStayInvisibleToTheLegacyDomain(t *testing.T) {
	l, c, owner := agentLab(t)
	id := createTenantAgent(t, c, owner, "private")
	if items, err := c.List(t.Context(), l.legacy, "", 100); err != nil || len(items) != 0 {
		t.Fatal("legacy service lists a tenant agent", items, err)
	}
	if _, err := c.Get(t.Context(), l.legacy, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy service reads a tenant agent", err)
	}
	if _, err := c.RequestLifecycle(t.Context(), l.legacy, id, "wake", "wake"); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy service wakes a tenant agent", err)
	}
	if _, err := c.Delete(t.Context(), l.legacy, id, "delete"); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy service deletes a tenant agent", err)
	}
}

func TestTenantAgentAuthorizationBoundaries(t *testing.T) {
	l, c, owner := agentLab(t)
	id := createTenantAgent(t, c, owner, "guarded")
	member := addMember(t, l, owner, "dave", authorization.AgentUser)
	user := agentPrincipal(t, l, "dave", agentScopes)
	// A member role cannot create agents or assignments even with the scopes.
	if _, err := c.Reserve(t.Context(), user, "nope", tenantAgentInput("nope")); !errors.Is(err, ErrForbidden) {
		t.Fatal("agent_user created an agent", err)
	}
	if _, err := l.a.CreateAgentAssignment(t.Context(), user, id, "nope", CreateAssignmentInput{PrincipalID: member.PrincipalID, Permissions: []string{"read_content"}}); !errors.Is(err, ErrForbidden) {
		t.Fatal("agent_user granted itself content access", err)
	}
	// A token without the scope is refused before anything is read.
	noScope := agentPrincipal(t, l, organizationInput().InitialOwner.Subject, "org:read")
	if _, err := c.ListTenantAgents(t.Context(), noScope, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("missing scope accepted", err)
	}
	// Invalid input is rejected: both or neither target, unknown permission.
	for _, in := range []CreateAssignmentInput{
		{Permissions: []string{"invoke"}},
		{PrincipalID: member.PrincipalID, TeamID: "t", Permissions: []string{"invoke"}},
		{PrincipalID: member.PrincipalID, Permissions: []string{"admin"}},
		{PrincipalID: member.PrincipalID, Permissions: []string{"invoke", "invoke"}},
		{PrincipalID: member.PrincipalID},
	} {
		if _, err := l.a.CreateAgentAssignment(t.Context(), owner, id, "bad", in); !errors.Is(err, ErrInput) {
			t.Fatal("invalid assignment accepted", in, err)
		}
	}
	// A principal or agent that does not exist in this tenant is not found.
	if _, err := l.a.CreateAgentAssignment(t.Context(), owner, id, "ghost", CreateAssignmentInput{PrincipalID: "prn_ghost", Permissions: []string{"invoke"}}); !errors.Is(err, ErrNotFound) {
		t.Fatal("assignment to a foreign principal accepted", err)
	}
	if _, err := l.a.CreateAgentAssignment(t.Context(), owner, "agt_ghost", "ghost2", CreateAssignmentInput{PrincipalID: member.PrincipalID, Permissions: []string{"invoke"}}); !errors.Is(err, ErrNotFound) {
		t.Fatal("assignment on a foreign agent accepted", err)
	}
	// Several agents for one owner are allowed in the tenant domain.
	createTenantAgent(t, c, owner, "second")
}

// A tenant agent has no owner user. It must still pass through the existing
// provisioning, activation and automatic-wake machinery unchanged.
func TestTenantAgentFollowsTheExistingProvisioningPipeline(t *testing.T) {
	l, c, owner := agentLab(t)
	in := tenantAgentInput("auto")
	in.AutoStart = true
	r, err := c.Reserve(t.Context(), owner, "auto", in)
	var created AgentCreation
	if err != nil || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("reserve", err)
	}
	jobs, err := l.s.PendingProvisioning(t.Context(), "local", 20)
	if err != nil || len(jobs) != 1 || jobs[0].AgentID != created.AgentID || jobs[0].Stage != "INSTALLING" {
		t.Fatal("worker cannot discover the tenant reservation", jobs, err)
	}
	e := jobs[0]
	observeTestVolume(t, l.s, e)
	retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
	if err = l.s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal("activation of a tenant agent:", err)
	}
	assertPhase(t, l.s, e.AgentID, "LIVE")
	var wakes int
	var ownerless bool
	var requester string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*),coalesce(bool_and(owner_user_id IS NULL),false),coalesce(min(requested_by_principal_id),'')
        FROM platform_operations WHERE agent_id=$1 AND kind='wake'`, e.AgentID).Scan(&wakes, &ownerless, &requester); err != nil {
		t.Fatal(err)
	}
	if wakes != 1 || !ownerless || requester != owner.ID {
		t.Fatal("automatic wake lost its requester or invented an owner", wakes, ownerless, requester)
	}
	op, err := c.Operation(t.Context(), owner, created.OperationID)
	if err != nil || op.Status != "SUCCEEDED" {
		t.Fatal("requester cannot follow its operation", op, err)
	}
	// An ordinary member of the same tenant cannot follow someone else's operation.
	addMember(t, l, owner, "erin", authorization.AgentUser)
	other := agentPrincipal(t, l, "erin", "org:read agent:read")
	if _, err = c.Operation(t.Context(), other, created.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("operation visible to a member who did not request it", err)
	}
	view, err := c.GetTenantAgent(t.Context(), owner, e.AgentID)
	if err != nil || view.Name != "auto" {
		t.Fatal("activated tenant agent not readable", view, err)
	}
}

// activateTenantAgent drives a reservation to LIVE the way the worker does.
func activateTenantAgent(t *testing.T, l *tenantLab, c *AgentCatalog, owner Principal, name string) string {
	t.Helper()
	r, err := c.Reserve(t.Context(), owner, "activate-"+name, tenantAgentInput(name))
	var created AgentCreation
	if err != nil || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("reserve", err)
	}
	jobs, err := l.s.PendingProvisioning(t.Context(), "local", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID != created.AgentID {
			continue
		}
		observeTestVolume(t, l.s, e)
		retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
		if err = l.s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		return created.AgentID
	}
	t.Fatal("reservation not discoverable")
	return ""
}

func TestTenantAgentLifecycleIsGovernedByTheCurrentRole(t *testing.T) {
	l, c, owner := agentLab(t)
	id := activateTenantAgent(t, l, c, owner, "lifecycle")
	pending := createTenantAgent(t, c, owner, "not-yet-live")
	roles := map[string]authorization.Role{"operator": authorization.AgentOperator, "plain": authorization.AgentUser, "auditor": authorization.Auditor, "admin": authorization.OrgAdmin}
	people := map[string]Principal{}
	for subject, role := range roles {
		addMember(t, l, owner, subject, role)
		people[subject] = agentPrincipal(t, l, subject, agentScopes)
	}
	// Waking and sleeping need operate rights; plain members and auditors have none.
	for subject, want := range map[string]bool{"operator": true, "admin": true, "plain": false, "auditor": false} {
		_, err := c.RequestLifecycle(t.Context(), people[subject], id, "wake-"+subject, "wake")
		if want && err != nil || !want && !errors.Is(err, ErrForbidden) {
			t.Fatal("wake", subject, want, err)
		}
	}
	if _, err := c.RequestLifecycle(t.Context(), people["operator"], pending, "wake-early", "wake"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("woke an agent that is still provisioning", err)
	}
	r, err := c.RequestLifecycle(t.Context(), owner, id, "sleep-1", "sleep")
	again, err2 := c.RequestLifecycle(t.Context(), owner, id, "sleep-1", "sleep")
	if err != nil || err2 != nil || r.Status != 202 || !again.Replayed || string(again.Body) != string(r.Body) {
		t.Fatal("sleep command not durable and replayable", err, err2)
	}
	// Deleting is reserved to owners and administrators.
	if _, err = c.Delete(t.Context(), people["operator"], id, "del-op"); !errors.Is(err, ErrForbidden) {
		t.Fatal("operator deleted an agent", err)
	}
	first, err := c.Delete(t.Context(), people["admin"], id, "del-1")
	second, err2 := c.Delete(t.Context(), owner, id, "del-2")
	var a, b AgentCreation
	if err != nil || err2 != nil || json.Unmarshal(first.Body, &a) != nil || json.Unmarshal(second.Body, &b) != nil || a.OperationID == "" || a.OperationID != b.OperationID {
		t.Fatal("deletions with distinct keys do not share one operation", err, err2)
	}
	assertPhase(t, l.s, id, "QUIESCING")
	if _, err = c.RequestLifecycle(t.Context(), owner, id, "wake-after-delete", "wake"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("agent woke after its deletion was requested", err)
	}
	// An agent of the tenant that does not exist for the caller is not found.
	if _, err = c.Delete(t.Context(), owner, "agt_ghost", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleting an unknown agent", err)
	}
}
