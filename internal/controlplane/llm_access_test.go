package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func price(v int64) *int64 { return &v }

func (b *budgetLab) grant(t *testing.T, alias, key string, in CreateLLMAliasGrantInput) LLMAliasGrant {
	t.Helper()
	r, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, alias, key, in)
	var g LLMAliasGrant
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &g) != nil {
		t.Fatal("create grant", err, r.Status)
	}
	return g
}

func (b *budgetLab) access(t *testing.T, alias, key, access string) {
	t.Helper()
	if r, err := b.a.SetLLMAliasAccess(t.Context(), b.owner, alias, key, SetLLMAliasAccessInput{Access: access}); err != nil || r.Status != 200 {
		t.Fatal("set access", err, r.Status)
	}
}

func (b *budgetLab) usageRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := b.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An alias stays open to every agent until the organization lists it; then
// only the agents its grants name, directly or through an active team
// assignment, may call it. A refusal reserves nothing.
func TestListedAliasServesOnlyGrantedAgentsAndTeams(t *testing.T) {
	b := newBudgetLab(t)
	if _, err := b.reserve(b.agent, "open-1", 10); err != nil {
		t.Fatal("an alias open to the organization refused its agent", err)
	}
	if _, err := b.reserve(b.other, "open-2", 10); err != nil {
		t.Fatal(err)
	}
	b.access(t, "fast", "listed", "listed")
	before := b.usageRows(t)
	for _, agent := range []string{b.agent, b.other} {
		if _, err := b.reserve(agent, "none-"+agent, 10); !errors.Is(err, ErrLLMAliasDenied) {
			t.Fatal("a listed alias without grants served an agent", err)
		}
	}
	if b.usageRows(t) != before {
		t.Fatal("a refused call reserved budget")
	}
	direct := b.grant(t, "fast", "g-agent", CreateLLMAliasGrantInput{AgentID: b.agent})
	if _, err := b.reserve(b.agent, "direct", 10); err != nil {
		t.Fatal("granted agent refused", err)
	}
	if _, err := b.reserve(b.other, "direct-other", 10); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("a grant to one agent served another", err)
	}
	// A team grant reaches the agents assigned to the team, whatever the
	// assignment's permissions, while the assignment and the team are active.
	team := createTeam(t, b.tenantLab, b.owner, "research")
	b.grant(t, "fast", "g-team", CreateLLMAliasGrantInput{TeamID: team.ID})
	if _, err := b.reserve(b.other, "team-before", 10); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("a team grant served an agent outside the team", err)
	}
	asg := assign(t, b.tenantLab, b.owner, b.other, CreateAssignmentInput{TeamID: team.ID, Permissions: []string{"read_metadata"}}, "asg")
	if _, err := b.reserve(b.other, "team-in", 10); err != nil {
		t.Fatal("an agent assigned to a granted team refused", err)
	}
	if _, err := b.a.RevokeAgentAssignment(t.Context(), b.owner, b.other, asg.ID, "asg-off"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.reserve(b.other, "team-revoked", 10); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("a revoked assignment kept model access", err)
	}
	assign(t, b.tenantLab, b.owner, b.other, CreateAssignmentInput{TeamID: team.ID, Permissions: []string{"invoke"}}, "asg-2")
	if _, err := b.a.DisableTeam(t.Context(), b.owner, team.ID, "team-off"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.reserve(b.other, "team-disabled", 10); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("a disabled team kept model access", err)
	}
	// Revoking the last grant leaves the alias closed, never open.
	if r, err := b.a.RevokeLLMAliasGrant(t.Context(), b.owner, "fast", direct.ID, "g-off"); err != nil || r.Status != 200 {
		t.Fatal("revoke", err)
	}
	if again, err := b.a.RevokeLLMAliasGrant(t.Context(), b.owner, "fast", direct.ID, "g-off-2"); err != nil || again.Status != 200 {
		t.Fatal("revoking a revoked grant is not a no-change", err)
	}
	if _, err := b.reserve(b.agent, "after-revoke", 10); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("a revoked grant kept model access", err)
	}
	b.access(t, "fast", "open", "organization")
	if _, err := b.reserve(b.other, "reopened", 10); err != nil {
		t.Fatal("an alias opened again refused an agent", err)
	}
	grants, err := b.a.ListLLMAliasGrants(t.Context(), b.owner, "fast", "", 50)
	if err != nil || len(grants) != 2 {
		t.Fatal("list grants", err, len(grants))
	}
	var actions []string
	rows, err := b.s.pool.Query(t.Context(), `SELECT action FROM llm_audit WHERE action LIKE 'alias.%' AND action<>'alias.created' ORDER BY created_at,id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	want := []string{"alias.access_set", "alias.grant_created", "alias.grant_created", "alias.grant_revoked", "alias.access_set"}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Fatal("audit", actions)
	}
}

func TestAliasGrantsAreValidatedAndAdministeredLikeAliases(t *testing.T) {
	b := newBudgetLab(t)
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "fast", "k1", CreateLLMAliasGrantInput{AgentID: b.agent, TeamID: "team_x"}); !errors.Is(err, ErrInput) {
		t.Fatal("a grant to an agent and a team", err)
	}
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "fast", "k2", CreateLLMAliasGrantInput{}); !errors.Is(err, ErrInput) {
		t.Fatal("a grant to nobody", err)
	}
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "fast", "k3", CreateLLMAliasGrantInput{AgentID: "agent-of-nobody"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("a grant to an unknown agent", err)
	}
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "missing", "k4", CreateLLMAliasGrantInput{AgentID: b.agent}); !errors.Is(err, ErrNotFound) {
		t.Fatal("a grant on an unknown alias", err)
	}
	b.grant(t, "fast", "k5", CreateLLMAliasGrantInput{AgentID: b.agent})
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "fast", "k6", CreateLLMAliasGrantInput{AgentID: b.agent}); !errors.Is(err, ErrConflict) {
		t.Fatal("a second active grant to the same agent", err)
	}
	if _, err := b.a.SetLLMAliasAccess(t.Context(), b.owner, "fast", "k7", SetLLMAliasAccessInput{Access: "everyone"}); !errors.Is(err, ErrInput) {
		t.Fatal("unknown access mode", err)
	}
	// The same rights as the alias routes: provider:manage and an admin role.
	addMember(t, b.tenantLab, b.owner, "operator", authorization.AgentOperator)
	op := agentPrincipal(t, b.tenantLab, "operator", agentScopes)
	if _, err := b.a.SetLLMAliasAccess(t.Context(), op, "fast", "k8", SetLLMAliasAccessInput{Access: "listed"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("an operator restricted an alias", err)
	}
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), op, "fast", "k9", CreateLLMAliasGrantInput{AgentID: b.other}); !errors.Is(err, ErrForbidden) {
		t.Fatal("an operator granted an alias", err)
	}
	if _, err := b.a.ListLLMAliasGrants(t.Context(), op, "fast", "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("an operator listed grants", err)
	}
	noScope := agentPrincipal(t, b.tenantLab, organizationInput().InitialOwner.Subject, "org:read quota:manage")
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), noScope, "fast", "k10", CreateLLMAliasGrantInput{AgentID: b.other}); !errors.Is(err, ErrForbidden) {
		t.Fatal("a credential without provider:manage granted an alias", err)
	}
	// A disabled alias takes no policy change.
	if _, err := b.a.DisableLLMAlias(t.Context(), b.owner, "fast", "off"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, "fast", "k11", CreateLLMAliasGrantInput{AgentID: b.other}); !errors.Is(err, ErrTransition) {
		t.Fatal("a grant on a disabled alias", err)
	}
}
