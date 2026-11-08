package authorization_test

import (
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func activeContext(scopes ...string) authorization.AccessContext {
	return authorization.AccessContext{
		TenantID: "tenant-a", ResourceTenantID: "tenant-a", PrincipalID: "member-a",
		TenantActive: true, PrincipalActive: true, Scopes: scopes,
	}
}

func TestAdministrativeRoles(t *testing.T) {
	// These expected capabilities express the product role contract, independently
	// of the policy's switch and scope grouping. Content actions belong to nobody.
	roles := []authorization.Role{authorization.OrgOwner, authorization.OrgAdmin, authorization.AgentOperator, authorization.AgentUser, authorization.Auditor}
	tests := []struct {
		action authorization.Action
		want   [5]bool
	}{
		{authorization.ReadOrganizationMetadata, [5]bool{true, true, false, false, true}},
		{authorization.ReadMemberMetadata, [5]bool{true, true, false, false, true}},
		{authorization.ReadTeamMetadata, [5]bool{true, true, false, false, true}},
		{authorization.ReadAgentMetadata, [5]bool{true, true, true, false, true}},
		{authorization.ReadAudit, [5]bool{true, true, false, false, true}},
		{authorization.ReadUsage, [5]bool{true, true, false, false, true}},
		{authorization.ManageMembers, [5]bool{true, true, false, false, false}},
		{authorization.ManageTeams, [5]bool{true, true, false, false, false}},
		{authorization.ManageAssignments, [5]bool{true, true, false, false, false}},
		{authorization.CreateAgent, [5]bool{true, true, true, false, false}},
		{authorization.ConfigureAgent, [5]bool{true, true, true, false, false}},
		{authorization.WakeAgent, [5]bool{true, true, true, false, false}},
		{authorization.SleepAgent, [5]bool{true, true, true, false, false}},
		{authorization.DeleteAgent, [5]bool{true, true, false, false, false}},
		{authorization.ManageProviders, [5]bool{true, true, false, false, false}},
		{authorization.ManageQuotas, [5]bool{true, true, false, false, false}},
		{authorization.ManageIdentities, [5]bool{true, true, false, false, false}},
		{authorization.InvokeAgent, [5]bool{}},
		{authorization.ReadAgentContent, [5]bool{}},
	}
	for _, test := range tests {
		t.Run(string(test.action), func(t *testing.T) {
			scope, known := authorization.RequiredScope(test.action)
			if !known || scope == "" {
				t.Fatal("known action has no credential scope")
			}
			for i, role := range roles {
				if got := authorization.CanAdminister(activeContext(scope), role, test.action); got != test.want[i] {
					t.Errorf("role %s: got %v, want %v", role, got, test.want[i])
				}
			}
		})
	}
}

func TestAdministrativeRoleCannotEscalateMemberships(t *testing.T) {
	ctx := activeContext(authorization.ScopeMemberManage)
	ordinary := []authorization.Role{authorization.AgentOperator, authorization.AgentUser, authorization.Auditor}
	privileged := []authorization.Role{authorization.OrgOwner, authorization.OrgAdmin}
	for _, high := range privileged {
		if authorization.CanManageMember(ctx, authorization.OrgAdmin, high) {
			t.Errorf("administrator can disable/remove %s", high)
		}
		for _, other := range append(append([]authorization.Role{""}, ordinary...), privileged...) {
			if authorization.CanChangeMemberRole(ctx, authorization.OrgAdmin, other, high) {
				t.Errorf("administrator can grant %s from %q", high, other)
			}
			if authorization.CanChangeMemberRole(ctx, authorization.OrgAdmin, high, other) {
				t.Errorf("administrator can alter existing %s into %q", high, other)
			}
		}
		if !authorization.CanManageMember(ctx, authorization.OrgOwner, high) || !authorization.CanChangeMemberRole(ctx, authorization.OrgOwner, authorization.AgentUser, high) {
			t.Errorf("owner cannot manage privileged role %s", high)
		}
	}
	for _, target := range ordinary {
		if !authorization.CanManageMember(ctx, authorization.OrgAdmin, target) || !authorization.CanChangeMemberRole(ctx, authorization.OrgAdmin, "", target) || !authorization.CanChangeMemberRole(ctx, authorization.OrgAdmin, target, "") {
			t.Errorf("administrator cannot manage ordinary role %s", target)
		}
		for _, actor := range ordinary {
			if authorization.CanManageMember(ctx, actor, target) || authorization.CanChangeMemberRole(ctx, actor, "", target) {
				t.Errorf("role %s obtained member management", actor)
			}
		}
	}
}

func TestPublicScopesDoNotImplyOtherOperations(t *testing.T) {
	// Literal scopes pin the public PRD contract rather than deriving expected
	// values from the mapping being tested.
	tests := []struct {
		action authorization.Action
		scope  string
	}{
		{authorization.ReadOrganizationMetadata, "org:read"},
		{authorization.ReadTeamMetadata, "team:read"},
		{authorization.ManageTeams, "team:manage"},
		{authorization.CreateAgent, "agent:create"},
		{authorization.WakeAgent, "agent:operate"},
		{authorization.SleepAgent, "agent:operate"},
		{authorization.DeleteAgent, "agent:delete"},
		{authorization.ConfigureAgent, "agent:manage"},
	}
	scopes := []string{"org:read", "organization:read", "team:read", "team:manage", "member:read", "member:manage", "agent:create", "agent:operate", "agent:delete", "agent:manage", "*", "agent:*", ""}
	for _, test := range tests {
		t.Run(string(test.action), func(t *testing.T) {
			if got, known := authorization.RequiredScope(test.action); !known || got != test.scope {
				t.Fatalf("scope %q, want public scope %q", got, test.scope)
			}
			for _, scope := range scopes {
				if got := authorization.CanAdminister(activeContext(scope), authorization.OrgOwner, test.action); got != (scope == test.scope) {
					t.Errorf("scope %q authorizes %s: %v", scope, test.action, got)
				}
			}
		})
	}
}

func TestAssignmentsAndScopesAreIndependentRequirements(t *testing.T) {
	ctx := activeContext(authorization.ScopeAgentRead, authorization.ScopeAgentInvoke, authorization.ScopeAgentContentRead, authorization.ScopeAgentManage)
	for _, action := range []authorization.Action{authorization.ReadAgentMetadata, authorization.InvokeAgent, authorization.ReadAgentContent} {
		if authorization.CanAccessAssignedAgent(ctx, action, nil) {
			t.Errorf("unassigned principal can %s", action)
		}
	}
	if !authorization.CanAccessAssignedAgent(ctx, authorization.InvokeAgent, []authorization.Permission{authorization.PermissionInvoke}) {
		t.Fatal("assigned invoker cannot invoke")
	}
	if authorization.CanAccessAssignedAgent(ctx, authorization.ReadAgentContent, []authorization.Permission{authorization.PermissionInvoke}) {
		t.Fatal("invocation permission implies content visibility")
	}
	if authorization.CanAccessAssignedAgent(ctx, authorization.InvokeAgent, []authorization.Permission{authorization.PermissionReadContent}) {
		t.Fatal("content reader obtained invocation permission")
	}
	if !authorization.CanAccessAssignedAgent(ctx, authorization.ReadAgentContent, []authorization.Permission{authorization.PermissionReadContent}) {
		t.Fatal("explicit content reader denied")
	}
	for _, permission := range []authorization.Permission{authorization.PermissionReadMetadata, authorization.PermissionInvoke, authorization.PermissionReadContent} {
		if !authorization.CanAccessAssignedAgent(ctx, authorization.ReadAgentMetadata, []authorization.Permission{permission}) {
			t.Errorf("assigned principal cannot read redacted metadata: %s", permission)
		}
		if authorization.CanAccessAssignedAgent(ctx, authorization.DeleteAgent, []authorization.Permission{permission}) {
			t.Fatal("assignment grants administrative deletion")
		}
	}
	for _, scope := range []string{authorization.ScopeAgentRead, authorization.ScopeAgentManage, "*", "agent:*", ""} {
		limited := activeContext(scope)
		if authorization.CanAccessAssignedAgent(limited, authorization.InvokeAgent, []authorization.Permission{authorization.PermissionInvoke}) || authorization.CanAccessAssignedAgent(limited, authorization.ReadAgentContent, []authorization.Permission{authorization.PermissionReadContent}) {
			t.Errorf("scope %q implies content access", scope)
		}
	}
}

func TestInactiveOrForeignContextIsDenied(t *testing.T) {
	tests := []struct {
		name   string
		change func(*authorization.AccessContext)
	}{
		{"foreign-tenant", func(c *authorization.AccessContext) { c.ResourceTenantID = "tenant-b" }},
		{"missing-resource-tenant", func(c *authorization.AccessContext) { c.ResourceTenantID = "" }},
		{"missing-both-tenants", func(c *authorization.AccessContext) { c.TenantID, c.ResourceTenantID = "", "" }},
		{"missing-principal", func(c *authorization.AccessContext) { c.PrincipalID = "" }},
		{"disabled-tenant", func(c *authorization.AccessContext) { c.TenantActive = false }},
		{"disabled-principal", func(c *authorization.AccessContext) { c.PrincipalActive = false }},
		{"missing-scopes", func(c *authorization.AccessContext) { c.Scopes = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := activeContext(authorization.ScopeAgentDelete, authorization.ScopeMemberManage, authorization.ScopeAgentInvoke, authorization.ScopeAgentContentRead)
			test.change(&ctx)
			if authorization.CanAdminister(ctx, authorization.OrgOwner, authorization.DeleteAgent) || authorization.CanManageMember(ctx, authorization.OrgOwner, authorization.AgentUser) || authorization.CanChangeMemberRole(ctx, authorization.OrgOwner, authorization.AgentUser, authorization.OrgAdmin) {
				t.Fatal("administrative role bypassed identity boundary")
			}
			for _, action := range []authorization.Action{authorization.InvokeAgent, authorization.ReadAgentContent} {
				if authorization.CanAccessAssignedAgent(ctx, action, []authorization.Permission{authorization.PermissionInvoke, authorization.PermissionReadContent}) {
					t.Fatal("assignment bypassed identity boundary")
				}
			}
		})
	}
}

func TestUnknownPolicyValuesFailClosed(t *testing.T) {
	ctx := activeContext(authorization.ScopeMemberManage, authorization.ScopeAgentRead, authorization.ScopeAgentInvoke, authorization.ScopeAgentContentRead)
	for _, role := range []authorization.Role{"", "admin", "service", "ORG_OWNER"} {
		if authorization.ValidRole(role) || authorization.RoleAllows(role, authorization.ManageMembers) || authorization.CanManageMember(ctx, authorization.OrgOwner, role) || authorization.CanChangeMemberRole(ctx, authorization.OrgOwner, authorization.AgentUser, role) && role != "" {
			t.Errorf("unknown role %q accepted", role)
		}
	}
	if authorization.CanChangeMemberRole(ctx, authorization.OrgOwner, "", "") {
		t.Fatal("empty role change accepted")
	}
	for _, action := range []authorization.Action{"", "agent.all", "organization.delete"} {
		if scope, known := authorization.RequiredScope(action); known || scope != "" {
			t.Errorf("unknown action %q has scope", action)
		}
		if authorization.RoleAllows(authorization.OrgOwner, action) || authorization.CanAccessAssignedAgent(ctx, action, []authorization.Permission{authorization.PermissionInvoke, authorization.PermissionReadContent}) {
			t.Errorf("unknown action %q authorized", action)
		}
	}
	for _, action := range []authorization.Action{authorization.ReadAgentMetadata, authorization.InvokeAgent, authorization.ReadAgentContent} {
		if authorization.CanAccessAssignedAgent(ctx, action, []authorization.Permission{"", "*", "admin"}) {
			t.Errorf("unknown permission authorized %s", action)
		}
	}
}

func TestServiceAccountRoleRules(t *testing.T) {
	ctx := authorization.AccessContext{TenantID: "t", ResourceTenantID: "t", PrincipalID: "p", TenantActive: true, PrincipalActive: true, Scopes: []string{authorization.ScopeIdentityManage}}
	roles := []authorization.Role{authorization.OrgOwner, authorization.OrgAdmin, authorization.AgentOperator, authorization.AgentUser, authorization.Auditor}
	// Rows are actors, columns are target roles, in the order of roles.
	want := map[authorization.Role][5]bool{
		authorization.OrgOwner:      {false, true, true, true, true},
		authorization.OrgAdmin:      {false, false, true, true, true},
		authorization.AgentOperator: {},
		authorization.AgentUser:     {},
		authorization.Auditor:       {},
	}
	for actor, row := range want {
		for i, target := range roles {
			if got := authorization.CanManageServiceAccountRole(ctx, actor, target); got != row[i] {
				t.Errorf("actor %s target %s: got %v want %v", actor, target, got, row[i])
			}
		}
	}
	if authorization.CanManageServiceAccountRole(authorization.AccessContext{}, authorization.OrgOwner, authorization.AgentUser) {
		t.Error("an empty access context managed a service account")
	}
	noScope := ctx
	noScope.Scopes = []string{authorization.ScopeMemberManage}
	if authorization.CanManageServiceAccountRole(noScope, authorization.OrgOwner, authorization.AgentUser) {
		t.Error("identity:manage is required, member:manage is not enough")
	}
	if authorization.CanManageServiceAccountRole(ctx, authorization.OrgOwner, "") || authorization.CanManageServiceAccountRole(ctx, authorization.OrgOwner, "root") {
		t.Error("an invalid target role was accepted")
	}
}

func TestDelegableScopesAreAClosedRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, scope := range authorization.DelegableScopes {
		if seen[scope] {
			t.Errorf("duplicate delegable scope %s", scope)
		}
		seen[scope] = true
		if scope == authorization.ScopeIdentityManage || scope == "platform:admin" || strings.ContainsAny(scope, "*") {
			t.Errorf("scope %s must never be delegable to a technical account", scope)
		}
	}
}
