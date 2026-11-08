// Package authorization evaluates the administrative role and agent-assignment
// policies of the organizational API. It does not authenticate credentials, read
// the database, or make a stale authorization snapshot safe to use.
//
// Callers must obtain identities, current status, roles, scopes and effective
// assignments from trusted sources. They must keep those facts authoritative in
// the transaction that consumes the decision, including an idempotent replay.
// Assignment resolution, team membership, revocation serialization, historical
// content visibility and preservation of the last organization owner belong to
// the control plane, not to this package.
package authorization

type Role string

const (
	OrgOwner      Role = "org_owner"
	OrgAdmin      Role = "org_admin"
	AgentOperator Role = "agent_operator"
	AgentUser     Role = "agent_user"
	Auditor       Role = "auditor"
)

type Action string

const (
	ReadOrganizationMetadata Action = "organization.read_metadata"
	ReadMemberMetadata       Action = "member.read_metadata"
	ReadTeamMetadata         Action = "team.read_metadata"
	ReadAgentMetadata        Action = "agent.read_metadata"
	ReadAudit                Action = "audit.read"
	ReadUsage                Action = "usage.read"
	ManageMembers            Action = "member.manage"
	ManageTeams              Action = "team.manage"
	ManageAssignments        Action = "agent.assign"
	CreateAgent              Action = "agent.create"
	ConfigureAgent           Action = "agent.configure"
	WakeAgent                Action = "agent.wake"
	SleepAgent               Action = "agent.sleep"
	DeleteAgent              Action = "agent.delete"
	ManageProviders          Action = "provider.manage"
	ManageQuotas             Action = "quota.manage"
	InvokeAgent              Action = "agent.invoke"
	ReadAgentContent         Action = "agent.read_content"
	ManageIdentities         Action = "identity.manage"
)

const (
	ScopeIdentityManage   = "identity:manage"
	ScopeOrganizationRead = "org:read"
	ScopeMemberRead       = "member:read"
	ScopeTeamRead         = "team:read"
	ScopeAgentRead        = "agent:read"
	ScopeAuditRead        = "audit:read"
	ScopeUsageRead        = "usage:read"
	ScopeMemberManage     = "member:manage"
	ScopeTeamManage       = "team:manage"
	ScopeAgentAssign      = "agent:assign"
	ScopeAgentCreate      = "agent:create"
	ScopeAgentOperate     = "agent:operate"
	ScopeAgentDelete      = "agent:delete"
	// ConfigureAgent is an internal administrative capability. Public create,
	// wake/sleep and delete endpoints use their distinct PRD scopes below.
	ScopeAgentManage      = "agent:manage"
	ScopeProviderManage   = "provider:manage"
	ScopeQuotaManage      = "quota:manage"
	ScopeAgentInvoke      = "agent:invoke"
	ScopeAgentContentRead = "agent:content:read"
)

// AccessContext is a snapshot of already authenticated, authoritative state.
// ResourceTenantID must come from the resource or the server's creation target,
// never unchecked request data. An empty tenant is not a platform-admin bypass.
type AccessContext struct {
	TenantID         string
	ResourceTenantID string
	PrincipalID      string
	TenantActive     bool
	PrincipalActive  bool
	Scopes           []string
}

type Permission string

const (
	PermissionReadMetadata Permission = "read_metadata"
	PermissionInvoke       Permission = "invoke"
	PermissionReadContent  Permission = "read_content"
)

func ValidRole(role Role) bool {
	switch role {
	case OrgOwner, OrgAdmin, AgentOperator, AgentUser, Auditor:
		return true
	default:
		return false
	}
}

// RoleAllows is only the role matrix. Administrative roles grant neither agent
// invocation nor content access. Metadata returned under these actions must be
// redacted by the resource serializer; this function cannot inspect a response.
func RoleAllows(role Role, action Action) bool {
	switch action {
	case ReadOrganizationMetadata, ReadMemberMetadata, ReadTeamMetadata, ReadAudit, ReadUsage:
		return role == OrgOwner || role == OrgAdmin || role == Auditor
	case ReadAgentMetadata:
		return role == OrgOwner || role == OrgAdmin || role == AgentOperator || role == Auditor
	case CreateAgent, ConfigureAgent, WakeAgent, SleepAgent:
		return role == OrgOwner || role == OrgAdmin || role == AgentOperator
	case ManageMembers, ManageTeams, ManageAssignments, DeleteAgent, ManageProviders, ManageQuotas, ManageIdentities:
		return role == OrgOwner || role == OrgAdmin
	default:
		return false
	}
}

// RequiredScope returns the exact credential scope for a known action. There
// are no implicit scope hierarchies or wildcard grants.
func RequiredScope(action Action) (string, bool) {
	switch action {
	case ReadOrganizationMetadata:
		return ScopeOrganizationRead, true
	case ReadMemberMetadata:
		return ScopeMemberRead, true
	case ReadTeamMetadata:
		return ScopeTeamRead, true
	case ReadAgentMetadata:
		return ScopeAgentRead, true
	case ReadAudit:
		return ScopeAuditRead, true
	case ReadUsage:
		return ScopeUsageRead, true
	case ManageIdentities:
		return ScopeIdentityManage, true
	case ManageMembers:
		return ScopeMemberManage, true
	case ManageTeams:
		return ScopeTeamManage, true
	case ManageAssignments:
		return ScopeAgentAssign, true
	case CreateAgent:
		return ScopeAgentCreate, true
	case WakeAgent, SleepAgent:
		return ScopeAgentOperate, true
	case DeleteAgent:
		return ScopeAgentDelete, true
	case ConfigureAgent:
		return ScopeAgentManage, true
	case ManageProviders:
		return ScopeProviderManage, true
	case ManageQuotas:
		return ScopeQuotaManage, true
	case InvokeAgent:
		return ScopeAgentInvoke, true
	case ReadAgentContent:
		return ScopeAgentContentRead, true
	default:
		return "", false
	}
}

func canUse(ctx AccessContext, action Action) bool {
	if ctx.TenantID == "" || ctx.ResourceTenantID != ctx.TenantID || ctx.PrincipalID == "" || !ctx.TenantActive || !ctx.PrincipalActive {
		return false
	}
	scope, known := RequiredScope(action)
	if !known {
		return false
	}
	for _, granted := range ctx.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// CanAdminister combines the role matrix with current identity and scope checks.
// ManageMembers is a prerequisite, not permission to alter every target member:
// use CanManageMember or CanChangeMemberRole for the target-specific decision.
func CanAdminister(ctx AccessContext, role Role, action Action) bool {
	return RoleAllows(role, action) && canUse(ctx, action)
}

func privileged(role Role) bool { return role == OrgOwner || role == OrgAdmin }

// CanManageMember protects an existing owner's or administrator's membership
// from changes by an administrator, including status changes and removal.
// targetRole must be read from the current membership, not the request body.
func CanManageMember(ctx AccessContext, actorRole, targetRole Role) bool {
	return ValidRole(targetRole) && CanAdminister(ctx, actorRole, ManageMembers) &&
		(!privileged(targetRole) || actorRole == OrgOwner)
}

// CanChangeMemberRole covers creation (currentRole empty), reassignment and
// removal (nextRole empty). An administrator cannot grant, modify or remove an
// owner/admin membership. It does not enforce the last-owner constraint, which
// requires a serialized view of all organization owners in the control plane.
func CanChangeMemberRole(ctx AccessContext, actorRole, currentRole, nextRole Role) bool {
	if (currentRole == "" && nextRole == "") ||
		(currentRole != "" && !ValidRole(currentRole)) ||
		(nextRole != "" && !ValidRole(nextRole)) {
		return false
	}
	if !CanAdminister(ctx, actorRole, ManageMembers) {
		return false
	}
	return actorRole == OrgOwner || (!privileged(currentRole) && !privileged(nextRole))
}

// CanAccessAssignedAgent evaluates effective permissions for this principal and
// this agent, resolved by the caller from current direct/team assignments. The
// caller must not reuse another agent's assignment list. No role is accepted as
// a substitute. Read-content and invoke permissions are independent; either
// assignment also permits redacted metadata with the separate metadata scope.
// This decision does not grant access to historical conversations or results.
func CanAccessAssignedAgent(ctx AccessContext, action Action, permissions []Permission) bool {
	if !canUse(ctx, action) {
		return false
	}
	for _, permission := range permissions {
		switch action {
		case ReadAgentMetadata:
			if permission == PermissionReadMetadata || permission == PermissionInvoke || permission == PermissionReadContent {
				return true
			}
		case InvokeAgent:
			if permission == PermissionInvoke {
				return true
			}
		case ReadAgentContent:
			if permission == PermissionReadContent {
				return true
			}
		}
	}
	return false
}

// CanManageServiceAccountRole decides which roles an actor may give to a
// technical account, create it with, or manage afterwards. A technical account
// is never an owner, and an administrator cannot create another administrator.
// The actor must be able to manage identities and must be a human credential:
// callers enforce the human requirement, which this function cannot see.
func CanManageServiceAccountRole(ctx AccessContext, actorRole, targetRole Role) bool {
	if !ValidRole(targetRole) || targetRole == OrgOwner || !CanAdminister(ctx, actorRole, ManageIdentities) {
		return false
	}
	return actorRole == OrgOwner || !privileged(targetRole)
}

// DelegableScopes lists the scopes a technical account token may carry. It is a
// closed registry: a scope is never invented from request data. identity:manage
// is deliberately absent because technical accounts cannot administer
// identities, and platform or legacy scopes never belong here.
var DelegableScopes = []string{
	ScopeOrganizationRead, ScopeMemberRead, ScopeMemberManage, ScopeTeamRead, ScopeTeamManage,
	ScopeAgentRead, ScopeAgentCreate, ScopeAgentAssign, ScopeAgentOperate, ScopeAgentDelete,
	ScopeAgentManage, ScopeAgentInvoke, ScopeAgentContentRead, ScopeProviderManage, ScopeQuotaManage,
	ScopeAuditRead, ScopeUsageRead,
}
