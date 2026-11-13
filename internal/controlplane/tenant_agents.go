package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// TenantAgent is the redacted metadata of an agent owned by a tenant. It never
// carries conversation content, and administrative roles do not unlock content.
type TenantAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"`
	HarnessDigest string `json:"harness_digest"`
	// Harness is the release the agent is pinned to; it boots at the next start.
	Harness   HarnessReference `json:"harness"`
	Resources AgentResources   `json:"resources"`
	CreatedAt time.Time        `json:"created_at"`
	// DesiredState is what the lifecycle ledger asks for: running, stopped or
	// deleted. State is what the platform observes. Converged says they agree. It
	// reports; it does not restart a stopped agent by itself.
	DesiredState string `json:"desired_state"`
	Converged    bool   `json:"converged"`
	// IdleTimeoutSeconds is the idle-closure policy, absent when disabled.
	IdleTimeoutSeconds *int `json:"idle_timeout_seconds,omitempty"`
}

// AgentAssignment grants permissions on one agent to one principal or to every
// active member of one team. Permissions are read_metadata, invoke, read_content.
type AgentAssignment struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	PrincipalID *string    `json:"principal_id,omitempty"`
	TeamID      *string    `json:"team_id,omitempty"`
	Permissions []string   `json:"permissions"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type CreateAssignmentInput struct {
	PrincipalID string   `json:"principal_id,omitempty"`
	TeamID      string   `json:"team_id,omitempty"`
	Permissions []string `json:"permissions"`
}

const tenantAgentColumns = `a.id,x.name,
        CASE WHEN a.phase<>'LIVE' THEN a.phase
          WHEN p.state='RUNNING' AND NOT p.fence_only AND pc.agent_id IS NOT NULL THEN 'READY'
          WHEN p.state='RUNNING' THEN 'STARTING' ELSE coalesce(p.state,'STOPPED') END,
        r.artifact_digest,r.name,r.version,x.vcpus,x.memory_mib,x.volume_mib,x.created_at,
        CASE WHEN a.phase IN ('QUIESCING','DELETING','DELETED') THEN 'deleted' ELSE coalesce((SELECT CASE o.kind WHEN 'wake' THEN 'running' ELSE 'stopped' END
          FROM platform_operations o WHERE o.agent_id=a.id AND o.kind IN ('wake','sleep') AND o.status IN ('PENDING','RUNNING','SUCCEEDED')
          ORDER BY o.seq DESC LIMIT 1), CASE WHEN x.auto_start THEN 'running' ELSE 'stopped' END) END,x.idle_timeout_seconds`

// effectivePermissions are the permissions the principal holds on the agent
// right now: direct assignments plus those of teams it actively belongs to.
const effectivePermissions = `coalesce((SELECT array_agg(DISTINCT perm) FROM agent_assignments s, unnest(s.permissions) perm
        WHERE s.tenant_id=a.tenant_id AND s.agent_id=a.id AND s.status='active' AND (s.principal_id=$2 OR s.team_id IN
          (SELECT m.team_id FROM team_memberships m JOIN teams t ON (t.tenant_id,t.id)=(m.tenant_id,m.team_id)
           WHERE m.tenant_id=a.tenant_id AND m.principal_id=$2 AND m.status='active' AND t.status='active'))),'{}')`

func scanTenantAgent(row pgx.Row, perms *[]string) (TenantAgent, error) {
	var v TenantAgent
	var sink []string
	if perms == nil {
		perms = &sink
	}
	err := row.Scan(&v.ID, &v.Name, &v.State, &v.HarnessDigest, &v.Harness.Name, &v.Harness.Version, &v.Resources.VCPUs, &v.Resources.MemoryMiB, &v.Resources.DataVolumeMiB, &v.CreatedAt, &v.DesiredState, &v.IdleTimeoutSeconds, perms)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	v.Converged = (v.DesiredState == "running" && v.State == "READY") ||
		(v.DesiredState == "stopped" && v.State == "STOPPED") ||
		(v.DesiredState == "deleted" && v.State == "DELETED")
	return v, err
}

func toPermissions(in []string) []authorization.Permission {
	out := make([]authorization.Permission, 0, len(in))
	for _, p := range in {
		out = append(out, authorization.Permission(p))
	}
	return out
}

// canSeeTenantAgent applies the metadata decision: an administrative role that
// may read agent metadata, or any assignment on this agent for this principal.
func canSeeTenantAgent(p Principal, role string, perms []string) bool {
	access := tenantAccess(p)
	return authorization.CanAdminister(access, authorization.Role(role), authorization.ReadAgentMetadata) ||
		authorization.CanAccessAssignedAgent(access, authorization.ReadAgentMetadata, toPermissions(perms))
}

// ReserveTenant creates a tenant-owned agent reservation. Like Reserve it only
// records a durable provisioning operation; the worker creates the volume.
func (c *AgentCatalog) reserveTenant(ctx context.Context, p Principal, key string, in CreateAgentInput) (APIReceipt, error) {
	if in.OwnerUserID != "" || !displayName(in.Name) || !catalogName(in.Harness.Name) || !catalogName(in.Harness.Version) {
		return APIReceipt{}, ErrInput
	}
	r := in.Resources
	if r.VCPUs < 1 || r.VCPUs > 8 || r.MemoryMiB < 128 || r.MemoryMiB > 8192 || r.DataVolumeMiB < 64 || r.DataVolumeMiB > 32768 {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.CreateAgent); err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.create", key, in, func() (int, any, error) {
		var release string
		err := tx.QueryRow(ctx, "SELECT id FROM harness_releases WHERE name=$1 AND version=$2 AND enabled FOR SHARE", in.Harness.Name, in.Harness.Version).Scan(&release)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrRelease
		}
		if err != nil {
			return 0, nil, err
		}
		if err = lockWorkerHost(ctx, tx, c.host); err != nil {
			return 0, nil, err
		}
		var available bool
		err = tx.QueryRow(ctx, `SELECT storage_limit_mib>0 AND storage_limit_mib >= $2::bigint +
            (SELECT coalesce(sum(x.volume_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=$1 AND a.phase<>'DELETED')
            FROM worker_hosts WHERE host_id=$1`, c.host, r.DataVolumeMiB).Scan(&available)
		if err != nil {
			return 0, nil, err
		}
		if !available {
			return 0, nil, ErrStorageCapacity
		}
		id, op := newID("agt"), newID("op")
		if _, err = tx.Exec(ctx, "INSERT INTO agents(id,tenant_id,phase) VALUES($1,$2,'PROVISIONING')", id, p.TenantID); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO agent_specs(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, in.Name, release, c.host, r.VCPUs, r.MemoryMiB, r.DataVolumeMiB, in.AutoStart); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
            VALUES($1,$2,$3,$4,1,'provision')`, op, p.ID, id, c.host); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO store_enrollments(agent_id,operation_id,volume_id) VALUES($1,$2,$3)`, id, op, newID("vol")); err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, id, nil, "agent.created"); err != nil {
			return 0, nil, err
		}
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

func auditTenantAgent(ctx context.Context, tx pgx.Tx, p Principal, agent string, assignment *string, action string) error {
	// A file upload or deletion changes no authorization policy. Bumping the
	// version would also take the organization row exclusively after the agent
	// lock, against concurrent uploads that read it shared before (deadlock).
	if action != "agent.created" && !strings.HasPrefix(action, "attachment.") {
		if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,assignment_id,action) VALUES($1,$2,$3,$4,$5,$6)`,
		newID("audit"), p.TenantID, p.ID, agent, assignment, action)
	return err
}

func (c *AgentCatalog) listTenant(ctx context.Context, p Principal, after string, limit int) ([]TenantAgent, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return nil, err
	}
	administrative := authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata)
	rows, err := tx.Query(ctx, "SELECT "+tenantAgentColumns+", "+effectivePermissions+agentViewFrom+
		`WHERE a.tenant_id=$1 AND a.phase<>'DELETED' AND a.id>$3 ORDER BY a.id`, p.TenantID, p.ID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TenantAgent{}
	for rows.Next() {
		var perms []string
		v, err := scanTenantAgent(rows, &perms)
		if err != nil {
			return nil, err
		}
		if !administrative && !canSeeTenantAgent(p, current.Role, perms) {
			continue
		}
		if items = append(items, v); len(items) == limit {
			break
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, commit(ctx, tx)
}

func (c *AgentCatalog) getTenant(ctx context.Context, p Principal, id string) (TenantAgent, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return TenantAgent{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return TenantAgent{}, err
	}
	var perms []string
	v, err := scanTenantAgent(tx.QueryRow(ctx, "SELECT "+tenantAgentColumns+", "+effectivePermissions+agentViewFrom+
		`WHERE a.tenant_id=$1 AND a.id=$3 AND a.phase<>'DELETED'`, p.TenantID, p.ID, id), &perms)
	if err != nil {
		return TenantAgent{}, err
	}
	// A principal without any right to this agent learns nothing about it.
	if !canSeeTenantAgent(p, current.Role, perms) {
		return TenantAgent{}, ErrNotFound
	}
	return v, commit(ctx, tx)
}

var assignmentPermissions = []string{"read_metadata", "invoke", "read_content"}

func validAssignmentInput(in CreateAssignmentInput) ([]string, bool) {
	if (in.PrincipalID == "") == (in.TeamID == "") || len(in.Permissions) == 0 || len(in.Permissions) > len(assignmentPermissions) {
		return nil, false
	}
	target := in.PrincipalID + in.TeamID
	if !validOrganizationText(target, 100) {
		return nil, false
	}
	seen := []string{}
	for _, p := range in.Permissions {
		if !slices.Contains(assignmentPermissions, p) || slices.Contains(seen, p) {
			return nil, false
		}
		seen = append(seen, p)
	}
	slices.Sort(seen)
	return seen, true
}

func scanAssignment(row pgx.Row) (AgentAssignment, error) {
	var s AgentAssignment
	err := row.Scan(&s.ID, &s.AgentID, &s.PrincipalID, &s.TeamID, &s.Permissions, &s.Status, &s.CreatedAt, &s.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return s, err
}

const assignmentColumns = `id,agent_id,principal_id,team_id,permissions,status,created_at,revoked_at`

func (a *Accounts) CreateAgentAssignment(ctx context.Context, p Principal, agentID, key string, in CreateAssignmentInput) (APIReceipt, error) {
	permissions, ok := validAssignmentInput(in)
	if !ok || !validOrganizationText(agentID, 100) {
		return APIReceipt{}, ErrInput
	}
	in.Permissions = permissions
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return APIReceipt{}, err
	}
	var phase string
	if err = tx.QueryRow(ctx, `SELECT phase FROM agents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, agentID).Scan(&phase); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	operation := "assignment.create/" + agentID
	r, err := a.withTenantReceipt(ctx, tx, p, operation, key, in, func() (int, any, error) {
		if phase == "DELETING" || phase == "DELETED" {
			return 0, nil, ErrTransition
		}
		var targetActive bool
		if in.PrincipalID != "" {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
                WHERE p.tenant_id=$1 AND p.id=$2 AND p.status='active' AND m.status='active')`, p.TenantID, in.PrincipalID).Scan(&targetActive)
		} else {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id=$1 AND id=$2 AND status='active')`, p.TenantID, in.TeamID).Scan(&targetActive)
		}
		if err != nil {
			return 0, nil, err
		}
		if !targetActive {
			return 0, nil, ErrNotFound
		}
		var duplicate bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND status='active'
            AND principal_id IS NOT DISTINCT FROM nullif($3,'') AND team_id IS NOT DISTINCT FROM nullif($4,''))`, p.TenantID, agentID, in.PrincipalID, in.TeamID).Scan(&duplicate); err != nil {
			return 0, nil, err
		}
		if duplicate {
			return 0, nil, ErrTransition
		}
		s, err := scanAssignment(tx.QueryRow(ctx, `INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,team_id,permissions,created_by)
            VALUES($1,$2,$3,nullif($4,''),nullif($5,''),$6,$7) RETURNING `+assignmentColumns, newID("asg"), p.TenantID, agentID, in.PrincipalID, in.TeamID, in.Permissions, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, agentID, &s.ID, "assignment.created"); err != nil {
			return 0, nil, err
		}
		return 201, s, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) RevokeAgentAssignment(ctx context.Context, p Principal, agentID, assignmentID, key string) (APIReceipt, error) {
	if !validOrganizationText(agentID, 100) || !validOrganizationText(assignmentID, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return APIReceipt{}, err
	}
	current, err := scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND id=$3 FOR UPDATE`, p.TenantID, agentID, assignmentID))
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		AgentID      string `json:"agent_id"`
		AssignmentID string `json:"assignment_id"`
	}{agentID, assignmentID}
	r, err := a.withTenantReceipt(ctx, tx, p, "assignment.revoke", key, in, func() (int, any, error) {
		if current.Status == "revoked" {
			return 200, current, nil
		}
		s, err := scanAssignment(tx.QueryRow(ctx, `UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$4
            WHERE tenant_id=$1 AND agent_id=$2 AND id=$3 RETURNING `+assignmentColumns, p.TenantID, agentID, assignmentID, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, agentID, &s.ID, "assignment.revoked"); err != nil {
			return 0, nil, err
		}
		return 200, s, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// ReplaceAgentAssignment changes the permissions of an active assignment in one
// transaction: the old row is revoked and its replacement created for the same
// target, so there is no instant with zero rights or with both sets active.
// The audit trail records the usual revoked and created events.
func (a *Accounts) ReplaceAgentAssignment(ctx context.Context, p Principal, agentID, assignmentID, key string, permissions []string) (APIReceipt, error) {
	perms, ok := validAssignmentInput(CreateAssignmentInput{PrincipalID: "x", Permissions: permissions})
	if !ok || !validOrganizationText(agentID, 100) || !validOrganizationText(assignmentID, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return APIReceipt{}, err
	}
	current, err := scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND id=$3 FOR UPDATE`, p.TenantID, agentID, assignmentID))
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		AgentID      string   `json:"agent_id"`
		AssignmentID string   `json:"assignment_id"`
		Permissions  []string `json:"permissions"`
	}{agentID, assignmentID, perms}
	r, err := a.withTenantReceipt(ctx, tx, p, "assignment.replace", key, in, func() (int, any, error) {
		if current.Status != "active" {
			return 0, nil, ErrTransition
		}
		var phase string
		if err := tx.QueryRow(ctx, `SELECT phase FROM agents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, agentID).Scan(&phase); err != nil {
			return 0, nil, err
		}
		if phase == "DELETING" || phase == "DELETED" {
			return 0, nil, ErrTransition
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$4
            WHERE tenant_id=$1 AND agent_id=$2 AND id=$3`, p.TenantID, agentID, assignmentID, p.ID); err != nil {
			return 0, nil, err
		}
		if err := auditTenantAgent(ctx, tx, p, agentID, &assignmentID, "assignment.revoked"); err != nil {
			return 0, nil, err
		}
		var principal, team string
		if current.PrincipalID != nil {
			principal = *current.PrincipalID
		}
		if current.TeamID != nil {
			team = *current.TeamID
		}
		var targetActive bool
		var err error
		if principal != "" {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
                WHERE p.tenant_id=$1 AND p.id=$2 AND p.status='active' AND m.status='active')`, p.TenantID, principal).Scan(&targetActive)
		} else {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id=$1 AND id=$2 AND status='active')`, p.TenantID, team).Scan(&targetActive)
		}
		if err != nil {
			return 0, nil, err
		}
		if !targetActive {
			return 0, nil, ErrNotFound
		}
		s, err := scanAssignment(tx.QueryRow(ctx, `INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,team_id,permissions,created_by)
            VALUES($1,$2,$3,nullif($4,''),nullif($5,''),$6,$7) RETURNING `+assignmentColumns, newID("asg"), p.TenantID, agentID, principal, team, perms, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, agentID, &s.ID, "assignment.created"); err != nil {
			return 0, nil, err
		}
		return 201, s, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) ListAgentAssignments(ctx context.Context, p Principal, agentID, after string, limit int) ([]AgentAssignment, error) {
	if !validOrganizationText(agentID, 100) || limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentAssign)
	if err != nil {
		return nil, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ManageAssignments) {
		return nil, ErrForbidden
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, p.TenantID, agentID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT `+assignmentColumns+` FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND id>$3 ORDER BY id LIMIT $4`, p.TenantID, agentID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AgentAssignment{}
	for rows.Next() {
		s, err := scanAssignment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, commit(ctx, tx)
}

// ListTenantAgents and GetTenantAgent return the tenant domain's redacted view.
// A tenant principal never reaches the historical owner-domain listings.
func (c *AgentCatalog) ListTenantAgents(ctx context.Context, p Principal, after string, limit int) ([]TenantAgent, error) {
	if p.Kind != "tenant" || limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	return c.listTenant(ctx, p, after, limit)
}

func (c *AgentCatalog) GetTenantAgent(ctx context.Context, p Principal, id string) (TenantAgent, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return TenantAgent{}, ErrInput
	}
	return c.getTenant(ctx, p, id)
}

// operationTenant lets the requester, or an administrative reader, follow an
// operation on a tenant agent. Operations of other tenants do not exist here.
func (c *AgentCatalog) operationTenant(ctx context.Context, p Principal, id string) (PlatformOperation, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return PlatformOperation{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return PlatformOperation{}, err
	}
	administrative := authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata)
	var v PlatformOperation
	err = tx.QueryRow(ctx, `SELECT o.id,o.agent_id,o.kind,o.status,o.error_code,o.created_at,o.completed_at,o.unclean_stop
        FROM platform_operations o JOIN agents a ON a.id=o.agent_id
        WHERE a.tenant_id=$1 AND o.id=$2 AND ($3 OR o.requested_by_principal_id=$4)`, p.TenantID, id, administrative, p.ID).
		Scan(&v.ID, &v.AgentID, &v.Kind, &v.Status, &v.ErrorCode, &v.CreatedAt, &v.CompletedAt, &v.UncleanStop)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformOperation{}, ErrNotFound
	}
	if err != nil {
		return PlatformOperation{}, err
	}
	return v, commit(ctx, tx)
}

// tenantAgentForUpdate locks one agent of the caller's tenant. An agent of
// another tenant, or of the historical domain, is simply not found.
func tenantAgentForUpdate(ctx context.Context, tx pgx.Tx, p Principal, id string) (agent, string, error) {
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return agent{}, "", err
	}
	a, ok := agents[id]
	if !ok || a.Tenant != p.TenantID {
		return agent{}, "", ErrNotFound
	}
	var host string
	if err = tx.QueryRow(ctx, "SELECT host_id FROM agent_specs WHERE agent_id=$1", id).Scan(&host); errors.Is(err, pgx.ErrNoRows) {
		return agent{}, "", ErrNotFound
	} else if err != nil {
		return agent{}, "", err
	}
	return a, host, nil
}

// requestLifecycleTenant records an ordered wake or sleep command for a tenant
// agent. The caller needs the operate scope and a role that may operate agents.
func (c *AgentCatalog) requestLifecycleTenant(ctx context.Context, p Principal, id, key, kind string) (APIReceipt, error) {
	action := authorization.WakeAgent
	if kind == "sleep" {
		action = authorization.SleepAgent
	}
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, action); err != nil {
		return APIReceipt{}, err
	}
	a, host, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		AgentID string `json:"agent_id"`
	}{id}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent."+kind+"/"+id, key, in, func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		op, err := insertTenantOperation(ctx, tx, p, id, host, kind)
		if err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, id, nil, "agent."+kind+"_requested"); err != nil {
			return 0, nil, err
		}
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

func insertTenantOperation(ctx context.Context, tx pgx.Tx, p Principal, agentID, host, kind string) (string, error) {
	var seq int64
	err := tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
        WHERE agent_id=$1 AND next_operation_seq<$2 RETURNING next_operation_seq`, agentID, int64(math.MaxInt64)).Scan(&seq)
	if err != nil {
		return "", err
	}
	op := newID("op")
	_, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
        VALUES($1,$2,$3,$4,$5,$6)`, op, p.ID, agentID, host, seq, kind)
	return op, err
}

// deleteTenant requests the durable, fenced deletion of a tenant agent. Only an
// owner or administrator may; the existing deletion barrier protocol applies.
func (c *AgentCatalog) deleteTenant(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.DeleteAgent); err != nil {
		return APIReceipt{}, err
	}
	a, host, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		AgentID string `json:"agent_id"`
	}{id}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.delete/"+id, key, in, func() (int, any, error) {
		if err := requestDeletion(ctx, tx, a, p.ID); err != nil {
			return 0, nil, err
		}
		var op string
		if err := tx.QueryRow(ctx, "SELECT coalesce(operation_id,'') FROM deletion_operations WHERE agent_id=$1", id).Scan(&op); err != nil {
			return 0, nil, err
		}
		if op == "" {
			if op, err = insertTenantOperation(ctx, tx, p, id, host, "delete"); err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, "UPDATE deletion_operations SET operation_id=$2 WHERE agent_id=$1", id, op); err != nil {
				return 0, nil, err
			}
			// Audited once: later requests share this operation.
			if err := auditTenantAgent(ctx, tx, p, id, nil, "agent.delete_requested"); err != nil {
				return 0, nil, err
			}
		}
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// effectiveAgentPermissions are the permissions a principal holds on one agent
// right now, through a direct assignment or an active team it actively belongs to.
func effectiveAgentPermissions(ctx context.Context, tx pgx.Tx, tenant, principal, agentID string) ([]string, error) {
	var perms []string
	err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT perm),'{}') FROM agent_assignments s, unnest(s.permissions) perm
        WHERE s.tenant_id=$1 AND s.agent_id=$2 AND s.status='active' AND (s.principal_id=$3 OR s.team_id IN
          (SELECT m.team_id FROM team_memberships m JOIN teams t ON (t.tenant_id,t.id)=(m.tenant_id,m.team_id)
           WHERE m.tenant_id=$1 AND m.principal_id=$3 AND m.status='active' AND t.status='active'))`, tenant, agentID, principal).Scan(&perms)
	return perms, err
}

// instructTenant admits an invocation of a tenant agent. The right to invoke
// comes only from an assignment: no administrative role implies it. The
// authorization is read in this same transaction, before any replay, so a
// revoked member or assignment is refused even with a previously valid key.
func (c *AgentCatalog) instructTenant(ctx context.Context, p Principal, id, key string, in OwnerInstruction) (APIReceipt, error) {
	return c.admitTenantInvocation(ctx, p, id, key, in, invocationAdmission{ttl: DefaultInstructionTTL, request: in})
}

// invocationAdmission carries what differs between the two admission routes.
// request is what the idempotency receipt hashes; resource selects the
// invocation shape and its own idempotency operation.
type invocationAdmission struct {
	ttl         time.Duration
	runAt       *time.Time
	attachments []string
	work        time.Duration // 0 keeps the column default
	request     any
	resource    bool
}

// admitTenantInvocation is shared by the historical messages route and the
// invocation resource. They use distinct idempotency operations, so one key
// never replays a response of the other shape.
func (c *AgentCatalog) admitTenantInvocation(ctx context.Context, p Principal, id, key string, in OwnerInstruction, opt invocationAdmission) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentInvoke)
	if err != nil {
		return APIReceipt{}, err
	}
	a, host, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return APIReceipt{}, err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	access := tenantAccess(p)
	switch {
	case !authorization.CanAccessAssignedAgent(access, authorization.InvokeAgent, toPermissions(perms)):
		// An agent the caller cannot even see is not found; one it can see but not
		// invoke is forbidden.
		if authorization.CanAdminister(access, authorization.Role(current.Role), authorization.ReadAgentMetadata) || len(perms) > 0 {
			return APIReceipt{}, ErrForbidden
		}
		return APIReceipt{}, ErrNotFound
	}
	operation := "agent.invoke/" + id
	if opt.resource {
		operation = "invocation.create/" + id
	}
	runAt := opt.runAt
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, operation, key, opt.request, func() (int, any, error) {
		if runAt != nil {
			// Bounds are checked against the database clock inside the receipt, so a
			// replayed request is never re-judged against a later "now".
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()+interval '1 second' AND $1::timestamptz<=clock_timestamp()+$2::bigint*interval '1 second'`,
				*runAt, int64(MaxScheduleHorizon/time.Second)).Scan(&ok); err != nil {
				return 0, nil, err
			}
			if !ok {
				return 0, nil, ErrInput
			}
		}
		status, body, err := c.enqueueInstruction(ctx, tx, a, id, host, p.ID, in, opt.ttl, runAt)
		if err != nil {
			return status, body, err
		}
		created := body.(AgentCreation)
		// Same transaction as the operation: the files and the instruction are
		// accepted together or not at all.
		if err = bindAttachments(ctx, tx, p, id, created.OperationID, opt.attachments); err != nil {
			return 0, nil, err
		}
		if opt.work > 0 {
			if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET work_timeout_seconds=$2 WHERE operation_id=$1", created.OperationID, int(opt.work/time.Second)); err != nil {
				return 0, nil, err
			}
		}
		if opt.resource {
			inv := Invocation{ID: created.OperationID, AgentID: id, State: "accepted", Attachments: opt.attachments}
			if runAt != nil {
				inv.State, inv.RunAt = "scheduled", runAt
			}
			return status, inv, nil
		}
		return status, body, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// instructionResultTenant returns a completed private result only to the
// principal who asked, and only while that principal still holds read_content on
// the agent. Roles and later assignments of other members never open it. While
// the invocation is lost, the result the database still holds stays readable.
func (c *AgentCatalog) instructionResultTenant(ctx context.Context, p Principal, operation string) (json.RawMessage, error) {
	if !validOrganizationText(operation, 100) {
		return nil, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if _, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentContentRead); err != nil {
		return nil, err
	}
	var payload, agentID string
	err = tx.QueryRow(ctx, `SELECT i.result_payload_id,o.agent_id FROM owner_instructions i
        JOIN platform_operations o ON o.id=i.operation_id
        JOIN agents a ON a.id=o.agent_id
        JOIN transit_payloads payload ON payload.id=i.result_payload_id AND payload.kind='instruction_result' AND payload.ref_id=o.id`+rerunJoins+`
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction'
          AND (o.status='SUCCEEDED' OR `+lostCondition+`) AND i.result_payload_id IS NOT NULL`, operation, p.TenantID, p.ID).Scan(&payload, &agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, agentID)
	if err != nil {
		return nil, err
	}
	if !authorization.CanAccessAssignedAgent(tenantAccess(p), authorization.ReadAgentContent, toPermissions(perms)) {
		return nil, ErrNotFound
	}
	parties, err := payloadParties(ctx, tx, payload)
	if err != nil {
		return nil, err
	}
	if len(parties) != 1 || parties[0].Owner != p.ID || parties[0].Agent != agentID {
		return nil, ErrNotFound
	}
	body, err := c.transit.read(ctx, tx, payload, parties)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		clear(body)
		return nil, ErrTransitPayload
	}
	if err = c.transit.delivered(ctx, tx, payload); err != nil {
		clear(body)
		return nil, err
	}
	if err = commit(ctx, tx); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}
