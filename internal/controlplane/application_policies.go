package controlplane

import (
	"context"
	"errors"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type PolicySlot struct {
	Name        string   `json:"name"`
	PoolID      string   `json:"pool_id,omitempty"`
	TeamID      string   `json:"team_id,omitempty"`
	AgentID     string   `json:"agent_id,omitempty"`
	Permissions []string `json:"permissions"`
}

type PolicySpec struct {
	ManagerIDs    []string     `json:"manager_ids,omitempty"`
	ApplicationID string       `json:"application_id"`
	Slots         []PolicySlot `json:"slots"`
	AllowedTeams  []string     `json:"allowed_teams"`
	OnExhaustion  string       `json:"on_exhaustion"`
}

type AssignmentPolicy struct {
	ID string `json:"id"`
	PolicySpec
	Applied   bool           `json:"applied"`
	Available map[string]int `json:"pool_available"`
}

func readPolicy(ctx context.Context, tx pgx.Tx, tenant, id string) (AssignmentPolicy, error) {
	var v AssignmentPolicy
	err := tx.QueryRow(ctx, "SELECT id,spec,applied FROM app_policies WHERE tenant_id=$1 AND id=$2", tenant, id).Scan(&v.ID, &v.PolicySpec, &v.Applied)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func eligibleTeam(ctx context.Context, tx pgx.Tx, tenant, team string, spec PolicySpec) error {
	if team == "" {
		return nil
	}
	if !slices.Contains(spec.AllowedTeams, team) {
		return ErrForbidden
	}
	v, err := teamByID(ctx, tx, tenant, team)
	if err != nil {
		return err
	}
	if v.Status != "active" {
		return ErrTransition
	}
	return nil
}

// Simulate on the current tenant and resources. Shared-slot application is a
// team grant, so a future transfer removes precisely the inherited access.
func inspectPolicy(ctx context.Context, tx pgx.Tx, tenant string, v *AssignmentPolicy) error {
	if len(v.Slots) < 1 || len(v.Slots) > 16 || len(v.AllowedTeams) > 32 || !slices.Contains([]string{"wait", "refuse", "create"}, v.OnExhaustion) {
		return ErrInput
	}
	a, err := readApp(ctx, tx, tenant, v.ApplicationID)
	if err != nil {
		return err
	}
	if a.Status != "active" {
		return ErrTransition
	}
	v.Available = map[string]int{}
	seen := map[string]bool{}
	for _, team := range v.AllowedTeams {
		if !validOrganizationText(team, 100) || seen[team] {
			return ErrInput
		}
		seen[team] = true
		if err := eligibleTeam(ctx, tx, tenant, team, v.PolicySpec); err != nil {
			return err
		}
	}
	if len(v.ManagerIDs) > 32 {
		return ErrInput
	}
	for _, id := range v.ManagerIDs {
		var eligible bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_activations a JOIN memberships m ON m.principal_id=a.principal_id WHERE a.app_id=$1 AND a.tenant_id=$2 AND a.principal_id=$3 AND NOT a.disabled AND m.status='active')`, v.ApplicationID, tenant, id).Scan(&eligible)
		if err != nil {
			return err
		}
		if !eligible {
			return ErrNotFound
		}
	}
	names := map[string]bool{}
	shared := map[[2]string]bool{}
	for _, slot := range v.Slots {
		if !catalogName(slot.Name) || names[slot.Name] {
			return ErrInput
		}
		names[slot.Name] = true
		if _, ok := validAssignmentInput(CreateAssignmentInput{PrincipalID: "member", Permissions: slot.Permissions}); !ok {
			return ErrInput
		}
		if slot.PoolID != "" {
			if slot.AgentID != "" || slot.TeamID != "" {
				return ErrInput
			}
			var n int
			err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM `+assignablePoolInventory+` m WHERE m.tenant_id=p.tenant_id AND m.pool_id=p.id)
                FROM agent_pools p WHERE p.tenant_id=$1 AND p.id=$2`, tenant, slot.PoolID).Scan(&n)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			v.Available[slot.PoolID] = n
		} else {
			pair := [2]string{slot.TeamID, slot.AgentID}
			if slot.TeamID == "" || slot.AgentID == "" || shared[pair] {
				return ErrInput
			}
			shared[pair] = true
			if err := eligibleTeam(ctx, tx, tenant, slot.TeamID, v.PolicySpec); err != nil {
				return err
			}
			var present bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2 AND phase='LIVE' AND NOT EXISTS(
                SELECT 1 FROM app_personal_reservations WHERE tenant_id=$1 AND agent_id=$2) AND NOT EXISTS(
                SELECT 1 FROM personal_volume_holds WHERE tenant_id=$1 AND agent_id=$2))`, tenant, slot.AgentID).Scan(&present); err != nil {
				return err
			}
			if !present {
				return ErrNotFound
			}
		}
	}
	return nil
}

func writePolicyGrant(ctx context.Context, tx pgx.Tx, p Principal, policy, agent, member, team string, permissions []string) error {
	id := newID("asg")
	_, err := tx.Exec(ctx, `INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,team_id,permissions,created_by,policy_id)
       VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8)`, id, p.TenantID, agent, member, team, permissions, p.ID, policy)
	if err != nil {
		return err
	}
	return auditTenantAgent(ctx, tx, p, agent, &id, "assignment.created")
}

func (a *Accounts) PlanPolicy(ctx context.Context, p Principal, key string, in PolicySpec) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return APIReceipt{}, err
	}
	if in.AllowedTeams == nil {
		in.AllowedTeams = []string{}
	}
	plan := AssignmentPolicy{PolicySpec: in}
	if err = inspectPolicy(ctx, tx, p.TenantID, &plan); err != nil {
		return APIReceipt{}, err
	}
	out, err := a.withTenantReceipt(ctx, tx, p, "policy.plan", key, in, func() (int, any, error) {
		plan.ID = newID("pol")
		_, err := tx.Exec(ctx, "INSERT INTO app_policies(id,tenant_id,app_id,spec) VALUES($1,$2,$3,$4)", plan.ID, p.TenantID, in.ApplicationID, in)
		if err != nil {
			return 0, nil, err
		}
		return 201, plan, auditApplication(ctx, tx, p, plan.ID, "policy.planned")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}

func (a *Accounts) ApplyPolicy(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return APIReceipt{}, err
	}
	plan, err := readPolicy(ctx, tx, p.TenantID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	if err = inspectPolicy(ctx, tx, p.TenantID, &plan); err != nil {
		return APIReceipt{}, err
	}
	out, err := a.withTenantReceipt(ctx, tx, p, "policy.apply", key, id, func() (int, any, error) {
		if plan.Applied {
			return 200, plan, nil
		}
		for _, slot := range plan.Slots {
			if slot.TeamID != "" {
				if err := writePolicyGrant(ctx, tx, p, id, slot.AgentID, "", slot.TeamID, slot.Permissions); err != nil {
					return 0, nil, err
				}
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE app_policies SET applied=true WHERE id=$1", id); err != nil {
			return 0, nil, err
		}
		plan.Applied = true
		return 200, plan, auditApplication(ctx, tx, p, id, "policy.applied")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}

type AccessExplanation struct {
	Member      string         `json:"member"`
	Agent       string         `json:"agent"`
	Active      bool           `json:"active"`
	Permissions []string       `json:"permissions"`
	Sources     []AccessSource `json:"sources"`
}
type AccessSource struct {
	AssignmentID string   `json:"assignment_id"`
	TeamID       string   `json:"team_id,omitempty"`
	PolicyID     string   `json:"policy_id,omitempty"`
	Permissions  []string `json:"permissions"`
}

func (a *Accounts) ExplainAccess(ctx context.Context, p Principal, member, agent string) (AccessExplanation, error) {
	v := AccessExplanation{Member: member, Agent: agent, Permissions: []string{}, Sources: []AccessSource{}}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return v, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageAssignments); err != nil {
		return v, err
	}
	err = tx.QueryRow(ctx, `SELECT m.status='active' AND p.status='active' FROM memberships m JOIN principals p ON m.principal_id=p.id
        JOIN agents a ON a.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND m.principal_id=$2 AND a.id=$3`, p.TenantID, member, agent).Scan(&v.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if v.Active {
		rows, err := tx.Query(ctx, `SELECT s.id,coalesce(s.team_id,''),coalesce(s.policy_id,''),s.permissions FROM agent_assignments s
          WHERE s.tenant_id=$1 AND s.agent_id=$2 AND s.status='active' AND (s.principal_id=$3 OR s.team_id IN
          (SELECT m.team_id FROM team_memberships m JOIN teams t ON t.id=m.team_id WHERE m.tenant_id=$1 AND m.principal_id=$3 AND m.status='active' AND t.status='active')) ORDER BY s.id`, p.TenantID, agent, member)
		if err != nil {
			return v, err
		}
		for rows.Next() {
			var s AccessSource
			if err := rows.Scan(&s.AssignmentID, &s.TeamID, &s.PolicyID, &s.Permissions); err != nil {
				rows.Close()
				return v, err
			}
			v.Sources = append(v.Sources, s)
			v.Permissions = append(v.Permissions, s.Permissions...)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return v, err
		}
		slices.Sort(v.Permissions)
		v.Permissions = slices.Compact(v.Permissions)
	}
	return v, commit(ctx, tx)
}
