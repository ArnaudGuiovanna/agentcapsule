package controlplane

import (
	"context"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// ReassignAssignmentInput names the new target of an assignment: exactly one
// of PrincipalID (an active member or technical account) and TeamID (an
// active team). Permissions, when given, are the new target's; when omitted,
// the new target receives the permissions of the moved assignment.
type ReassignAssignmentInput struct {
	PrincipalID string   `json:"principal_id,omitempty"`
	TeamID      string   `json:"team_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// ReassignAgentAssignment moves an active assignment of an agent to another
// target in one transaction: the old assignment is revoked and the new one
// created, so no instant leaves both targets, or neither, holding the moved
// rights. It applies ADR 002 (D-02):
//
//   - the organization's row is taken exclusively first, like every other
//     authority change. An admission or a result read holds it shared from its
//     authorization to its commit, so it is serialized entirely before or
//     entirely after the reassignment: one that commits before keeps its job,
//     one that waited is judged against the new targets;
//   - work the old target had admitted is not canceled. It may complete for
//     the organization; its operation keeps its requester;
//   - results stay bound to their requester. The old target no longer reads
//     them (it lost read_content), and the new target never reads them
//     (it did not ask). Reassigning back to the old target makes its own
//     retained results readable again;
//   - nothing in the agent's volume is separated: a harness may remember the
//     old target's exchanges. A reassignment that needs that separation uses
//     a new agent.
func (a *Accounts) ReassignAgentAssignment(ctx context.Context, p Principal, agentID, assignmentID, key string, in ReassignAssignmentInput) (APIReceipt, error) {
	if !validOrganizationText(agentID, 100) || !validOrganizationText(assignmentID, 100) {
		return APIReceipt{}, ErrInput
	}
	check := CreateAssignmentInput{PrincipalID: in.PrincipalID, TeamID: in.TeamID, Permissions: in.Permissions}
	if len(check.Permissions) == 0 {
		check.Permissions = []string{"read_metadata"}
	}
	perms, ok := validAssignmentInput(check)
	if !ok {
		return APIReceipt{}, ErrInput
	}
	if len(in.Permissions) > 0 {
		in.Permissions = perms
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
	request := struct {
		AgentID      string   `json:"agent_id"`
		AssignmentID string   `json:"assignment_id"`
		PrincipalID  string   `json:"principal_id"`
		TeamID       string   `json:"team_id"`
		Permissions  []string `json:"permissions"`
	}{agentID, assignmentID, in.PrincipalID, in.TeamID, in.Permissions}
	r, err := a.withTenantReceipt(ctx, tx, p, "assignment.reassign", key, request, func() (int, any, error) {
		if current.Status != "active" {
			return 0, nil, ErrTransition
		}
		if (current.PrincipalID != nil && *current.PrincipalID == in.PrincipalID) || (current.TeamID != nil && *current.TeamID == in.TeamID) {
			// The same target: changing its permissions is a replacement.
			return 0, nil, ErrTransition
		}
		var phase string
		if err := tx.QueryRow(ctx, `SELECT phase FROM agents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, agentID).Scan(&phase); err != nil {
			return 0, nil, err
		}
		if phase == "DELETING" || phase == "DELETED" {
			return 0, nil, ErrTransition
		}
		var targetActive, duplicate bool
		var err error
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
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND status='active'
            AND principal_id IS NOT DISTINCT FROM nullif($3,'') AND team_id IS NOT DISTINCT FROM nullif($4,''))`, p.TenantID, agentID, in.PrincipalID, in.TeamID).Scan(&duplicate); err != nil {
			return 0, nil, err
		}
		if duplicate {
			// The target already holds its own assignment: replace that one.
			return 0, nil, ErrTransition
		}
		moved := in.Permissions
		if len(moved) == 0 {
			moved = slices.Clone(current.Permissions)
		}
		if _, err = tx.Exec(ctx, `UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$4
            WHERE tenant_id=$1 AND agent_id=$2 AND id=$3`, p.TenantID, agentID, assignmentID, p.ID); err != nil {
			return 0, nil, err
		}
		if err = auditTenantAgent(ctx, tx, p, agentID, &assignmentID, "assignment.revoked"); err != nil {
			return 0, nil, err
		}
		s, err := scanAssignment(tx.QueryRow(ctx, `INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,team_id,permissions,created_by)
            VALUES($1,$2,$3,nullif($4,''),nullif($5,''),$6,$7) RETURNING `+assignmentColumns, newID("asg"), p.TenantID, agentID, in.PrincipalID, in.TeamID, moved, p.ID))
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
