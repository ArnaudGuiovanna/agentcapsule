package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/assignments"
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
	subject := assignments.Subject{Tenant: p.TenantID, Agent: agentID, Actor: p.ID}
	current, err := subject.LockAssignment(ctx, tx, assignmentID)
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
		s, err := subject.Reassign(ctx, tx, current, CreateAssignmentInput{PrincipalID: in.PrincipalID, TeamID: in.TeamID, Permissions: in.Permissions})
		if err != nil {
			return 0, nil, err
		}
		// The former target's assignment is revoked: its record, in this transaction.
		revoked := a.store.revocations(tx, p.TenantID)
		if err = revoked.add(ctx, authoritylog.AccessAssignment, p.TenantID, [][]string{{assignmentID}}); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(s)
		return 201, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, r, commit(ctx, tx))
}
