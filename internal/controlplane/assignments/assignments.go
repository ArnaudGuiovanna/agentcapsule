// Package assignments grants, replaces and revokes access to tenant agents inside the caller's transaction.
package assignments

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/audit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// Assignment grants permissions on one agent to one principal or to every
// active member of one team. Permissions are read_metadata, invoke, read_content.
type Assignment struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	PrincipalID *string    `json:"principal_id,omitempty"`
	TeamID      *string    `json:"team_id,omitempty"`
	Permissions []string   `json:"permissions"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type Input struct {
	PrincipalID string   `json:"principal_id,omitempty"`
	TeamID      string   `json:"team_id,omitempty"`
	Permissions []string `json:"permissions"`
}

// Subject identifies the agent whose assignments an authorized tenant administrator changes.
type Subject struct{ Tenant, Agent, Actor string }

var assignmentPermissions = []string{"read_metadata", "invoke", "read_content"}

func (in Input) NormalizedPermissions() ([]string, bool) {
	if (in.PrincipalID == "") == (in.TeamID == "") || len(in.Permissions) == 0 || len(in.Permissions) > len(assignmentPermissions) {
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

func scanAssignment(row pgx.Row) (Assignment, error) {
	var s Assignment
	err := row.Scan(&s.ID, &s.AgentID, &s.PrincipalID, &s.TeamID, &s.Permissions, &s.Status, &s.CreatedAt, &s.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = persistence.ErrNotFound
	}
	return s, err
}

const assignmentColumns = `id,agent_id,principal_id,team_id,permissions,status,created_at,revoked_at`

// LockAssignment takes the assignment row before looking up the receipt for a mutation.
func (s Subject) LockAssignment(ctx context.Context, tx pgx.Tx, id string) (Assignment, error) {
	return scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND id=$3 FOR UPDATE`, s.Tenant, s.Agent, id))
}

// LockAgentPhase pins the agent during a new grant, including on receipt replay.
func (s Subject) LockAgentPhase(ctx context.Context, tx pgx.Tx) (string, error) {
	var phase string
	err := tx.QueryRow(ctx, `SELECT phase FROM agents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.Tenant, s.Agent).Scan(&phase)
	if errors.Is(err, pgx.ErrNoRows) {
		err = persistence.ErrNotFound
	}
	return phase, err
}

func (s Subject) checkActiveTarget(ctx context.Context, tx pgx.Tx, in Input) error {
	var active bool
	var err error
	if in.PrincipalID != "" {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
    WHERE p.tenant_id=$1 AND p.id=$2 AND p.status='active' AND m.status='active')`, s.Tenant, in.PrincipalID).Scan(&active)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id=$1 AND id=$2 AND status='active')`, s.Tenant, in.TeamID).Scan(&active)
	}
	if err == nil && !active {
		return persistence.ErrNotFound
	}
	return err
}

// Direct creation can coexist with policy-managed grants. Moving a grant onto
// another target refuses any existing grant to that target.
func (s Subject) checkNewTarget(ctx context.Context, tx pgx.Tx, in Input, onlyManual bool) error {
	if err := s.checkActiveTarget(ctx, tx, in); err != nil {
		return err
	}
	const match = ` AND principal_id IS NOT DISTINCT FROM nullif($3,'') AND team_id IS NOT DISTINCT FROM nullif($4,''))`
	query := `SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND status='active'`
	if onlyManual {
		query += " AND policy_id IS NULL"
	}
	var duplicate bool
	if err := tx.QueryRow(ctx, query+match, s.Tenant, s.Agent, in.PrincipalID, in.TeamID).Scan(&duplicate); err != nil {
		return err
	}
	if err := personalTarget(ctx, tx, s.Tenant, s.Agent, in.PrincipalID); err != nil {
		return err
	}
	if duplicate {
		return persistence.ErrTransition
	}
	return nil
}

func (s Subject) insertAssignment(ctx context.Context, tx pgx.Tx, in Input) (Assignment, error) {
	item, err := scanAssignment(tx.QueryRow(ctx, `INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,team_id,permissions,created_by)
 VALUES($1,$2,$3,nullif($4,''),nullif($5,''),$6,$7) RETURNING `+assignmentColumns, persistence.ID("asg"), s.Tenant, s.Agent, in.PrincipalID, in.TeamID, in.Permissions, s.Actor))
	if err != nil {
		return Assignment{}, err
	}
	err = audit.RecordAgent(ctx, tx, s.Tenant, s.Actor, s.Agent, &item.ID, "assignment.created")
	return item, err
}

// CreateAssignment creates a manual grant for an active target and audits its creation.
func (s Subject) CreateAssignment(ctx context.Context, tx pgx.Tx, phase string, in Input) (Assignment, error) {
	if phase == "DELETING" || phase == "DELETED" {
		return Assignment{}, persistence.ErrTransition
	}
	if err := s.checkNewTarget(ctx, tx, in, true); err != nil {
		return Assignment{}, err
	}
	return s.insertAssignment(ctx, tx, in)
}

// RevokeAssignment records revocation and its audit before the caller records the authority effect.
func (s Subject) RevokeAssignment(ctx context.Context, tx pgx.Tx, id string) (Assignment, error) {
	item, err := scanAssignment(tx.QueryRow(ctx, `UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$4
  WHERE tenant_id=$1 AND agent_id=$2 AND id=$3 RETURNING `+assignmentColumns, s.Tenant, s.Agent, id, s.Actor))
	if err != nil {
		return Assignment{}, err
	}
	err = audit.RecordAgent(ctx, tx, s.Tenant, s.Actor, s.Agent, &item.ID, "assignment.revoked")
	return item, err
}

func (s Subject) canReplace(ctx context.Context, tx pgx.Tx) error {
	phase, err := s.LockAgentPhase(ctx, tx)
	if err != nil {
		return err
	}
	if phase == "DELETING" || phase == "DELETED" {
		return persistence.ErrTransition
	}
	return nil
}

// ReplacePermissions atomically revokes the locked grant and creates its replacement.
func (s Subject) ReplacePermissions(ctx context.Context, tx pgx.Tx, current Assignment, permissions []string) (Assignment, error) {
	if current.Status != "active" {
		return Assignment{}, persistence.ErrTransition
	}
	if err := s.canReplace(ctx, tx); err != nil {
		return Assignment{}, err
	}
	if _, err := s.RevokeAssignment(ctx, tx, current.ID); err != nil {
		return Assignment{}, err
	}
	in := Input{Permissions: permissions}
	if current.PrincipalID != nil {
		in.PrincipalID = *current.PrincipalID
	}
	if current.TeamID != nil {
		in.TeamID = *current.TeamID
	}
	if err := s.checkActiveTarget(ctx, tx, in); err != nil {
		return Assignment{}, err
	}
	return s.insertAssignment(ctx, tx, in)
}

// Reassign atomically moves the locked grant to a different active target.
func (s Subject) Reassign(ctx context.Context, tx pgx.Tx, current Assignment, in Input) (Assignment, error) {
	if current.Status != "active" || (current.PrincipalID != nil && *current.PrincipalID == in.PrincipalID) || (current.TeamID != nil && *current.TeamID == in.TeamID) {
		return Assignment{}, persistence.ErrTransition
	}
	if err := s.canReplace(ctx, tx); err != nil {
		return Assignment{}, err
	}
	if err := s.checkNewTarget(ctx, tx, in, false); err != nil {
		return Assignment{}, err
	}
	if len(in.Permissions) == 0 {
		in.Permissions = slices.Clone(current.Permissions)
	}
	if _, err := s.RevokeAssignment(ctx, tx, current.ID); err != nil {
		return Assignment{}, err
	}
	return s.insertAssignment(ctx, tx, in)
}

func personalTarget(ctx context.Context, tx pgx.Tx, tenant, agent, member string) error {
	var conflicts bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_personal_reservations WHERE tenant_id=$1 AND agent_id=$2 AND principal_id<>$3)
		OR EXISTS(SELECT 1 FROM personal_volume_holds WHERE tenant_id=$1 AND agent_id=$2 AND principal_id<>$3)`, tenant, agent, member).Scan(&conflicts)
	if err == nil && conflicts {
		return persistence.ErrTransition
	}
	return err
}

// ListAssignments reads a bounded page for the agent.
func (s Subject) ListAssignments(ctx context.Context, tx pgx.Tx, after string, limit int) ([]Assignment, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, s.Tenant, s.Agent).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, persistence.ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT `+assignmentColumns+` FROM agent_assignments WHERE tenant_id=$1 AND agent_id=$2 AND id>$3 ORDER BY id LIMIT $4`, s.Tenant, s.Agent, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Assignment{}
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
	return items, nil
}

// EffectivePermissions are the permissions a principal holds on one agent
// right now, through a direct assignment or an active team it actively belongs to.
func EffectivePermissions(ctx context.Context, tx pgx.Tx, tenant, principal, agentID string) ([]string, error) {
	var perms []string
	err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT perm),'{}') FROM agent_assignments s, unnest(s.permissions) perm
        WHERE s.tenant_id=$1 AND s.agent_id=$2 AND s.status='active' AND (s.principal_id=$3 OR s.team_id IN
          (SELECT m.team_id FROM team_memberships m JOIN teams t ON (t.tenant_id,t.id)=(m.tenant_id,m.team_id)
           WHERE m.tenant_id=$1 AND m.principal_id=$3 AND m.status='active' AND t.status='active'))`, tenant, agentID, principal).Scan(&perms)
	return perms, err
}
