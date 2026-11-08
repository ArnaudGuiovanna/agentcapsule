package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Team and TeamMembership are administrative metadata, never effective agent
// permissions. team:read does not expose external issuer/subject identities or roles.
type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type TeamMembership struct {
	TeamID      string    `json:"team_id"`
	PrincipalID string    `json:"principal_id"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}
type CreateTeamInput struct {
	Name string `json:"name"`
}
type AddTeamMemberInput struct {
	PrincipalID string `json:"principal_id"`
}

func scanTeam(row pgx.Row) (Team, error) {
	var t Team
	err := row.Scan(&t.ID, &t.Name, &t.Status, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return t, err
}
func scanTeamMembership(row pgx.Row) (TeamMembership, error) {
	var m TeamMembership
	err := row.Scan(&m.TeamID, &m.PrincipalID, &m.Status, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return m, err
}
func teamByID(ctx context.Context, tx pgx.Tx, tenant, id string) (Team, error) {
	return scanTeam(tx.QueryRow(ctx, `SELECT id,name,status,created_at FROM teams WHERE tenant_id=$1 AND id=$2`, tenant, id))
}
func authorizeTeamRead(ctx context.Context, tx pgx.Tx, p Principal) error {
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeTeamRead)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadTeamMetadata) {
		return ErrForbidden
	}
	return nil
}

func (a *Accounts) ListTeams(ctx context.Context, p Principal, after string, limit int) ([]Team, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizeTeamRead(ctx, tx, p); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id,name,status,created_at FROM teams WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	items := []Team{}
	for rows.Next() {
		item, err := scanTeam(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}
func (a *Accounts) GetTeam(ctx context.Context, p Principal, id string) (Team, error) {
	if !validOrganizationText(id, 100) {
		return Team{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return Team{}, err
	}
	defer rollback(tx)
	if err = authorizeTeamRead(ctx, tx, p); err != nil {
		return Team{}, err
	}
	t, err := teamByID(ctx, tx, p.TenantID, id)
	if err != nil {
		return Team{}, err
	}
	return t, commit(ctx, tx)
}
func (a *Accounts) ListTeamMembers(ctx context.Context, p Principal, id, after string, limit int) ([]TeamMembership, error) {
	if !validOrganizationText(id, 100) || limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizeTeamRead(ctx, tx, p); err != nil {
		return nil, err
	}
	if _, err = teamByID(ctx, tx, p.TenantID, id); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT team_id,principal_id,status,created_at FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 AND principal_id>$3 ORDER BY principal_id LIMIT $4`, p.TenantID, id, after, limit)
	if err != nil {
		return nil, err
	}
	items := []TeamMembership{}
	for rows.Next() {
		item, err := scanTeamMembership(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}

func auditTeam(ctx context.Context, tx pgx.Tx, p Principal, team string, target *string, action, before, after string, changed bool) error {
	if changed {
		if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_team_audit(id,tenant_id,actor_principal_id,team_id,target_principal_id,action,previous_status,next_status,changed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, newID("audit"), p.TenantID, p.ID, team, target, action, before, after, changed)
	return err
}
func (a *Accounts) CreateTeam(ctx context.Context, p Principal, key string, in CreateTeamInput) (APIReceipt, error) {
	if !validOrganizationText(in.Name, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageTeams); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "team.create", key, in, func() (int, any, error) {
		t, err := scanTeam(tx.QueryRow(ctx, `INSERT INTO teams(id,tenant_id,name) VALUES($1,$2,$3) RETURNING id,name,status,created_at`, newID("team"), p.TenantID, in.Name))
		if err != nil {
			return 0, nil, err
		}
		if err = auditTeam(ctx, tx, p, t.ID, nil, "team.created", "", t.Status, true); err != nil {
			return 0, nil, err
		}
		return 201, t, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
func (a *Accounts) DisableTeam(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageTeams); err != nil {
		return APIReceipt{}, err
	}
	t, err := teamByID(ctx, tx, p.TenantID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		TeamID string `json:"team_id"`
	}{id}
	r, err := a.withTenantReceipt(ctx, tx, p, "team.disable", key, in, func() (int, any, error) {
		before := t.Status
		if _, err := tx.Exec(ctx, `UPDATE teams SET status='disabled' WHERE tenant_id=$1 AND id=$2`, p.TenantID, id); err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND team_id=$2 AND status='active'`, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		t.Status = "disabled"
		if err = auditTeam(ctx, tx, p, id, nil, "team.disabled", before, t.Status, before != t.Status || tag.RowsAffected() > 0); err != nil {
			return 0, nil, err
		}
		return 200, t, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
func (a *Accounts) AddTeamMember(ctx context.Context, p Principal, team, key string, in AddTeamMemberInput) (APIReceipt, error) {
	return a.changeTeamMembership(ctx, p, team, in.PrincipalID, key, true)
}
func (a *Accounts) RevokeTeamMember(ctx context.Context, p Principal, team, principal, key string) (APIReceipt, error) {
	return a.changeTeamMembership(ctx, p, team, principal, key, false)
}
func (a *Accounts) changeTeamMembership(ctx context.Context, p Principal, team, principal, key string, add bool) (APIReceipt, error) {
	if !validOrganizationText(team, 100) || !validOrganizationText(principal, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageTeams); err != nil {
		return APIReceipt{}, err
	}
	t, err := teamByID(ctx, tx, p.TenantID, team)
	if err != nil {
		return APIReceipt{}, err
	}
	var principalStatus, memberStatus string
	err = tx.QueryRow(ctx, `SELECT p.status,m.status FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id) WHERE p.tenant_id=$1 AND p.id=$2 AND p.kind='user'`, p.TenantID, principal).Scan(&principalStatus, &memberStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	// These current target checks also precede an exact receipt replay. Cleanup
	// remains possible for disabled teams and already-revoked human members.
	if add && (t.Status != "active" || principalStatus != "active" || memberStatus != "active") {
		return APIReceipt{}, ErrTransition
	}
	m, err := scanTeamMembership(tx.QueryRow(ctx, `SELECT team_id,principal_id,status,created_at FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 AND principal_id=$3`, p.TenantID, team, principal))
	if err != nil && (!add || !errors.Is(err, ErrNotFound)) {
		return APIReceipt{}, err
	}
	exists := err == nil
	operation, action, next := "team.member_revoke", "team.member_revoked", "revoked"
	if add {
		operation, action, next = "team.member_add", "team.member_added", "active"
	}
	in := struct {
		TeamID      string `json:"team_id"`
		PrincipalID string `json:"principal_id"`
	}{team, principal}
	r, err := a.withTenantReceipt(ctx, tx, p, operation, key, in, func() (int, any, error) {
		before, status := m.Status, 200
		if !exists {
			status = 201
			m, err = scanTeamMembership(tx.QueryRow(ctx, `INSERT INTO team_memberships(tenant_id,team_id,principal_id) VALUES($1,$2,$3) RETURNING team_id,principal_id,status,created_at`, p.TenantID, team, principal))
		} else if before != next {
			_, err = tx.Exec(ctx, `UPDATE team_memberships SET status=$4 WHERE tenant_id=$1 AND team_id=$2 AND principal_id=$3`, p.TenantID, team, principal, next)
			m.Status = next
		}
		if err != nil {
			return 0, nil, err
		}
		if err = auditTeam(ctx, tx, p, team, &principal, action, before, m.Status, before != m.Status); err != nil {
			return 0, nil, err
		}
		return status, m, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
