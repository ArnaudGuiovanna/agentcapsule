package controlplane

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Member is administrative metadata. Status is the membership status; these
// routes expose neither agent assignments nor any historical private content.
type Member struct {
	PrincipalID string             `json:"principal_id"`
	Issuer      string             `json:"issuer"`
	Subject     string             `json:"subject"`
	DisplayName string             `json:"display_name"`
	Role        authorization.Role `json:"role"`
	Status      string             `json:"status"`
	CreatedAt   time.Time          `json:"created_at"`
}
type CreateMemberInput struct {
	Issuer      string             `json:"issuer"`
	Subject     string             `json:"subject"`
	DisplayName string             `json:"display_name"`
	Role        authorization.Role `json:"role"`
}
type ChangeMemberRoleInput struct {
	Role authorization.Role `json:"role"`
}

const memberColumns = `p.id,p.issuer,p.subject,p.display_name,m.role,m.status,m.created_at`
const memberJoin = ` FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id) WHERE p.tenant_id=$1 AND p.kind='user'`

func scanMember(row pgx.Row) (Member, error) {
	var m Member
	err := row.Scan(&m.PrincipalID, &m.Issuer, &m.Subject, &m.DisplayName, &m.Role, &m.Status, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return m, err
}

func tenantAccess(p Principal) authorization.AccessContext {
	// Only used after authorizeTenant, with its private signed scopes and current
	// active organization/principal/membership. Never trust mutable p.Scopes.
	return authorization.AccessContext{TenantID: p.TenantID, ResourceTenantID: p.TenantID, PrincipalID: p.ID, TenantActive: true, PrincipalActive: true, Scopes: tenantScopes(p)}
}

func authorizeMemberMutation(ctx context.Context, tx pgx.Tx, p Principal) (CurrentOrganization, error) {
	return authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageMembers)
}

// Take the tenant's exclusive policy lock before resolving current authority.
// Callers still enforce their target-specific policy before consulting receipts.
func authorizeTenantAdminMutation(ctx context.Context, tx pgx.Tx, p Principal, action authorization.Action) (CurrentOrganization, error) {
	if !tenantBound(p) {
		return CurrentOrganization{}, ErrForbidden
	}
	scope, known := authorization.RequiredScope(action)
	if !known {
		return CurrentOrganization{}, ErrForbidden
	}
	// A token that never carried the scope cannot succeed, so refuse it before
	// taking the tenant-wide exclusive lock. authorizeTenant below remains the
	// authoritative check; this only keeps unauthorized callers from queueing.
	if !slices.Contains(tenantScopes(p), scope) {
		return CurrentOrganization{}, ErrForbidden
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, p.TenantID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	// UPDATE was acquired first. resolveTenant's SHARE request on our already
	// exclusive row neither upgrades nor releases it. It reloads state after wait.
	current, err := authorizeTenant(ctx, tx, p, scope)
	if err != nil {
		return CurrentOrganization{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), action) {
		return CurrentOrganization{}, ErrForbidden
	}
	return current, nil
}

func (a *Accounts) ListMembers(ctx context.Context, p Principal, after string, limit int) ([]Member, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeMemberRead)
	if err != nil {
		return nil, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadMemberMetadata) {
		return nil, ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT `+memberColumns+memberJoin+` AND p.id>$2 ORDER BY p.id LIMIT $3`, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	items := []Member{}
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}

func auditMember(ctx context.Context, tx pgx.Tx, p Principal, target, action string, before, after authorization.Role, changed bool) error {
	if changed {
		if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_member_audit(id,tenant_id,actor_principal_id,target_principal_id,action,previous_role,next_role,changed) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, newID("audit"), p.TenantID, p.ID, target, action, before, after, changed)
	return err
}

func (a *Accounts) CreateMember(ctx context.Context, p Principal, key string, in CreateMemberInput) (APIReceipt, error) {
	if !validRegisteredIdentity(in.Issuer) || !validRegisteredIdentity(in.Subject) || !validOrganizationText(in.DisplayName, 100) || !authorization.ValidRole(in.Role) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeMemberMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	existing, err := scanMember(tx.QueryRow(ctx, `SELECT `+memberColumns+memberJoin+` AND p.issuer=$2 AND p.subject=$3`, p.TenantID, in.Issuer, in.Subject))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return APIReceipt{}, err
	}
	found := err == nil
	if !authorization.CanChangeMemberRole(tenantAccess(p), authorization.Role(current.Role), existing.Role, in.Role) {
		return APIReceipt{}, ErrForbidden
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "member.create", key, in, func() (int, any, error) {
		if found {
			return 0, nil, ErrTransition
		}
		id := newID("prn")
		if _, err := tx.Exec(ctx, `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name) VALUES($1,$2,'user',$3,$4,$5)`, id, p.TenantID, in.Issuer, in.Subject, in.DisplayName); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,$3)`, p.TenantID, id, in.Role); err != nil {
			return 0, nil, err
		}
		m, err := scanMember(tx.QueryRow(ctx, `SELECT `+memberColumns+memberJoin+` AND p.id=$2`, p.TenantID, id))
		if err != nil {
			return 0, nil, err
		}
		if err = auditMember(ctx, tx, p, id, "member.created", "", in.Role, true); err != nil {
			return 0, nil, err
		}
		return 201, m, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func preserveOwner(ctx context.Context, tx pgx.Tx, tenant string, target Member) error {
	if target.Role != authorization.OrgOwner || target.Status != "active" {
		return nil
	}
	var owners int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN principals p ON (p.tenant_id,p.id)=(m.tenant_id,m.principal_id) WHERE m.tenant_id=$1 AND m.role='org_owner' AND m.status='active' AND p.status='active'`, tenant).Scan(&owners); err != nil {
		return err
	}
	if owners <= 1 {
		return ErrTransition
	}
	return nil
}

func (a *Accounts) ChangeMemberRole(ctx context.Context, p Principal, id, key string, in ChangeMemberRoleInput) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !authorization.ValidRole(in.Role) {
		return APIReceipt{}, ErrInput
	}
	return a.changeMember(ctx, p, id, key, &in)
}
func (a *Accounts) RevokeMember(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	return a.changeMember(ctx, p, id, key, nil)
}
func (a *Accounts) changeMember(ctx context.Context, p Principal, id, key string, role *ChangeMemberRoleInput) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeMemberMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	target, err := scanMember(tx.QueryRow(ctx, `SELECT `+memberColumns+memberJoin+` AND p.id=$2`, p.TenantID, id))
	if err != nil {
		return APIReceipt{}, err
	}
	operation, action := "member.revoke", "member.revoked"
	next := authorization.Role("")
	if role != nil {
		operation, action, next = "member.change_role", "member.role_changed", role.Role
	}
	access, actor := tenantAccess(p), authorization.Role(current.Role)
	if !authorization.CanManageMember(access, actor, target.Role) || !authorization.CanChangeMemberRole(access, actor, target.Role, next) {
		return APIReceipt{}, ErrForbidden
	}
	input := struct {
		PrincipalID string             `json:"principal_id"`
		Role        authorization.Role `json:"role"`
	}{id, next}
	r, err := a.withTenantReceipt(ctx, tx, p, operation, key, input, func() (int, any, error) {
		before := target.Role
		changed := target.Status == "active"
		if role != nil {
			if target.Status != "active" {
				return 0, nil, ErrTransition
			}
			changed = before != next
		}
		if changed && next != authorization.OrgOwner {
			if err := preserveOwner(ctx, tx, p.TenantID, target); err != nil {
				return 0, nil, err
			}
		}
		if role != nil {
			_, err = tx.Exec(ctx, `UPDATE memberships SET role=$3 WHERE tenant_id=$1 AND principal_id=$2`, p.TenantID, id, next)
			target.Role = next
		} else {
			_, err = tx.Exec(ctx, `UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2`, p.TenantID, id)
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2`, p.TenantID, id)
			}
			target.Status = "revoked"
		}
		if err != nil {
			return 0, nil, err
		}
		// Technical-account tokens issued by this person lapse with the right that
		// justified them: all on offboarding, those no longer manageable on demotion.
		if changed {
			if err = revokeIssuedServiceTokens(ctx, tx, p, id, next); err != nil {
				return 0, nil, err
			}
		}
		if err = auditMember(ctx, tx, p, id, action, before, next, changed); err != nil {
			return 0, nil, err
		}
		return 200, target, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
