package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// serviceBinding is what a technical-account token proves once authenticated.
// Like a delegated identity it is only a claim: authorizeTenant resolves the
// current organization, principal, membership and token again in the consuming
// transaction.
type serviceBinding struct {
	tenantID, tokenID string
	scopes            []string
}

const serviceTokenPrefix = "acps_"

func newServiceSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return serviceTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func validServiceSecret(secret string) bool {
	if len(secret) != 48 || !strings.HasPrefix(secret, serviceTokenPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret[len(serviceTokenPrefix):])
	return err == nil && len(decoded) == 32
}

// tenantScopes returns the scopes carried by whichever credential authenticated
// a tenant principal. They are an upper bound; roles and assignments still apply.
func tenantScopes(p Principal) []string {
	switch {
	case p.delegation != nil:
		return p.delegation.Scopes
	case p.service != nil:
		return p.service.scopes
	}
	return nil
}

// tenantBound reports whether the principal is a tenant principal whose
// credential binding agrees with the identity fields the rest of the code uses.
func tenantBound(p Principal) bool {
	if p.Kind != "tenant" {
		return false
	}
	switch {
	case p.delegation != nil:
		return p.TenantID == p.delegation.TenantID && p.TokenID == p.delegation.TokenID
	case p.service != nil:
		return p.TenantID == p.service.tenantID && p.TokenID == p.service.tokenID
	}
	return false
}

func (s *Store) authenticateService(ctx context.Context, secret string) (Principal, error) {
	if !validServiceSecret(secret) {
		return Principal{}, ErrAuthentication
	}
	hash := sha256.Sum256([]byte(secret))
	tx, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer rollback(tx)
	var b serviceBinding
	var principal string
	err = tx.QueryRow(ctx, `SELECT tenant_id,principal_id,id,scopes FROM service_tokens
        WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash[:]).Scan(&b.tenantID, &principal, &b.tokenID, &b.scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrAuthentication
	}
	if err != nil {
		return Principal{}, err
	}
	current, err := resolveService(ctx, tx, b)
	if err != nil {
		return Principal{}, err
	}
	if current.PrincipalID != principal {
		return Principal{}, ErrAuthentication
	}
	if err = commit(ctx, tx); err != nil {
		return Principal{}, err
	}
	return Principal{Kind: "tenant", ID: principal, TenantID: b.tenantID, TokenID: b.tokenID, Scopes: slices.Clone(b.scopes), service: &b}, nil
}

// resolveService rechecks, under shared locks, that the organization, the
// technical account, its membership and the token are all current. Every
// mutation of these rows holds the organization row exclusively, so shared
// access to it excludes a concurrent revocation until this transaction ends.
func resolveService(ctx context.Context, tx pgx.Tx, b serviceBinding) (CurrentOrganization, error) {
	var current CurrentOrganization
	o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1 FOR SHARE`, b.tenantID))
	if errors.Is(err, ErrNotFound) || (err == nil && o.Status != "active") {
		return current, ErrAuthentication
	}
	if err != nil {
		return current, err
	}
	current.Organization = o
	var status, membership string
	err = tx.QueryRow(ctx, `SELECT p.id,p.display_name,p.status,m.role,m.status
        FROM service_tokens t
        JOIN principals p ON (p.tenant_id,p.id)=(t.tenant_id,t.principal_id)
        JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
        WHERE t.id=$1 AND t.tenant_id=$2 AND p.kind='service'
          AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
        FOR SHARE OF t,p,m`, b.tokenID, b.tenantID).Scan(&current.PrincipalID, &current.DisplayName, &status, &current.Role, &membership)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	if status != "active" || membership != "active" {
		return CurrentOrganization{}, ErrAuthentication
	}
	return current, nil
}

// revokeIssuedServiceTokens revokes tokens a person issued when that person
// leaves (newRole empty) or is demoted to a role that can no longer manage the
// technical account. It runs inside the member mutation, under the organization
// lock, so no token can be issued concurrently on stale authority.
func revokeIssuedServiceTokens(ctx context.Context, tx pgx.Tx, actor Principal, issuer string, newRole authorization.Role) error {
	_, err := tx.Exec(ctx, `UPDATE service_tokens t SET revoked_at=clock_timestamp(),revoked_by=$4
        FROM memberships m
        WHERE t.tenant_id=$1 AND t.issued_by=$2 AND t.revoked_at IS NULL
          AND m.tenant_id=t.tenant_id AND m.principal_id=t.principal_id
          AND NOT ($3='org_owner') AND ($3<>'org_admin' OR m.role='org_admin')`, actor.TenantID, issuer, string(newRole), actor.ID)
	return err
}

type ServiceAccount struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Role      authorization.Role `json:"role"`
	Status    string             `json:"status"`
	CreatedAt time.Time          `json:"created_at"`
}
type CreateServiceAccountInput struct {
	Name string             `json:"name"`
	Role authorization.Role `json:"role"`
}
type ServiceToken struct {
	ID               string     `json:"id"`
	ServiceAccountID string     `json:"service_account_id"`
	Scopes           []string   `json:"scopes"`
	ExpiresAt        time.Time  `json:"expires_at"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// IssuedServiceToken carries the secret exactly once, in the idempotent receipt.
type IssuedServiceToken struct {
	ServiceToken
	Token string `json:"token"`
}
type IssueServiceTokenInput struct {
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

const serviceAccountColumns = `p.id,p.display_name,m.role,CASE WHEN p.status='active' AND m.status='active' THEN 'active' ELSE 'disabled' END,p.created_at`
const serviceAccountFrom = ` FROM principals p JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id) WHERE p.tenant_id=$1 AND p.kind='service'`

func scanServiceAccount(row pgx.Row) (ServiceAccount, error) {
	var s ServiceAccount
	err := row.Scan(&s.ID, &s.Name, &s.Role, &s.Status, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return s, err
}

const serviceTokenColumns = `id,principal_id,scopes,expires_at,
    CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END,created_at,revoked_at`

func scanServiceToken(row pgx.Row) (ServiceToken, error) {
	var t ServiceToken
	err := row.Scan(&t.ID, &t.ServiceAccountID, &t.Scopes, &t.ExpiresAt, &t.Status, &t.CreatedAt, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return t, err
}

// authorizeIdentityMutation requires a human credential: a technical account
// never issues or manages credentials, including its own and other accounts'.
func authorizeIdentityMutation(ctx context.Context, tx pgx.Tx, p Principal) (CurrentOrganization, error) {
	if p.delegation == nil {
		return CurrentOrganization{}, ErrForbidden
	}
	return authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageIdentities)
}

func auditService(ctx context.Context, tx pgx.Tx, p Principal, service string, token *string, action string) error {
	if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_service_audit(id,tenant_id,actor_principal_id,service_principal_id,token_id,action) VALUES($1,$2,$3,$4,$5,$6)`,
		newID("audit"), p.TenantID, p.ID, service, token, action)
	return err
}

func (a *Accounts) CreateServiceAccount(ctx context.Context, p Principal, key string, in CreateServiceAccountInput) (APIReceipt, error) {
	if !validOrganizationText(in.Name, 100) || !authorization.ValidRole(in.Role) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeIdentityMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	if !authorization.CanManageServiceAccountRole(tenantAccess(p), authorization.Role(current.Role), in.Role) {
		return APIReceipt{}, ErrForbidden
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "service_account.create", key, in, func() (int, any, error) {
		id := newID("svc")
		if _, err := tx.Exec(ctx, `INSERT INTO principals(id,tenant_id,kind,display_name) VALUES($1,$2,'service',$3)`, id, p.TenantID, in.Name); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,$3)`, p.TenantID, id, in.Role); err != nil {
			return 0, nil, err
		}
		if err := auditService(ctx, tx, p, id, nil, "service_account.created"); err != nil {
			return 0, nil, err
		}
		s, err := scanServiceAccount(tx.QueryRow(ctx, `SELECT `+serviceAccountColumns+serviceAccountFrom+` AND p.id=$2`, p.TenantID, id))
		return 201, s, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) readServiceAccounts(ctx context.Context, p Principal, fn func(tx pgx.Tx) error) error {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if p.delegation == nil {
		return ErrForbidden
	}
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeIdentityManage)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ManageIdentities) {
		return ErrForbidden
	}
	if err = fn(tx); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (a *Accounts) ListServiceAccounts(ctx context.Context, p Principal, after string, limit int) ([]ServiceAccount, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	items := []ServiceAccount{}
	err := a.readServiceAccounts(ctx, p, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+serviceAccountColumns+serviceAccountFrom+` AND p.id>$2 ORDER BY p.id LIMIT $3`, p.TenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanServiceAccount(rows)
			if err != nil {
				return err
			}
			items = append(items, s)
		}
		return rows.Err()
	})
	return items, err
}

func (a *Accounts) ListServiceTokens(ctx context.Context, p Principal, id, after string, limit int) ([]ServiceToken, error) {
	if !validOrganizationText(id, 100) || limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	items := []ServiceToken{}
	err := a.readServiceAccounts(ctx, p, func(tx pgx.Tx) error {
		if _, err := scanServiceAccount(tx.QueryRow(ctx, `SELECT `+serviceAccountColumns+serviceAccountFrom+` AND p.id=$2`, p.TenantID, id)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+serviceTokenColumns+` FROM service_tokens WHERE tenant_id=$1 AND principal_id=$2 AND id>$3 ORDER BY id LIMIT $4`, p.TenantID, id, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanServiceToken(rows)
			if err != nil {
				return err
			}
			items = append(items, t)
		}
		return rows.Err()
	})
	return items, err
}

// serviceTarget locks a technical account and checks the actor may manage it.
func serviceTarget(ctx context.Context, tx pgx.Tx, p Principal, actor authorization.Role, id string) (ServiceAccount, error) {
	s, err := scanServiceAccount(tx.QueryRow(ctx, `SELECT `+serviceAccountColumns+serviceAccountFrom+` AND p.id=$2 FOR UPDATE OF p,m`, p.TenantID, id))
	if err != nil {
		return ServiceAccount{}, err
	}
	if !authorization.CanManageServiceAccountRole(tenantAccess(p), actor, s.Role) {
		return ServiceAccount{}, ErrForbidden
	}
	return s, nil
}

func (a *Accounts) DisableServiceAccount(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeIdentityMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	target, err := serviceTarget(ctx, tx, p, authorization.Role(current.Role), id)
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		ServiceAccountID string `json:"service_account_id"`
	}{id}
	r, err := a.withTenantReceipt(ctx, tx, p, "service_account.disable", key, in, func() (int, any, error) {
		if target.Status == "disabled" {
			return 200, target, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE principals SET status='disabled' WHERE tenant_id=$1 AND id=$2`, p.TenantID, id); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2`, p.TenantID, id); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=$3 WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL`, p.TenantID, id, p.ID); err != nil {
			return 0, nil, err
		}
		if err := auditService(ctx, tx, p, id, nil, "service_account.disabled"); err != nil {
			return 0, nil, err
		}
		target.Status = "disabled"
		return 200, target, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func validTokenScopes(requested, held []string) ([]string, bool) {
	if len(requested) == 0 || len(requested) > 32 {
		return nil, false
	}
	out := []string{}
	for _, scope := range requested {
		// A token can never exceed the credential that issued it, nor leave the
		// closed registry of scopes a technical account may hold.
		if !slices.Contains(authorization.DelegableScopes, scope) || !slices.Contains(held, scope) || slices.Contains(out, scope) {
			return nil, false
		}
		out = append(out, scope)
	}
	slices.Sort(out)
	return out, true
}

func (a *Accounts) IssueServiceToken(ctx context.Context, p Principal, id, key string, in IssueServiceTokenInput) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || in.ExpiresAt.IsZero() {
		return APIReceipt{}, ErrInput
	}
	scopes, ok := validTokenScopes(in.Scopes, tenantScopes(p))
	if !ok {
		return APIReceipt{}, ErrInput
	}
	in.Scopes = scopes
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeIdentityMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	target, err := serviceTarget(ctx, tx, p, authorization.Role(current.Role), id)
	if err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "service_token.issue/"+id, key, in, func() (int, any, error) {
		if target.Status != "active" {
			return 0, nil, ErrTransition
		}
		var allowed bool
		if err := tx.QueryRow(ctx, "SELECT $1::timestamptz>clock_timestamp() AND $1::timestamptz<=clock_timestamp()+interval '365 days'", in.ExpiresAt).Scan(&allowed); err != nil {
			return 0, nil, err
		}
		if !allowed {
			return 0, nil, ErrInput
		}
		secret := newServiceSecret()
		hash := sha256.Sum256([]byte(secret))
		token, err := scanServiceToken(tx.QueryRow(ctx, `INSERT INTO service_tokens(id,tenant_id,principal_id,token_hash,scopes,expires_at,issued_by)
            VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+serviceTokenColumns, newID("stk"), p.TenantID, id, hash[:], in.Scopes, in.ExpiresAt, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditService(ctx, tx, p, id, &token.ID, "token.issued"); err != nil {
			return 0, nil, err
		}
		return 201, IssuedServiceToken{ServiceToken: token, Token: secret}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) RevokeServiceToken(ctx context.Context, p Principal, id, tokenID, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !validOrganizationText(tokenID, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	current, err := authorizeIdentityMutation(ctx, tx, p)
	if err != nil {
		return APIReceipt{}, err
	}
	if _, err = serviceTarget(ctx, tx, p, authorization.Role(current.Role), id); err != nil {
		return APIReceipt{}, err
	}
	token, err := scanServiceToken(tx.QueryRow(ctx, `SELECT `+serviceTokenColumns+` FROM service_tokens WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE`, p.TenantID, id, tokenID))
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		ServiceAccountID string `json:"service_account_id"`
		TokenID          string `json:"token_id"`
	}{id, tokenID}
	r, err := a.withTenantReceipt(ctx, tx, p, "service_token.revoke", key, in, func() (int, any, error) {
		if token.Status == "revoked" {
			return 200, token, nil
		}
		token, err = scanServiceToken(tx.QueryRow(ctx, `UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=$4
            WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 RETURNING `+serviceTokenColumns, p.TenantID, id, tokenID, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditService(ctx, tx, p, id, &token.ID, "token.revoked"); err != nil {
			return 0, nil, err
		}
		return 200, token, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
