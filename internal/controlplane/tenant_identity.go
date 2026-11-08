package controlplane

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

type CurrentOrganization struct {
	Organization Organization `json:"organization"`
	PrincipalID  string       `json:"principal_id"`
	DisplayName  string       `json:"display_name"`
	Role         string       `json:"role"`
}

// AuthenticateDelegation verifies a signature using immutable local config,
// then resolves existing state. It never installs trust or provisions identity.
func (s *Store) AuthenticateDelegation(ctx context.Context, verifier *delegatedidentity.Verifier, raw string) (Principal, error) {
	v, err := verifier.Verify(raw)
	if err != nil {
		return Principal{}, ErrAuthentication
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer rollback(tx)
	current, err := resolveTenant(ctx, tx, v)
	if err != nil {
		return Principal{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Principal{}, err
	}
	return Principal{Kind: "tenant", ID: current.PrincipalID, TenantID: v.TenantID, TokenID: v.TokenID, Scopes: slices.Clone(v.Scopes), delegation: &v}, nil
}

// Lock order is organization -> principal -> membership -> issuer -> trust.
// Issuer SHARE protects even an absent JTI tombstone: all revocations take that
// existing anchor in UPDATE before writing. No row is created by this function.
func resolveTenant(ctx context.Context, tx pgx.Tx, v delegatedidentity.VerifiedIdentity) (CurrentOrganization, error) {
	var current CurrentOrganization
	o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1 FOR SHARE`, v.TenantID))
	if errors.Is(err, ErrNotFound) || (err == nil && o.Status != "active") {
		return current, ErrAuthentication
	}
	if err != nil {
		return current, err
	}
	current.Organization = o
	var status string
	err = tx.QueryRow(ctx, `SELECT id,display_name,status FROM principals
        WHERE tenant_id=$1 AND kind='user' AND issuer=$2 AND subject=$3 FOR SHARE`, v.TenantID, v.Issuer, v.Subject).Scan(&current.PrincipalID, &current.DisplayName, &status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	err = tx.QueryRow(ctx, `SELECT role,status FROM memberships WHERE tenant_id=$1 AND principal_id=$2 FOR SHARE`, v.TenantID, current.PrincipalID).Scan(&current.Role, &status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	var issuer string
	err = tx.QueryRow(ctx, `SELECT issuer FROM delegation_issuers WHERE tenant_id=$1 AND issuer=$2 FOR SHARE`, v.TenantID, v.Issuer).Scan(&issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	var fingerprint []byte
	var minimum time.Time
	var generation int64
	err = tx.QueryRow(ctx, `SELECT fingerprint,status,minimum_iat,generation FROM delegation_trusts
		WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 FOR SHARE`, v.TenantID, v.Issuer, v.Audience).Scan(&fingerprint, &status, &minimum, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	if status != "active" || generation != v.TrustGeneration || generation <= 0 || !bytes.Equal(fingerprint, v.TrustFingerprint[:]) || v.IssuedAt.Before(minimum) {
		return CurrentOrganization{}, ErrAuthentication
	}
	var revoked, validTime bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM delegation_revocations WHERE tenant_id=$1 AND issuer=$2 AND token_id=$3),
		$4::timestamptz>clock_timestamp() AND $5::timestamptz<=clock_timestamp() AND $6::timestamptz<=clock_timestamp()`, v.TenantID, v.Issuer, v.TokenID, v.ExpiresAt, v.IssuedAt, v.NotBefore).Scan(&revoked, &validTime)
	if err != nil {
		return CurrentOrganization{}, err
	}
	if revoked || !validTime {
		return CurrentOrganization{}, ErrAuthentication
	}
	return current, nil
}

func authorizeTenant(ctx context.Context, tx pgx.Tx, p Principal, scope string) (CurrentOrganization, error) {
	if !tenantBound(p) {
		return CurrentOrganization{}, ErrForbidden
	}
	var current CurrentOrganization
	var err error
	if p.delegation != nil {
		current, err = resolveTenant(ctx, tx, *p.delegation)
	} else {
		current, err = resolveService(ctx, tx, *p.service)
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	if current.PrincipalID != p.ID || !slices.Contains(tenantScopes(p), scope) {
		return CurrentOrganization{}, ErrForbidden
	}
	return current, nil
}

func (a *Accounts) CurrentOrganization(ctx context.Context, p Principal) (CurrentOrganization, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return CurrentOrganization{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, "org:read")
	if err != nil {
		return CurrentOrganization{}, err
	}
	return current, commit(ctx, tx)
}
