package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/individualidentity"
	"slices"
	"strings"
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

// AuthenticateDelegation verifies a signature, then resolves existing state. It
// never installs trust or provisions identity. With a nil verifier, the one
// the API uses, the token is verified with the key it names among the trusts
// registered in PostgreSQL (ADR 001, D-01); a non-nil verifier is a fixed
// configuration, still checked against the registered trust.
func (s *Store) AuthenticateDelegation(ctx context.Context, verifier *delegatedidentity.Verifier, raw string) (Principal, error) {
	if c, ok := selectApplication(raw); ok {
		return s.authenticateApp(ctx, raw, c)
	}
	issuer, audience, kid, err := delegatedidentity.Select(raw)
	if verifier == nil && err != nil {
		return Principal{}, ErrAuthentication
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer rollback(tx)
	if verifier == nil {
		if verifier, err = registeredVerifier(ctx, tx, issuer, audience, kid); err != nil {
			return Principal{}, err
		}
	}
	v, err := verifier.Verify(raw)
	if err != nil {
		return Principal{}, ErrAuthentication
	}
	current, err := resolveTenant(ctx, tx, v)
	if err != nil {
		return Principal{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Principal{}, err
	}
	return Principal{Kind: "tenant", ID: current.PrincipalID, TenantID: v.TenantID, TokenID: v.TokenID, Scopes: slices.Clone(v.Scopes), delegation: &v}, nil
}

// registeredVerifier builds the verifier of one registered key: the trust that
// the token names, restricted to the key it names. Its fingerprint is that
// key's, so that adding or retiring another key leaves it valid.
func registeredVerifier(ctx context.Context, tx pgx.Tx, issuer, audience, kid string) (*delegatedidentity.Verifier, error) {
	var p trustPolicy
	var key []byte
	var ttl int64
	err := tx.QueryRow(ctx, `SELECT t.tenant_id,coalesce(t.allowed_scopes,'{}'),t.max_ttl_nanoseconds,k.public_key
        FROM delegation_trusts t JOIN delegation_keys k USING (tenant_id,issuer,audience)
        WHERE t.issuer=$1 AND t.audience=$2 AND k.key_id=$3 AND k.retired_at IS NULL AND t.max_ttl_nanoseconds IS NOT NULL`,
		issuer, audience, kid).Scan(&p.tenant, &p.scopes, &ttl, &key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthentication
	}
	if err != nil {
		return nil, err
	}
	p.issuer, p.audience, p.ttl = issuer, audience, time.Duration(ttl)
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{p.trust(map[string]ed25519.PublicKey{kid: key})}})
	if err != nil {
		return nil, ErrAuthentication
	}
	return v, nil
}

// resolveTenant holds the organization's row FOR KEY SHARE until the
// transaction ends, then reads the principal, its membership, the issuer, the
// trust and the key without a lock (v0.1.0 audit, P-07; ADR 001, "Changes
// after the v0.1.0 audit"). Every transaction that revokes or changes one of
// these rows, a JTI tombstone included, takes the organization's row FOR
// UPDATE first, the one row lock FOR KEY SHARE conflicts with: a revocation
// waits for an admission authorized before it, and an admission that waited
// for a revocation reads it. FOR KEY SHARE lets the other updates of the row,
// and other admissions, through. No row is created by this function.
func resolveTenant(ctx context.Context, tx pgx.Tx, v delegatedidentity.VerifiedIdentity) (CurrentOrganization, error) {
	var current CurrentOrganization
	if strings.HasPrefix(v.Issuer, individualidentity.Prefix) {
		key, ok := individualidentity.Key(v.Issuer)
		if !ok || individualidentity.Subject(key) != v.Subject || v.Audience != v.TenantID {
			return current, ErrAuthentication
		}
	}
	o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1`+authorityLock(tx, " FOR KEY SHARE"), v.TenantID))
	if errors.Is(err, ErrNotFound) || (err == nil && o.Status != "active") {
		return current, ErrAuthentication
	}
	if err != nil {
		return current, err
	}
	current.Organization = o
	var status string
	err = tx.QueryRow(ctx, `SELECT id,display_name,status FROM principals
        WHERE tenant_id=$1 AND kind='user' AND issuer=$2 AND subject=$3`, v.TenantID, v.Issuer, v.Subject).Scan(&current.PrincipalID, &current.DisplayName, &status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	err = tx.QueryRow(ctx, `SELECT role,status FROM memberships WHERE tenant_id=$1 AND principal_id=$2`, v.TenantID, current.PrincipalID).Scan(&current.Role, &status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	var issuer string
	err = tx.QueryRow(ctx, `SELECT issuer FROM delegation_issuers WHERE tenant_id=$1 AND issuer=$2`, v.TenantID, v.Issuer).Scan(&issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	var fingerprint []byte
	var minimum time.Time
	var generation int64
	var held bool
	err = tx.QueryRow(ctx, `SELECT fingerprint,status,minimum_iat,generation,max_ttl_nanoseconds IS NOT NULL FROM delegation_trusts
		WHERE tenant_id=$1 AND issuer=$2 AND audience=$3`, v.TenantID, v.Issuer, v.Audience).Scan(&fingerprint, &status, &minimum, &generation, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return CurrentOrganization{}, ErrAuthentication
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	verified := bytes.Equal(fingerprint, v.TrustFingerprint[:])
	if held {
		// The signing key must still be valid: not retired, and its overlap
		// not ended. The identity was verified with the whole registered trust
		// or with this key alone; either fingerprint must be the current one.
		// A trust installed before its keys were held here (migration 0034)
		// has only its fingerprint, checked as before.
		var keyFingerprint []byte
		var keyValid bool
		err = tx.QueryRow(ctx, `SELECT fingerprint,retired_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FROM delegation_keys
			WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4`, v.TenantID, v.Issuer, v.Audience, v.KeyID).Scan(&keyFingerprint, &keyValid)
		if errors.Is(err, pgx.ErrNoRows) {
			return CurrentOrganization{}, ErrAuthentication
		}
		if err != nil {
			return CurrentOrganization{}, err
		}
		verified = keyValid && (verified || bytes.Equal(keyFingerprint, v.TrustFingerprint[:]))
	}
	if status != "active" || generation != v.TrustGeneration || generation <= 0 || !verified || v.IssuedAt.Before(minimum) {
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
	} else if p.app != nil {
		current, err = resolveApp(ctx, tx, *p.app)
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
