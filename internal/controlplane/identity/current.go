// Package identity resolves verified credentials against the current organization, membership, and revocation state.
package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/individualidentity"
	"github.com/jackc/pgx/v5"
)

var ErrAuthentication = errors.New("authentication required")

type Organization struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	PolicyVersion int64     `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
}

func ScanOrganization(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Name, &o.Status, &o.PolicyVersion, &o.CreatedAt)
	return o, err
}

type CurrentOrganization struct {
	Organization Organization `json:"organization"`
	PrincipalID  string       `json:"principal_id"`
	DisplayName  string       `json:"display_name"`
	Role         string       `json:"role"`
}

// Application identifies the verified application token and its activation.
type Application struct {
	Tenant, App, Subject, Token string
	Generation                  int64
	Issued, NotBefore, Expires  time.Time
	Scopes                      []string
}

// SnapshotTx marks a read-only repeatable read of authority and content at one snapshot.
type SnapshotTx struct{ pgx.Tx }

// activeOrganization serializes admissions with revocations at the organization row.
func activeOrganization(ctx context.Context, tx pgx.Tx, tenant string) (Organization, error) {
	query := "SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1"
	if _, snapshot := tx.(SnapshotTx); !snapshot {
		query += " FOR KEY SHARE"
	}
	o, err := ScanOrganization(tx.QueryRow(ctx, query, tenant))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && o.Status != "active") {
		return Organization{}, ErrAuthentication
	}
	return o, err
}

// ResolveDelegation holds the organization's row FOR KEY SHARE until the
// transaction ends, then reads the principal, its membership, the issuer, the
// trust and the key without a lock (v0.1.0 audit, P-07; ADR 001, "Changes
// after the v0.1.0 audit"). Every transaction that revokes or changes one of
// these rows, a JTI tombstone included, takes the organization's row FOR
// UPDATE first, the one row lock FOR KEY SHARE conflicts with: a revocation
// waits for an admission authorized before it, and an admission that waited
// for a revocation reads it. FOR KEY SHARE lets the other updates of the row,
// and other admissions, through. No row is created by this function.
func ResolveDelegation(ctx context.Context, tx pgx.Tx, v delegatedidentity.VerifiedIdentity) (CurrentOrganization, error) {
	var current CurrentOrganization
	if strings.HasPrefix(v.Issuer, individualidentity.Prefix) {
		key, ok := individualidentity.Key(v.Issuer)
		if !ok || individualidentity.Subject(key) != v.Subject || v.Audience != v.TenantID {
			return current, ErrAuthentication
		}
	}
	o, err := activeOrganization(ctx, tx, v.TenantID)
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

// ResolveServiceToken rechecks that the organization, the technical account, its
// membership and the token are all current. Every mutation of these rows
// holds the organization row FOR UPDATE, so FOR KEY SHARE on it, held until
// this transaction ends, excludes a concurrent revocation; the other rows are
// read without a lock (P-07, as resolveTenant).
func ResolveServiceToken(ctx context.Context, tx pgx.Tx, tenant, token string) (CurrentOrganization, error) {
	var current CurrentOrganization
	o, err := activeOrganization(ctx, tx, tenant)
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
          AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()`, token, tenant).Scan(&current.PrincipalID, &current.DisplayName, &status, &current.Role, &membership)
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

// ResolveApplication holds the organization's row FOR KEY SHARE until the
// transaction ends and reads the application, its activation, its principals
// and the membership without a lock, as resolveTenant does (P-07): every
// transaction that revokes or changes them takes that row FOR UPDATE first.
func ResolveApplication(ctx context.Context, tx pgx.Tx, b Application) (CurrentOrganization, error) {
	var current CurrentOrganization
	o, err := activeOrganization(ctx, tx, b.Tenant)
	if err != nil {
		return current, err
	}
	current.Organization = o
	err = tx.QueryRow(ctx, `SELECT p.id,p.display_name,m.role FROM applications a
        JOIN principals signer ON signer.id=a.signing_principal AND signer.status='active'
        JOIN principals integration ON integration.id=a.id AND integration.status='active'
        JOIN app_activations v ON v.app_id=a.id AND NOT v.disabled
        JOIN principals p ON (p.tenant_id,p.id)=(v.tenant_id,v.principal_id)
        JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
        WHERE a.tenant_id=$1 AND a.id=$2 AND a.generation=$3 AND a.minimum_iat<=$6 AND p.issuer=a.issuer AND p.subject=$4
        AND p.status='active' AND m.status='active' AND $5>clock_timestamp() AND $6<=clock_timestamp() AND $7<=clock_timestamp()`, b.Tenant, b.App, b.Generation, b.Subject, b.Expires, b.Issued, b.NotBefore).Scan(&current.PrincipalID, &current.DisplayName, &current.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrAuthentication
	}
	return current, err
}
