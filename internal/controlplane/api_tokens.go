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

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

var (
	ErrAuthentication = errors.New("authentication required")
	ErrForbidden      = errors.New("operation is not permitted for this identity")
	ErrInput          = errors.New("invalid input")
	ErrInProgress     = errors.New("idempotent operation is in progress")
)

// Principal comes exclusively from Authenticate. HTTP request fields must never
// populate it. Administrative service identities do not represent a data owner.
type Principal struct {
	Kind    string
	ID      string
	TokenID string
	Scopes  []string
	// Bound by platform authentication; never accepted from request fields.
	platformHash [32]byte
	TenantID     string
	// Created only after cryptographic verification and current DB resolution.
	delegation *delegatedidentity.VerifiedIdentity
	// Set instead of delegation for a technical account token (acps_).
	service *serviceBinding
}

func tokenSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "acp_" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if strings.HasPrefix(secret, "acpp_") {
		return s.authenticatePlatform(ctx, secret)
	}
	if strings.HasPrefix(secret, serviceTokenPrefix) {
		return s.authenticateService(ctx, secret)
	}
	if len(secret) != 47 || !strings.HasPrefix(secret, "acp_") {
		return Principal{}, ErrAuthentication
	}
	hash := sha256.Sum256([]byte(secret))
	var p Principal
	err := s.pool.QueryRow(ctx, `SELECT t.kind,coalesce(t.user_id,t.service_account),t.id,t.scopes
        FROM api_tokens t LEFT JOIN users u ON u.id=t.user_id
        WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
        AND (t.kind='service' OR u.status='active')`, hash[:]).Scan(&p.Kind, &p.ID, &p.TokenID, &p.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrAuthentication
	}
	return p, err
}

// Lock and recheck current token/account authority in the transaction that
// consumes it, including before replaying an idempotent response. FOR SHARE
// excludes revocation until commit; an earlier revocation rejects this action.
func authorizePrincipal(ctx context.Context, tx pgx.Tx, p Principal, kind, scope string) error {
	if p.TokenID == "" || p.Kind != kind || (kind != "user" && kind != "service") {
		return ErrForbidden
	}
	var id string
	var scopes []string
	query := `SELECT service_account,scopes FROM api_tokens WHERE id=$1 AND kind='service'
        AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`
	if kind == "user" {
		// Keep the owner-before-token lock order explicit, including operations
		// that already hold a stronger lock on this user's account.
		var active bool
		err := tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1 FOR SHARE", p.ID).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
			return ErrAuthentication
		}
		if err != nil {
			return err
		}
		query = `SELECT user_id,scopes FROM api_tokens WHERE id=$1 AND kind='user'
            AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`
	}
	err := tx.QueryRow(ctx, query, p.TokenID).Scan(&id, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAuthentication
	}
	if err != nil {
		return err
	}
	if id != p.ID || (scope != "" && !slices.Contains(scopes, scope)) {
		return ErrForbidden
	}
	return nil
}

// BootstrapService creates the first service credential on an empty token
// registry. It is an operator-only database operation, never an HTTP endpoint.
// The secret is returned once to the caller; logs must not contain it.
func (s *Store) BootstrapService(ctx context.Context, account string, lifetime time.Duration) (string, error) {
	secret := tokenSecret()
	return secret, s.BootstrapServiceToken(ctx, account, secret, lifetime)
}

// BootstrapServiceToken lets the operator persist the secret before committing
// its hash. Retrying after an unknown commit is safe and never extends expiry.
// A new secret is accepted when no service token is active, which replaces an
// expired or revoked one without direct SQL.
func (s *Store) BootstrapServiceToken(ctx context.Context, account, secret string, lifetime time.Duration) error {
	if account == "" || len(account) > 100 || lifetime < time.Minute || lifetime > 365*24*time.Hour || len(secret) != 47 || !strings.HasPrefix(secret, "acp_") {
		return ErrInput
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret[4:])
	if err != nil || len(decoded) != 32 {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610043)"); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(secret))
	var sameActive, sameEver, anyActive bool
	if err = tx.QueryRow(ctx, `SELECT
        EXISTS(SELECT 1 FROM api_tokens WHERE kind='service' AND service_account=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()),
        EXISTS(SELECT 1 FROM api_tokens WHERE token_hash=$2),
        EXISTS(SELECT 1 FROM api_tokens WHERE kind='service' AND revoked_at IS NULL AND expires_at>clock_timestamp())`,
		account, hash[:]).Scan(&sameActive, &sameEver, &anyActive); err != nil {
		return err
	}
	if sameActive {
		return commit(ctx, tx)
	}
	// Same rule as the platform credential: never reuse a stored secret, never add
	// a second active service credential, but allow replacing an expired or
	// revoked one with a new secret.
	if sameEver || anyActive {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO api_tokens(id,kind,service_account,token_hash,scopes,expires_at)
        VALUES($1,'service',$2,$3,$4,clock_timestamp()+$5::bigint*interval '1 microsecond')`, newID("tok"), account, hash[:],
		[]string{"user:manage", "harness:read", "harness:publish", "harness:manage", "agent:read", "agent:manage"}, lifetime.Microseconds())
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}

// RevokeToken allows a personal token to revoke its own credential and a
// user-management service to revoke a personal credential. Services cannot use
// this operation to revoke other service accounts or gain owner authority.
func (s *Store) RevokeToken(ctx context.Context, p Principal, tokenID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	// Serialize concurrent revocations before acquiring the shared authority
	// locks, avoiding a self-revocation SHARE -> UPDATE lock-upgrade deadlock.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "api-token-revoke/"+tokenID); err != nil {
		return err
	}
	scope := ""
	if p.Kind == "service" {
		scope = "user:manage"
	}
	if err = authorizePrincipal(ctx, tx, p, p.Kind, scope); err != nil {
		return err
	}
	if p.Kind == "user" && tokenID != p.TokenID {
		return ErrNotFound
	}
	tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=coalesce(revoked_at,clock_timestamp())
        WHERE id=$1 AND kind='user'`, tokenID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return commit(ctx, tx)
}
