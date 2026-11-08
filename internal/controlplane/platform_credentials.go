package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func validPlatformSecret(secret string) bool {
	if len(secret) != 48 || !strings.HasPrefix(secret, "acpp_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret[5:])
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == secret[5:]
}

// BootstrapPlatformToken is a trusted local installation operation, never an
// HTTP endpoint. The operator persists the secret before calling it. A retry
// with that same secret/account confirms the prior commit without extending its
// expiry or reviving a revoked credential. A new secret is accepted only when no
// platform credential is active, so an expired or revoked credential can be
// replaced without SQL. Legacy tokens are not consulted.
func (s *Store) BootstrapPlatformToken(ctx context.Context, account, secret string, lifetime time.Duration) error {
	if !validOrganizationText(account, 100) || !validPlatformSecret(secret) || lifetime < time.Minute || lifetime > 365*24*time.Hour {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610045)"); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(secret))
	var sameActive, sameEver, anyActive bool
	if err = tx.QueryRow(ctx, `SELECT
        EXISTS(SELECT 1 FROM platform_credentials WHERE account=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()),
        EXISTS(SELECT 1 FROM platform_credentials WHERE token_hash=$2),
        EXISTS(SELECT 1 FROM platform_credentials WHERE revoked_at IS NULL AND expires_at>clock_timestamp())`,
		account, hash[:]).Scan(&sameActive, &sameEver, &anyActive); err != nil {
		return err
	}
	if sameActive {
		return commit(ctx, tx)
	}
	// A secret that was ever stored is never reused, and a second active
	// credential is never added. A new secret is accepted only when no credential
	// is active, which is the recovery path after expiry or revocation.
	if sameEver || anyActive {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO platform_credentials(id,account,token_hash,scopes,expires_at)
        VALUES($1,$2,$3,$4,clock_timestamp()+$5::bigint*interval '1 microsecond')`,
		newID("ptok"), account, hash[:], []string{"platform:admin"}, lifetime.Microseconds())
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (s *Store) authenticatePlatform(ctx context.Context, secret string) (Principal, error) {
	if !validPlatformSecret(secret) {
		return Principal{}, ErrAuthentication
	}
	hash := sha256.Sum256([]byte(secret))
	var p Principal
	p.platformHash = hash
	err := s.pool.QueryRow(ctx, `SELECT 'platform',account,id,scopes FROM platform_credentials
        WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash[:]).Scan(&p.Kind, &p.ID, &p.TokenID, &p.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrAuthentication
	}
	return p, err
}

// Deliberately separate from authorizePrincipal: no legacy route accepts a
// platform identity. The current database scopes, expiry and revocation are
// rechecked and held through mutation/read/receipt replay until commit.
func authorizePlatform(ctx context.Context, tx pgx.Tx, p Principal) error {
	if p.Kind != "platform" || p.TokenID == "" {
		return ErrForbidden
	}
	var account string
	var scopes []string
	err := tx.QueryRow(ctx, `SELECT account,scopes FROM platform_credentials
		WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`, p.TokenID, p.platformHash[:]).Scan(&account, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAuthentication
	}
	if err != nil {
		return err
	}
	if account != p.ID || !slices.Contains(scopes, "platform:admin") {
		return ErrForbidden
	}
	return nil
}

// OperatorCredential is the non-secret description of a bootstrap credential.
type OperatorCredential struct {
	Kind      string     `json:"kind"`
	ID        string     `json:"id"`
	Account   string     `json:"account"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Status    string     `json:"status"`
}

// ListOperatorCredentials describes platform and service credentials for the
// local operator. It never returns a hash or a secret.
func (s *Store) ListOperatorCredentials(ctx context.Context) ([]OperatorCredential, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT kind,id,account,expires_at,revoked_at,
        CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END
        FROM (SELECT 'platform' AS kind,id,account,expires_at,revoked_at FROM platform_credentials
              UNION ALL
              SELECT 'service',id,service_account,expires_at,revoked_at FROM api_tokens WHERE kind='service') c
        ORDER BY kind,expires_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperatorCredential
	for rows.Next() {
		var c OperatorCredential
		if err = rows.Scan(&c.Kind, &c.ID, &c.Account, &c.ExpiresAt, &c.RevokedAt, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, commit(ctx, tx)
}

// RevokeOperatorCredential is a trusted local operation. It permanently revokes
// a platform or service credential and is idempotent. Revocation takes effect at
// the next request because authentication reads the row each time.
func (s *Store) RevokeOperatorCredential(ctx context.Context, kind, id string) error {
	var table, where string
	switch kind {
	case "platform":
		table, where = "platform_credentials", ""
	case "service":
		table, where = "api_tokens", " AND kind='service'"
	default:
		return ErrInput
	}
	if !validOrganizationText(id, 100) {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var revoked bool
	err = tx.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM "+table+" WHERE id=$1"+where+" FOR UPDATE", id).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !revoked {
		if _, err = tx.Exec(ctx, "UPDATE "+table+" SET revoked_at=clock_timestamp() WHERE id=$1"+where, id); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}
