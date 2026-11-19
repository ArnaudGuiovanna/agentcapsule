package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

// MaxKeyOverlap bounds how long a retired delegation key keeps signing valid
// tokens. A longer overlap is an unretired key, and is refused.
const MaxKeyOverlap = 30 * 24 * time.Hour

// DelegationChange is trusted operator input, never constructed from a JWT.
// Install is idempotent for an already-active identical trust. Rotate explicitly
// replaces/reactivates a trust, including the same fingerprint, and rejects
// tokens from previous signed generations. The iat cutoff is freshness policy,
// not proof of when a token was physically signed. OperationID stays stable on retries.
//
// add-key and retire-key change one key of an active trust without changing its
// generation or its iat cutoff, so that tokens signed with the other keys keep
// working: this is the overlap of a routine key rotation (ADR 001, D-01).
type DelegationChange struct {
	OperationID string
	Actor       string
	Action      string // install, rotate, revoke-trust, revoke-token, add-key, retire-key
	TenantID    string
	Issuer      string
	Audience    string
	TokenID     string
	Trust       *delegatedidentity.Trust // install/rotate only, from operator config
	// KeyID is the key that add-key adds, with PublicKey, or that retire-key retires.
	KeyID     string
	PublicKey ed25519.PublicKey
	// Overlap is how long retire-key still accepts tokens signed with the key;
	// zero retires it at once.
	Overlap time.Duration
	// DryRun checks the change and returns its result without recording it:
	// no change, no receipt, no audit (ADR 014).
	DryRun bool
}

type DelegationChangeResult struct {
	TenantID     string     `json:"tenant_id"`
	Issuer       string     `json:"issuer"`
	Audience     string     `json:"audience,omitempty"`
	TokenID      string     `json:"token_id,omitempty"`
	Status       string     `json:"status"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	MinimumIAT   time.Time  `json:"minimum_iat,omitempty"`
	Generation   int64      `json:"generation,omitempty"`
	KeyID        string     `json:"key_id,omitempty"`
	KeyExpiresAt *time.Time `json:"key_expires_at,omitempty"`
	Replayed     bool       `json:"replayed"`
	// Revocations are the access revocations the change recorded (ADR 006
	// wave 5): pending until the standby holds them.
	Revocations []AccessRevocation `json:"revocations,omitempty"`
}

// trustPolicy is a stored trust without its keys. Its fingerprint over a key
// set is the one delegatedidentity computes for the same configuration.
type trustPolicy struct {
	tenant, issuer, audience string
	scopes                   []string
	ttl                      time.Duration
}

func policyOf(t *delegatedidentity.Trust) trustPolicy {
	return trustPolicy{tenant: t.TenantID, issuer: t.Issuer, audience: t.Audience, scopes: append([]string{}, t.AllowedScopes...), ttl: t.MaxTTL}
}

func (p trustPolicy) trust(keys map[string]ed25519.PublicKey) delegatedidentity.Trust {
	return delegatedidentity.Trust{Issuer: p.issuer, Audience: p.audience, TenantID: p.tenant, Keys: keys, AllowedScopes: p.scopes, MaxTTL: p.ttl}
}

func (p trustPolicy) fingerprint(keys map[string]ed25519.PublicKey) ([]byte, error) {
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{p.trust(keys)}})
	if err != nil {
		return nil, err
	}
	f, _ := v.TrustFingerprint(p.issuer, p.audience)
	return f[:], nil
}

func (s *Store) ChangeDelegationAuthority(ctx context.Context, in DelegationChange) (DelegationChangeResult, error) {
	var out DelegationChangeResult
	if !validKey(in.OperationID) || !validOrganizationText(in.Actor, 100) || !validRegisteredIdentity(in.TenantID) || !validRegisteredIdentity(in.Issuer) {
		return out, ErrInput
	}
	keyChange := in.Action == "add-key" || in.Action == "retire-key"
	if !keyChange && (in.KeyID != "" || in.PublicKey != nil || in.Overlap != 0) {
		return out, ErrInput
	}
	var fingerprint [32]byte
	switch in.Action {
	case "install", "rotate":
		if in.Trust == nil || in.TokenID != "" || in.Trust.TenantID != in.TenantID || in.Trust.Issuer != in.Issuer || in.Trust.Audience != in.Audience {
			return out, ErrInput
		}
		v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{*in.Trust}})
		if err != nil {
			return out, ErrInput
		}
		fingerprint, _ = v.TrustFingerprint(in.Issuer, in.Audience)
	case "revoke-trust":
		if in.Trust != nil || in.TokenID != "" || !validRegisteredIdentity(in.Audience) {
			return out, ErrInput
		}
	case "revoke-token":
		if in.Trust != nil || in.Audience != "" || !validRegisteredIdentity(in.TokenID) {
			return out, ErrInput
		}
	case "add-key":
		if in.Trust != nil || in.TokenID != "" || !validRegisteredIdentity(in.Audience) || !validRegisteredIdentity(in.KeyID) || len(in.PublicKey) != ed25519.PublicKeySize || in.Overlap != 0 {
			return out, ErrInput
		}
	case "retire-key":
		if in.Trust != nil || in.TokenID != "" || !validRegisteredIdentity(in.Audience) || !validRegisteredIdentity(in.KeyID) || in.PublicKey != nil || in.Overlap < 0 || in.Overlap > MaxKeyOverlap {
			return out, ErrInput
		}
	default:
		return out, ErrInput
	}
	// Hash only the validated public configuration identity, not pointer/map
	// representation, so configuration ordering cannot change retry semantics.
	var hash [32]byte
	var err error
	if keyChange {
		hash, err = requestHash(struct {
			Actor, Action, Tenant, Issuer, Audience, Key, PublicKey string
			Overlap                                                 int64
		}{in.Actor, in.Action, in.TenantID, in.Issuer, in.Audience, in.KeyID, base64.StdEncoding.EncodeToString(in.PublicKey), int64(in.Overlap)})
	} else {
		hash, err = requestHash(struct{ Actor, Action, Tenant, Issuer, Audience, Token, Fingerprint string }{
			in.Actor, in.Action, in.TenantID, in.Issuer, in.Audience, in.TokenID, hex.EncodeToString(fingerprint[:]),
		})
	}
	if err != nil {
		return out, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "delegation-admin/"+in.OperationID); err != nil {
		return out, err
	}
	var prior, response []byte
	err = tx.QueryRow(ctx, "SELECT request_hash,response FROM delegation_admin_receipts WHERE operation_id=$1", in.OperationID).Scan(&prior, &response)
	if err == nil {
		if !bytes.Equal(prior, hash[:]) {
			return out, ErrConflict
		}
		if err = json.Unmarshal(response, &out); err != nil {
			return DelegationChangeResult{}, err
		}
		// A replay says what holds now of the revocations it recorded.
		for i := range out.Revocations {
			if err = tx.QueryRow(ctx, `SELECT state,confirmed_at FROM access_revocations WHERE id=$1`, out.Revocations[i].ID).
				Scan(&out.Revocations[i].State, &out.Revocations[i].ConfirmedAt); err != nil {
				return DelegationChangeResult{}, err
			}
		}
		out.Replayed = true
		return out, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	var orgStatus string
	err = tx.QueryRow(ctx, "SELECT status FROM organizations WHERE id=$1 FOR UPDATE", in.TenantID).Scan(&orgStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if (in.Action == "install" || in.Action == "rotate" || in.Action == "add-key") && orgStatus != "active" {
		return out, ErrForbidden
	}
	if in.Action == "install" {
		// The verifier maps an issuer and audience to one organization.
		var taken bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM delegation_trusts WHERE issuer=$1 AND audience=$2 AND tenant_id<>$3)", in.Issuer, in.Audience, in.TenantID).Scan(&taken); err != nil {
			return out, err
		}
		if taken {
			return out, ErrConflict
		}
		if _, err = tx.Exec(ctx, "INSERT INTO delegation_issuers(tenant_id,issuer) VALUES($1,$2) ON CONFLICT DO NOTHING", in.TenantID, in.Issuer); err != nil {
			return out, err
		}
	}
	var issuer string
	err = tx.QueryRow(ctx, "SELECT issuer FROM delegation_issuers WHERE tenant_id=$1 AND issuer=$2 FOR UPDATE", in.TenantID, in.Issuer).Scan(&issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out = DelegationChangeResult{TenantID: in.TenantID, Issuer: in.Issuer, Audience: in.Audience, TokenID: in.TokenID, KeyID: in.KeyID}
	changed := false
	if in.Action == "revoke-token" {
		tag, err := tx.Exec(ctx, "INSERT INTO delegation_revocations(tenant_id,issuer,token_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", in.TenantID, in.Issuer, in.TokenID)
		if err != nil {
			return out, err
		}
		changed = tag.RowsAffected() == 1
		out.Status = "revoked"
	} else {
		var current []byte
		err = tx.QueryRow(ctx, `SELECT fingerprint,status,minimum_iat,generation FROM delegation_trusts
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 FOR UPDATE`, in.TenantID, in.Issuer, in.Audience).Scan(&current, &out.Status, &out.MinimumIAT, &out.Generation)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		if exists {
			if current, err = settleKeys(ctx, tx, in.TenantID, in.Issuer, in.Audience, current); err != nil {
				return out, err
			}
		}
		switch in.Action {
		case "install":
			if exists && (out.Status != "active" || !bytes.Equal(current, fingerprint[:])) {
				return out, ErrConflict
			}
			if !exists {
				out.MinimumIAT, out.Generation, err = installTrust(ctx, tx, in.Trust, fingerprint[:])
				if err != nil {
					return out, err
				}
				out.Status = "active"
				changed = true
			}
			current = fingerprint[:]
		case "rotate":
			if !exists {
				return out, ErrNotFound
			}
			policy := policyOf(in.Trust)
			if err = replaceKeys(ctx, tx, policy, in.Trust.Keys); err != nil {
				return out, err
			}
			err = tx.QueryRow(ctx, `UPDATE delegation_trusts SET fingerprint=$4,status='active',
                    minimum_iat=greatest(minimum_iat,date_trunc('second',clock_timestamp()))+interval '1 second',
                    generation=generation+1,allowed_scopes=$5,max_ttl_nanoseconds=$6,updated_at=clock_timestamp()
                    WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 RETURNING minimum_iat,generation`, in.TenantID, in.Issuer, in.Audience, fingerprint[:], policy.scopes, int64(policy.ttl)).Scan(&out.MinimumIAT, &out.Generation)
			if err != nil {
				return out, err
			}
			current = fingerprint[:]
			out.Status = "active"
			changed = true
		case "revoke-trust":
			if !exists {
				return out, ErrNotFound
			}
			if out.Status != "revoked" {
				if _, err = tx.Exec(ctx, `UPDATE delegation_trusts SET status='revoked',updated_at=clock_timestamp()
                        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3`, in.TenantID, in.Issuer, in.Audience); err != nil {
					return out, err
				}
				out.Status = "revoked"
				changed = true
			}
		case "add-key", "retire-key":
			if !exists {
				return out, ErrNotFound
			}
			policy, err := loadPolicy(ctx, tx, in.TenantID, in.Issuer, in.Audience)
			if err != nil {
				return out, err
			}
			if in.Action == "add-key" {
				if out.Status != "active" {
					return out, ErrTransition
				}
				changed, err = addKey(ctx, tx, policy, in.KeyID, in.PublicKey)
			} else {
				changed, out.KeyExpiresAt, err = retireKey(ctx, tx, policy, in.KeyID, in.Overlap)
			}
			if err != nil {
				return out, err
			}
			if current, err = refreshTrustFingerprint(ctx, tx, policy); err != nil {
				return out, err
			}
		}
		out.Fingerprint = hex.EncodeToString(current)
	}
	if in.DryRun {
		return out, nil
	}
	// The access this change revokes: its record, before the commit. The
	// platform's own revocation: its operator reads it.
	if changed {
		var object []string
		kind := authoritylog.AccessDelegationTrust
		switch in.Action {
		case "revoke-token":
			kind, object = authoritylog.AccessDelegatedToken, []string{in.Issuer, in.TokenID}
		case "revoke-trust":
			object = []string{in.Issuer, in.Audience}
		case "rotate":
			// Tokens of earlier generations, and the keys it retired.
			object = []string{in.Issuer, in.Audience, "generation", strconv.FormatInt(out.Generation, 10)}
		case "retire-key":
			object = []string{in.Issuer, in.Audience, "key", in.KeyID}
			if out.KeyExpiresAt != nil {
				object = append(object, out.KeyExpiresAt.UTC().Format(time.RFC3339Nano))
			}
		}
		if object != nil {
			revoked := s.revocations(tx, "")
			if err = revoked.add(ctx, kind, in.TenantID, [][]string{object}); err != nil {
				return out, err
			}
			out.Revocations = revoked.list
		}
	}
	response, err = json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO delegation_admin_receipts(operation_id,request_hash,response) VALUES($1,$2,$3)", in.OperationID, hash[:], response); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO delegation_audit(id,tenant_id,issuer,audience,token_id,action,actor,operation_id,changed,key_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, newID("audit"), in.TenantID, in.Issuer, in.Audience, in.TokenID, in.Action, in.Actor, in.OperationID, changed, in.KeyID); err != nil {
		return out, err
	}
	return out, commit(ctx, tx)
}

// loadPolicy reads a locked trust's policy. A trust installed before its keys
// were held in PostgreSQL has none: rotate it from its file first.
func loadPolicy(ctx context.Context, tx pgx.Tx, tenant, issuer, audience string) (trustPolicy, error) {
	p := trustPolicy{tenant: tenant, issuer: issuer, audience: audience}
	var ttl *int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(allowed_scopes,'{}'),max_ttl_nanoseconds FROM delegation_trusts
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3`, tenant, issuer, audience).Scan(&p.scopes, &ttl); err != nil {
		return p, err
	}
	if ttl == nil {
		return p, ErrTransition
	}
	p.ttl = time.Duration(*ttl)
	return p, nil
}

func insertKey(ctx context.Context, tx pgx.Tx, p trustPolicy, kid string, key ed25519.PublicKey) error {
	f, err := p.fingerprint(map[string]ed25519.PublicKey{kid: key})
	if err != nil {
		return ErrInput
	}
	_, err = tx.Exec(ctx, `INSERT INTO delegation_keys(tenant_id,issuer,audience,key_id,public_key,fingerprint)
        VALUES($1,$2,$3,$4,$5,$6)`, p.tenant, p.issuer, p.audience, kid, []byte(key), f)
	return err
}

// activeKeys returns the keys of the trust's key set: those not retired. A key
// whose overlap has ended stays in the set until the next change settles it;
// the consuming transaction refuses its tokens from its expiry on.
func activeKeys(ctx context.Context, tx pgx.Tx, tenant, issuer, audience string) (map[string]ed25519.PublicKey, error) {
	rows, err := tx.Query(ctx, `SELECT key_id,public_key FROM delegation_keys
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND retired_at IS NULL`, tenant, issuer, audience)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := map[string]ed25519.PublicKey{}
	for rows.Next() {
		var kid string
		var key []byte
		if err = rows.Scan(&kid, &key); err != nil {
			return nil, err
		}
		keys[kid] = ed25519.PublicKey(key)
	}
	return keys, rows.Err()
}

func refreshTrustFingerprint(ctx context.Context, tx pgx.Tx, p trustPolicy) ([]byte, error) {
	keys, err := activeKeys(ctx, tx, p.tenant, p.issuer, p.audience)
	if err != nil {
		return nil, err
	}
	f, err := p.fingerprint(keys)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE delegation_trusts SET fingerprint=$4,updated_at=clock_timestamp()
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3`, p.tenant, p.issuer, p.audience, f)
	return f, err
}

// settleKeys retires the keys whose overlap has ended, and returns the trust's
// fingerprint after it. A trust whose keys are not held here is left as is.
func settleKeys(ctx context.Context, tx pgx.Tx, tenant, issuer, audience string, current []byte) ([]byte, error) {
	tag, err := tx.Exec(ctx, `UPDATE delegation_keys SET retired_at=clock_timestamp()
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND retired_at IS NULL AND expires_at<=clock_timestamp()`, tenant, issuer, audience)
	if err != nil || tag.RowsAffected() == 0 {
		return current, err
	}
	p, err := loadPolicy(ctx, tx, tenant, issuer, audience)
	if err != nil {
		return nil, err
	}
	return refreshTrustFingerprint(ctx, tx, p)
}

// replaceKeys makes keys the trust's key set, for rotate: a key absent from it
// is retired at once, a new one is added. A key ID keeps its public key for
// good, and a retired key never returns.
func replaceKeys(ctx context.Context, tx pgx.Tx, p trustPolicy, keys map[string]ed25519.PublicKey) error {
	rows, err := tx.Query(ctx, `SELECT key_id,public_key,retired_at IS NOT NULL FROM delegation_keys
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 FOR UPDATE`, p.tenant, p.issuer, p.audience)
	if err != nil {
		return err
	}
	type stored struct {
		key     []byte
		retired bool
	}
	existing := map[string]stored{}
	for rows.Next() {
		var kid string
		var row stored
		if err = rows.Scan(&kid, &row.key, &row.retired); err != nil {
			rows.Close()
			return err
		}
		existing[kid] = row
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for kid, row := range existing {
		wanted, kept := keys[kid]
		switch {
		case kept && (row.retired || !bytes.Equal(row.key, wanted)):
			return ErrConflict
		case !kept && !row.retired:
			if _, err = tx.Exec(ctx, `UPDATE delegation_keys k SET retired_at=c.now,expires_at=least(coalesce(k.expires_at,c.now),c.now)
                FROM (SELECT clock_timestamp() AS now) c
                WHERE k.tenant_id=$1 AND k.issuer=$2 AND k.audience=$3 AND k.key_id=$4`, p.tenant, p.issuer, p.audience, kid); err != nil {
				return err
			}
		}
	}
	for kid, key := range keys {
		if _, found := existing[kid]; found {
			// The policy may change with a rotation: so does each key's fingerprint.
			f, err := p.fingerprint(map[string]ed25519.PublicKey{kid: key})
			if err != nil {
				return ErrInput
			}
			if _, err = tx.Exec(ctx, `UPDATE delegation_keys SET fingerprint=$5
                WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4`, p.tenant, p.issuer, p.audience, kid, f); err != nil {
				return err
			}
		} else if err = insertKey(ctx, tx, p, kid, key); err != nil {
			return err
		}
	}
	return nil
}

// addKey adds a key to the trust's key set. Adding the same key again changes
// nothing; another key under a known ID, or a retired key, is refused.
func addKey(ctx context.Context, tx pgx.Tx, p trustPolicy, kid string, key ed25519.PublicKey) (bool, error) {
	var stored []byte
	var retired bool
	err := tx.QueryRow(ctx, `SELECT public_key,retired_at IS NOT NULL FROM delegation_keys
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4 FOR UPDATE`, p.tenant, p.issuer, p.audience, kid).Scan(&stored, &retired)
	if err == nil {
		if retired || !bytes.Equal(stored, key) {
			return false, ErrConflict
		}
		return false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return true, insertKey(ctx, tx, p, kid, key)
}

// retireKey ends a key's validity after overlap; zero retires it at once. An
// earlier end is never pushed back. The trust must keep a key without an end,
// so that retiring keys cannot stop every sign-in: revoke-trust does that.
func retireKey(ctx context.Context, tx pgx.Tx, p trustPolicy, kid string, overlap time.Duration) (bool, *time.Time, error) {
	var expires *time.Time
	var retired bool
	err := tx.QueryRow(ctx, `SELECT expires_at,retired_at IS NOT NULL FROM delegation_keys
        WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4 FOR UPDATE`, p.tenant, p.issuer, p.audience, kid).Scan(&expires, &retired)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, ErrNotFound
	}
	if err != nil || retired {
		return false, expires, err
	}
	var end time.Time
	var other bool
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()+$5::bigint*interval '1 microsecond',
        EXISTS(SELECT 1 FROM delegation_keys WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id<>$4 AND retired_at IS NULL AND expires_at IS NULL)`,
		p.tenant, p.issuer, p.audience, kid, overlap.Microseconds()).Scan(&end, &other); err != nil {
		return false, nil, err
	}
	if !other {
		return false, nil, ErrTransition
	}
	if expires != nil && !expires.After(end) {
		return false, expires, nil
	}
	if overlap == 0 {
		_, err = tx.Exec(ctx, `UPDATE delegation_keys SET expires_at=$5,retired_at=$5
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4`, p.tenant, p.issuer, p.audience, kid, end)
	} else {
		_, err = tx.Exec(ctx, `UPDATE delegation_keys SET expires_at=$5
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4`, p.tenant, p.issuer, p.audience, kid, end)
	}
	return err == nil, &end, err
}

func installTrust(ctx context.Context, tx pgx.Tx, trust *delegatedidentity.Trust, fingerprint []byte) (time.Time, int64, error) {
	var minimum time.Time
	var generation int64
	policy := policyOf(trust)
	err := tx.QueryRow(ctx, `INSERT INTO delegation_trusts(tenant_id,issuer,audience,fingerprint,status,minimum_iat,generation,allowed_scopes,max_ttl_nanoseconds)
		VALUES($1,$2,$3,$4,'active',date_trunc('second',clock_timestamp())+interval '1 second',1,$5,$6)
		RETURNING minimum_iat,generation`, trust.TenantID, trust.Issuer, trust.Audience, fingerprint, policy.scopes, int64(policy.ttl)).Scan(&minimum, &generation)
	if err == nil {
		for kid, key := range trust.Keys {
			if err = insertKey(ctx, tx, policy, kid, key); err != nil {
				break
			}
		}
	}
	return minimum, generation, err
}
