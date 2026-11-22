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
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/identity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

// MaxKeyOverlap bounds how long a retired delegation key keeps signing valid
// tokens. A longer overlap is an unretired key, and is refused.
const MaxKeyOverlap = 30 * 24 * time.Hour

type DelegationChange = identity.DelegationChange

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
	state, changed, err := identity.ApplyTrustChange(ctx, tx, in, fingerprint)
	out.Status, out.Fingerprint, out.MinimumIAT, out.Generation, out.KeyExpiresAt = state.Status, state.Fingerprint, state.MinimumIAT, state.Generation, state.KeyExpiresAt
	if err != nil {
		return out, err
	}
	if in.DryRun {
		return out, nil
	}
	// The access this change revokes: its record, recorded after the commit. The
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
