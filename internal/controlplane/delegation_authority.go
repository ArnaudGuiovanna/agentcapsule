package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

// DelegationChange is trusted operator input, never constructed from a JWT.
// Install is idempotent for an already-active identical trust. Rotate explicitly
// replaces/reactivates a trust, including the same fingerprint, and rejects
// tokens from previous signed generations. The iat cutoff is freshness policy,
// not proof of when a token was physically signed. OperationID stays stable on retries.
type DelegationChange struct {
	OperationID string
	Actor       string
	Action      string // install, rotate, revoke-trust, revoke-token
	TenantID    string
	Issuer      string
	Audience    string
	TokenID     string
	Trust       *delegatedidentity.Trust // install/rotate only, from operator config
}

type DelegationChangeResult struct {
	TenantID    string    `json:"tenant_id"`
	Issuer      string    `json:"issuer"`
	Audience    string    `json:"audience,omitempty"`
	TokenID     string    `json:"token_id,omitempty"`
	Status      string    `json:"status"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	MinimumIAT  time.Time `json:"minimum_iat,omitempty"`
	Generation  int64     `json:"generation,omitempty"`
	Replayed    bool      `json:"replayed"`
}

func (s *Store) ChangeDelegationAuthority(ctx context.Context, in DelegationChange) (DelegationChangeResult, error) {
	var out DelegationChangeResult
	if !validKey(in.OperationID) || !validOrganizationText(in.Actor, 100) || !validRegisteredIdentity(in.TenantID) || !validRegisteredIdentity(in.Issuer) {
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
	default:
		return out, ErrInput
	}
	// Hash only the validated public configuration identity, not pointer/map
	// representation, so configuration ordering cannot change retry semantics.
	hash, err := requestHash(struct{ Actor, Action, Tenant, Issuer, Audience, Token, Fingerprint string }{
		in.Actor, in.Action, in.TenantID, in.Issuer, in.Audience, in.TokenID, hex.EncodeToString(fingerprint[:]),
	})
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
	if (in.Action == "install" || in.Action == "rotate") && orgStatus != "active" {
		return out, ErrForbidden
	}
	if in.Action == "install" {
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
	out = DelegationChangeResult{TenantID: in.TenantID, Issuer: in.Issuer, Audience: in.Audience, TokenID: in.TokenID}
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
		switch in.Action {
		case "install":
			if exists && (out.Status != "active" || !bytes.Equal(current, fingerprint[:])) {
				return out, ErrConflict
			}
			if !exists {
				err = tx.QueryRow(ctx, `INSERT INTO delegation_trusts(tenant_id,issuer,audience,fingerprint,status,minimum_iat,generation)
                    VALUES($1,$2,$3,$4,'active',date_trunc('second',clock_timestamp())+interval '1 second',1)
                    RETURNING minimum_iat,generation`, in.TenantID, in.Issuer, in.Audience, fingerprint[:]).Scan(&out.MinimumIAT, &out.Generation)
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
			err = tx.QueryRow(ctx, `UPDATE delegation_trusts SET fingerprint=$4,status='active',
                    minimum_iat=greatest(minimum_iat,date_trunc('second',clock_timestamp()))+interval '1 second',
                    generation=generation+1,updated_at=clock_timestamp()
                    WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 RETURNING minimum_iat,generation`, in.TenantID, in.Issuer, in.Audience, fingerprint[:]).Scan(&out.MinimumIAT, &out.Generation)
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
		}
		out.Fingerprint = hex.EncodeToString(current)
	}
	response, err = json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO delegation_admin_receipts(operation_id,request_hash,response) VALUES($1,$2,$3)", in.OperationID, hash[:], response); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO delegation_audit(id,tenant_id,issuer,audience,token_id,action,actor,operation_id,changed)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, newID("audit"), in.TenantID, in.Issuer, in.Audience, in.TokenID, in.Action, in.Actor, in.OperationID, changed); err != nil {
		return out, err
	}
	return out, commit(ctx, tx)
}
