package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/jackc/pgx/v5"
)

// Enrollments and sessions share the platform credential revocation journal.
// Only the exchange endpoint accepts an enrollment's prefix and scope.
func (s *Store) IssuePlatformEnrollment(ctx context.Context, account, proof string, lifetime time.Duration) error {
	if !validOrganizationText(account, 100) || len(proof) != 48 || proof[:5] != "acpe_" ||
		!validPlatformSecret("acpp_"+proof[5:]) || lifetime < time.Minute || lifetime > time.Hour {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	hash := sha256.Sum256([]byte(proof))
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO platform_credentials(id,account,token_hash,scopes,expires_at)
		VALUES ($1,$2,$3,ARRAY['platform:enroll'],clock_timestamp()+$4::bigint*interval '1 second')
		ON CONFLICT(token_hash) DO NOTHING RETURNING id`, newID("ptok"), account, hash[:], int64(lifetime.Seconds())).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM platform_credentials WHERE token_hash=$1 AND account=$2
			AND revoked_at IS NULL AND expires_at>clock_timestamp() AND scopes=ARRAY['platform:enroll']`, hash[:], account).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
	} else if err == nil {
		err = auditPlatform(ctx, tx, "platform_credential.created", id, true)
	}
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}

type PlatformSessionRequest struct {
	// The CLI persists a randomly generated bearer before sending its SHA-256.
	// A lost HTTP response can be recovered by authenticating with the new bearer.
	TokenSHA256    string `json:"token_sha256"`
	ReplaceCurrent bool   `json:"replace_current,omitempty"`
}

func (a *Accounts) CreatePlatformSession(ctx context.Context, p Principal, enrollment, key string, in PlatformSessionRequest) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	// Stable ordering across issue, rotate and revoke, including self revocation.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610045)"); err != nil {
		return APIReceipt{}, err
	}
	if enrollment != "" {
		hash := sha256.Sum256([]byte(enrollment))
		p.Kind = "platform"
		err = tx.QueryRow(ctx, `SELECT id,account FROM platform_credentials WHERE token_hash=$1
			AND scopes=ARRAY['platform:enroll'] AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`, hash[:]).Scan(&p.TokenID, &p.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return APIReceipt{}, ErrAuthentication
		}
	} else {
		err = authorizePlatform(ctx, tx, p)
	}
	if err != nil {
		return APIReceipt{}, err
	}
	hash, err := hex.DecodeString(in.TokenSHA256)
	if err != nil || len(hash) != sha256.Size {
		return APIReceipt{}, ErrInput
	}
	out, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/platform/sessions/"+p.TokenID, key), in, func() (int, any, error) {
		session := OperatorCredential{Kind: "platform", Account: p.ID, Status: "active"}
		err := tx.QueryRow(ctx, `INSERT INTO platform_credentials(id,account,token_hash,scopes,expires_at)
		  VALUES($1,$2,$3,ARRAY['platform:admin'],clock_timestamp()+interval '12 hours')
		  ON CONFLICT(token_hash) DO NOTHING RETURNING id,expires_at`, newID("ptok"), p.ID, hash).Scan(&session.ID, &session.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrTransition
		}
		if err != nil {
			return 0, nil, err
		}
		actor := WithOperator(ctx, p.ID)
		if err = auditPlatform(actor, tx, "platform_credential.created", session.ID, true); err != nil {
			return 0, nil, err
		}
		records := a.store.revocations(tx, "")
		if enrollment != "" || in.ReplaceCurrent {
			if err = revokeSession(actor, tx, records, p.TokenID); err != nil {
				return 0, nil, err
			}
		}
		body, err := records.body(session)
		return 201, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, out, commit(ctx, tx))
}

func revokeSession(ctx context.Context, tx pgx.Tx, records *revocations, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	if err = auditPlatform(ctx, tx, "platform_credential.revoked", id, true); err != nil {
		return err
	}
	return records.add(ctx, authoritylog.AccessPlatformCredential, "", [][]string{{id}})
}

func (a *Accounts) RevokePlatformSession(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610045)"); err != nil {
		return APIReceipt{}, err
	}
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	out, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/platform/sessions/"+id+"/revoke", key), struct{}{}, func() (int, any, error) {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM platform_credentials WHERE id=$1)", id).Scan(&exists); err != nil {
			return 0, nil, err
		}
		if !exists {
			return 0, nil, ErrNotFound
		}
		records := a.store.revocations(tx, "")
		if err := revokeSession(WithOperator(ctx, p.ID), tx, records, id); err != nil {
			return 0, nil, err
		}
		body, err := records.body(map[string]string{"id": id, "status": "revoked"})
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, out, commit(ctx, tx))
}

func (s *Store) PlatformSession(ctx context.Context, p Principal) (OperatorCredential, error) {
	var out OperatorCredential
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return out, err
	}
	out.Kind, out.ID, out.Account, out.Status = "platform", p.TokenID, p.ID, "active"
	if err = tx.QueryRow(ctx, "SELECT expires_at FROM platform_credentials WHERE id=$1", p.TokenID).Scan(&out.ExpiresAt); err != nil {
		return out, err
	}
	return out, commit(ctx, tx)
}
