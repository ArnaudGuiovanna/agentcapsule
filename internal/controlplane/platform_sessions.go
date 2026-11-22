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

// PlatformSessionChainLifetime bounds a chain of platform sessions (audit
// finding L-01): no session outlives this long after the chain's root, an
// enrollment proof or a credential of bootstrap-platform, was issued. Past
// it, the operator enrolls again on the host (agentcapsule-admin
// issue-enrollment).
const PlatformSessionChainLifetime = 30 * 24 * time.Hour

// platformSessionLifetime is one session's lifetime.
const platformSessionLifetime = 12 * time.Hour

// CreatePlatformSession issues a session to the credential p, or to an
// enrollment proof. The session records its parent. An enrollment proof is
// always consumed; replace_current consumes p. Consuming a credential
// revokes it and every session descended from it. A credential has at most
// one live child otherwise: a second is refused (ErrTransition). The
// session ends at the latest PlatformSessionChainLifetime after its chain
// started; a chain at its end issues no session (ErrExpired).
func (a *Accounts) CreatePlatformSession(ctx context.Context, p Principal, enrollment, key string, in PlatformSessionRequest) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	var proof [32]byte
	if enrollment != "" {
		// A bearer that is no live enrollment proof is refused before the
		// shared lock (audit finding L-02): it neither waits on it nor
		// holds it. The proof is read again, and locked, under it.
		proof = sha256.Sum256([]byte(enrollment))
		p.Kind = "platform"
		err = tx.QueryRow(ctx, `SELECT id,account FROM platform_credentials WHERE token_hash=$1
			AND scopes=ARRAY['platform:enroll'] AND revoked_at IS NULL AND expires_at>clock_timestamp()`, proof[:]).Scan(&p.TokenID, &p.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return APIReceipt{}, ErrAuthentication
		}
		if err != nil {
			return APIReceipt{}, err
		}
	}
	// Stable ordering across issue, rotate and revoke, including self revocation.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610045)"); err != nil {
		return APIReceipt{}, err
	}
	if enrollment != "" {
		err = tx.QueryRow(ctx, `SELECT id,account FROM platform_credentials WHERE token_hash=$1
			AND scopes=ARRAY['platform:enroll'] AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`, proof[:]).Scan(&p.TokenID, &p.ID)
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
		var started time.Time
		var open bool
		err := tx.QueryRow(ctx, `SELECT chain_started_at,chain_started_at+$2::bigint*interval '1 microsecond'>clock_timestamp()+interval '1 minute'
            FROM platform_credentials WHERE id=$1`, p.TokenID, PlatformSessionChainLifetime.Microseconds()).Scan(&started, &open)
		if err != nil {
			return 0, nil, err
		}
		if !open {
			return 0, nil, ErrExpired
		}
		actor := WithOperator(ctx, p.ID)
		records := a.store.revocations(tx, "")
		if enrollment != "" || in.ReplaceCurrent {
			// Revoked before the new session exists: the cascade never
			// reaches it.
			if err = revokeSession(actor, tx, records, p.TokenID); err != nil {
				return 0, nil, err
			}
		} else {
			var live bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_credentials WHERE parent_id=$1
                AND revoked_at IS NULL AND expires_at>clock_timestamp())`, p.TokenID).Scan(&live); err != nil {
				return 0, nil, err
			}
			if live {
				return 0, nil, ErrTransition
			}
		}
		session := OperatorCredential{Kind: "platform", Account: p.ID, Status: "active"}
		err = tx.QueryRow(ctx, `INSERT INTO platform_credentials(id,account,token_hash,scopes,expires_at,parent_id,chain_started_at)
		  VALUES($1,$2,$3,ARRAY['platform:admin'],least(clock_timestamp()+$5::bigint*interval '1 microsecond',$6::timestamptz+$7::bigint*interval '1 microsecond'),$4,$6)
		  ON CONFLICT(token_hash) DO NOTHING RETURNING id,expires_at`, newID("ptok"), p.ID, hash, p.TokenID,
			platformSessionLifetime.Microseconds(), started, PlatformSessionChainLifetime.Microseconds()).Scan(&session.ID, &session.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrTransition
		}
		if err != nil {
			return 0, nil, err
		}
		if err = auditPlatform(actor, tx, "platform_credential.created", session.ID, true); err != nil {
			return 0, nil, err
		}
		body, err := records.body(session)
		return 201, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, out, commit(ctx, tx))
}

// revokeSession revokes the credential id and every session descended from
// it, also below a session revoked before; each is audited and recorded.
func revokeSession(ctx context.Context, tx pgx.Tx, records *revocations, id string) error {
	ids, err := revokePlatformChain(ctx, tx, id)
	if err != nil {
		return err
	}
	for _, revoked := range ids {
		if err = auditPlatform(ctx, tx, "platform_credential.revoked", revoked, true); err != nil {
			return err
		}
	}
	return records.add(ctx, authoritylog.AccessPlatformCredential, "", objects(ids))
}

// revokePlatformChain revokes the platform credential id and its live
// descendants, and returns those it revoked. A parent is older than its
// children, and never changes: the chain has no cycle.
func revokePlatformChain(ctx context.Context, tx pgx.Tx, id string) ([]string, error) {
	return collect(tx.Query(ctx, `WITH RECURSIVE chain(id) AS (
            SELECT id FROM platform_credentials WHERE id=$1
            UNION ALL SELECT c.id FROM platform_credentials c JOIN chain ON c.parent_id=chain.id)
        UPDATE platform_credentials c SET revoked_at=clock_timestamp() FROM chain
         WHERE c.id=chain.id AND c.revoked_at IS NULL
        RETURNING c.id`, id))
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
