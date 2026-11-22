package reconciliation

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/identity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// readerOf is the organization whose administrators and auditors read a
// revocation, as the revoking route sets it: empty for the platform's own.
func readerOf(kind, organization string) string {
	switch kind {
	case authoritylog.AccessMember, authoritylog.AccessPrincipal, authoritylog.AccessServiceToken, authoritylog.AccessTeam,
		authoritylog.AccessTeamMembership, authoritylog.AccessAssignment, authoritylog.AccessLLMProvider, authoritylog.AccessPersonalVolume:
		return organization
	}
	return ""
}

// Valid reports whether the authority's record has a replayable identity and object shape.
func (r AuthorityRecord) Valid() bool {
	_, known := authoritylog.AccessBearer(r.Kind)
	return known && authoritylog.ValidID(r.ID, "arv_") && authoritylog.ValidAccessObjects(r.Objects)
}

// ReplayRecord applies a validated record atomically with its receipt, and reports whether
// it was missing. Retiring a delegation key also refreshes its trust's fingerprint.
func ReplayRecord(ctx context.Context, tx pgx.Tx, r AuthorityRecord) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_revocations WHERE id=$1)`, r.ID).Scan(&exists); err != nil || exists {
		return false, err
	}
	if err := replayEffect(ctx, tx, r); err != nil {
		return false, err
	}
	state := RevocationPending
	if Confirmable(r.Kind, AccessReceipt{Known: true, OnReplica: r.OnReplica, Degraded: r.Degraded}) {
		state = RevocationConfirmed
	}
	objects, err := json.Marshal(r.Objects)
	if err != nil {
		return false, err
	}
	recorded := r.RecordedAt
	if recorded.IsZero() {
		recorded = time.Now()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO access_revocations(id,tenant_id,organization_id,kind,objects,epoch,seq,state,recorded_at,confirmed_at)
        VALUES($1,nullif($2,''),nullif($3,''),$4,$5,$6,$7,$8,$9,CASE WHEN $8='confirmed' THEN clock_timestamp() END)`,
		r.ID, readerOf(r.Kind, r.Organization), r.Organization, r.Kind, objects, int64(r.Epoch), int64(r.Seq), state, recorded); err != nil {
		return false, err
	}
	return true, nil
}

// replayEffect makes PostgreSQL revoke what r revokes, as the revoking
// route did, in tx. An object PostgreSQL does not know was created in the
// window and lost with it: nothing grants access through it.
func replayEffect(ctx context.Context, tx pgx.Tx, r AuthorityRecord) error {
	org := r.Organization
	exec := func(sql string, args ...any) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}
	tenantScoped := r.Kind != authoritylog.AccessAPIToken && r.Kind != authoritylog.AccessPlatformCredential &&
		r.Kind != authoritylog.AccessMandate && r.Kind != authoritylog.AccessBlanket && r.Kind != authoritylog.AccessOrganization
	if tenantScoped && org == "" {
		return ErrReconciliationRecord
	}
	// As every revoking route does, the replay holds the organizations' rows
	// FOR UPDATE before it revokes: an admission holds its organization's row
	// FOR KEY SHARE, and reads the other rows without a lock (P-07). A blanket
	// revocation holds every organization's row, in their order.
	locks := []string{}
	switch {
	case r.Kind == authoritylog.AccessBlanket:
		locks = nil
	case r.Kind == authoritylog.AccessOrganization:
		for _, o := range r.Objects {
			if len(o) == 1 {
				locks = append(locks, o[0])
			}
		}
	case org != "":
		locks = append(locks, org)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE $1::text[] IS NULL OR id=ANY($1) ORDER BY id FOR UPDATE`, locks); err != nil {
		return err
	}
	if r.Kind == authoritylog.AccessBlanket {
		b, ok := authoritylog.ParseBlanket(r.Objects)
		if !ok {
			return ErrReconciliationRecord
		}
		return replayBlanket(ctx, tx, b.IssuedBefore)
	}
	for _, o := range r.Objects {
		var err error
		switch {
		case r.Kind == authoritylog.AccessMember && len(o) == 1:
			if err = exec(`UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0]); err == nil {
				err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessPrincipal && len(o) == 1:
			if err = exec(`UPDATE principals SET status='disabled' WHERE tenant_id=$1 AND id=$2 AND status<>'disabled'`, org, o[0]); err == nil {
				err = exec(`UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessServiceToken && len(o) == 1:
			// revoked_by names a principal of the organization: the token's
			// issuer stands for the administrator whose revocation was lost.
			err = exec(`UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=issued_by
                WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, org, o[0])
		case r.Kind == authoritylog.AccessTeam && len(o) == 1:
			if err = exec(`UPDATE teams SET status='disabled' WHERE tenant_id=$1 AND id=$2 AND status<>'disabled'`, org, o[0]); err == nil {
				err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND team_id=$2 AND status='active'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessTeamMembership && len(o) == 2:
			err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND team_id=$2 AND principal_id=$3 AND status='active'`, org, o[0], o[1])
		case r.Kind == authoritylog.AccessPersonalVolume && len(r.Objects) == 1 && len(o) == 3:
			// Older snapshots can contain earlier grants. Only the original
			// individual may retain a grant on this volume after promotion.
			err = exec(`UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp()
				WHERE tenant_id=$1 AND agent_id=$2 AND principal_id IS DISTINCT FROM $3 AND status='active'`, org, o[0], o[2])
		case r.Kind == authoritylog.AccessAssignment && len(o) == 1:
			err = exec(`UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='active'`, org, o[0])
		case r.Kind == authoritylog.AccessOrganization && len(o) == 1:
			err = exec(`UPDATE organizations SET status='disabled',policy_version=policy_version+1 WHERE id=$1 AND status<>'disabled'`, o[0])
		case r.Kind == authoritylog.AccessAPIToken && len(o) == 1:
			err = exec(`UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, o[0])
		case r.Kind == authoritylog.AccessPlatformCredential && len(o) == 1:
			err = exec(`UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, o[0])
		case r.Kind == authoritylog.AccessMandate && len(o) == 1:
			err = exec(`UPDATE mandates SET valid=false WHERE id=$1 AND valid`, o[0])
		case r.Kind == authoritylog.AccessLLMProvider && (len(o) == 1 || len(o) == 3 && o[1] == "generation"):
			// A disabled provider, or a rotated one: the database still
			// holding the revoked generation's credential disables the
			// provider, which cannot be enabled again. Its administrator
			// creates it again.
			generation := int64(1<<63 - 1)
			if len(o) == 3 {
				if generation, err = strconv.ParseInt(o[2], 10, 64); err != nil {
					return ErrReconciliationRecord
				}
			}
			var tag int64
			if err = tx.QueryRow(ctx, `WITH d AS (UPDATE llm_providers SET status='disabled',disabled_at=clock_timestamp(),secret_ciphertext='\x'::bytea
                WHERE tenant_id=$1 AND id=$2 AND status<>'disabled' AND secret_generation<=$3 RETURNING 1) SELECT count(*) FROM d`, org, o[0], generation).Scan(&tag); err == nil && tag > 0 {
				err = exec(`UPDATE llm_model_aliases SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND provider_id=$2 AND status='active'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessDelegatedToken && len(o) == 2:
			if err = exec(`INSERT INTO delegation_issuers(tenant_id,issuer) SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM organizations WHERE id=$1)
                ON CONFLICT DO NOTHING`, org, o[0]); err == nil {
				err = exec(`INSERT INTO delegation_revocations(tenant_id,issuer,token_id)
                    SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM delegation_issuers WHERE tenant_id=$1 AND issuer=$2) ON CONFLICT DO NOTHING`, org, o[0], o[1])
			}
		case r.Kind == authoritylog.AccessDelegationTrust:
			err = replayTrust(ctx, tx, org, o)
		default:
			return ErrReconciliationRecord
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// replayTrust replays a delegation trust's revocation: the trust revoked;
// a rotation, whose new keys the database lost, revokes the trust while it
// is of an earlier generation, until the operator rotates it again; a
// retired key's end.
func replayTrust(ctx context.Context, tx pgx.Tx, org string, o []string) error {
	switch {
	case len(o) == 2:
		_, err := tx.Exec(ctx, `UPDATE delegation_trusts SET status='revoked',updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND status<>'revoked'`, org, o[0], o[1])
		return err
	case len(o) == 4 && o[2] == "generation":
		generation, err := strconv.ParseInt(o[3], 10, 64)
		if err != nil {
			return ErrReconciliationRecord
		}
		_, err = tx.Exec(ctx, `UPDATE delegation_trusts SET status='revoked',updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND status<>'revoked' AND generation<$4`, org, o[0], o[1], generation)
		return err
	case (len(o) == 4 || len(o) == 5) && o[2] == "key":
		var end any = nil
		if len(o) == 5 {
			t, err := time.Parse(time.RFC3339Nano, o[4])
			if err != nil {
				return ErrReconciliationRecord
			}
			end = t
		}
		tag, err := tx.Exec(ctx, `UPDATE delegation_keys SET expires_at=coalesce($5::timestamptz,clock_timestamp())
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4 AND retired_at IS NULL
              AND (expires_at IS NULL OR expires_at>coalesce($5::timestamptz,clock_timestamp()))`, org, o[0], o[1], o[3], end)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		// A key whose end has passed leaves the trust's key set now.
		if _, err = identity.SettleKeys(ctx, tx, org, o[0], o[1], nil); errors.Is(err, persistence.ErrTransition) {
			err = nil
		}
		return err
	}
	return ErrReconciliationRecord
}

// replayBlanket revokes every bearer token issued before the failover, and
// moves every delegation trust's minimum_iat past it: a delegated token's iat
// is a whole second, so the second of the failover is refused too.
func replayBlanket(ctx context.Context, tx pgx.Tx, failover time.Time) error {
	for _, sql := range []string{
		`UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=issued_by WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE applications SET minimum_iat=greatest(minimum_iat,date_trunc('second',$1::timestamptz)+interval '1 second')`,
		`UPDATE delegation_trusts SET minimum_iat=date_trunc('second',$1::timestamptz)+interval '1 second',updated_at=clock_timestamp()
            WHERE minimum_iat<date_trunc('second',$1::timestamptz)+interval '1 second'`,
	} {
		if _, err := tx.Exec(ctx, sql, failover); err != nil {
			return err
		}
	}
	return nil
}
