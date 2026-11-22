package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/jackc/pgx/v5"
)

// The first component is an internally generated application ID or a fixed
// domain. The second is an immutable OIDC subject or a physical volume ID.
func applicationStableID(prefix, domain, value string) string {
	digest := sha256.Sum256([]byte(domain + "\x00" + value))
	return prefix + "_" + hex.EncodeToString(digest[:16])
}

func (s *Store) recordPersonalVolume(ctx context.Context, tx pgx.Tx, tenant string, hold []string) error {
	journal := s.revocations(tx, tenant)
	// The authority rejects reuse of an ID for any other record. Even if
	// PostgreSQL loses the commit, another member cannot consume this disk.
	record := AccessRecord{ID: applicationStableID("arv", "personal_volume", hold[1]), Kind: authoritylog.AccessPersonalVolume, Organization: tenant, Objects: [][]string{hold}}
	if err := journal.claim(ctx, record); err != nil {
		return err
	}
	if journal.list[0].State != RevocationConfirmed {
		return ErrAuthorityUnavailable
	}
	return nil
}

// SyncPersonalVolumeHolds runs before the API starts serving. A same-host
// point-in-time restore does not advance the authority epoch. Replay its
// missing holds, then journal reservations created before external tracking
// became available. A normal restart has no updates to make.
func (s *Store) SyncPersonalVolumeHolds(ctx context.Context, source interface {
	AuthorityRecords(context.Context) ([]AuthorityRecord, error)
}) error {
	records, err := source.AuthorityRecords(ctx)
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, "SELECT id FROM access_revocations WHERE kind='personal_volume'")
	if err != nil {
		return err
	}
	known, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	local := make(map[string]bool, len(known))
	for _, id := range known {
		local[id] = true
	}
	for _, r := range records {
		if r.Kind == authoritylog.AccessPersonalVolume && !local[r.ID] {
			if _, err = s.replayRecord(ctx, r); err != nil {
				return err
			}
		}
	}
	rows, err = s.pool.Query(ctx, `SELECT r.tenant_id,r.agent_id,e.volume_id,r.principal_id
		FROM app_personal_reservations r JOIN store_enrollments e ON e.agent_id=r.agent_id
		WHERE NOT EXISTS(SELECT 1 FROM personal_volume_holds h WHERE (h.tenant_id,h.agent_id)=(r.tenant_id,r.agent_id))`)
	if err != nil {
		return err
	}
	type existing struct{ Tenant, Agent, Volume, Member string }
	legacy, err := pgx.CollectRows(rows, pgx.RowToStructByPos[existing])
	if err != nil {
		return err
	}
	for _, r := range legacy {
		tx, err := s.begin(ctx)
		if err != nil {
			return err
		}
		if err = s.recordPersonalVolume(ctx, tx, r.Tenant, []string{r.Agent, r.Volume, r.Member}); err != nil {
			rollback(tx)
			return err
		}
		if err = commit(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
