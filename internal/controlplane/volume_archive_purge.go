package controlplane

import (
	"context"
)

// ArchiveBinding names an archive and the volume it holds: the agent and the
// volume of its manifest, or of its record.
type ArchiveBinding struct {
	ID, AgentID, VolumeID string
}

// PurgeableVolumeArchives lists the archives whose volume key is destroyed
// (ADR 018): their agent was deleted, and store_removals records that its key
// was revoked before its volume was removed. Their ciphertext no longer opens
// anywhere. It returns the archives recorded on host and not yet recorded
// removed, and those of found (the host's archive root, read by manifest) of
// such a volume, by archive ID.
func (s *Store) PurgeableVolumeArchives(ctx context.Context, host string, found []ArchiveBinding) ([]ArchiveBinding, error) {
	if host == "" || len(found) > 100000 {
		return nil, ErrInput
	}
	ids, agents, volumes := make([]string, len(found)), make([]string, len(found)), make([]string, len(found))
	for i, f := range found {
		if !archiveIDPattern.MatchString(f.ID) || f.AgentID == "" || f.VolumeID == "" {
			return nil, ErrInput
		}
		ids[i], agents[i], volumes[i] = f.ID, f.AgentID, f.VolumeID
	}
	rows, err := s.pool.Query(ctx, `SELECT v.archive_id,v.agent_id,v.volume_id FROM volume_archives v
          JOIN store_removals r ON r.agent_id=v.agent_id AND r.volume_id=v.volume_id
          WHERE v.host_id=$1 AND v.removed_at IS NULL
        UNION
        SELECT f.id,f.agent_id,f.volume_id FROM unnest($2::text[],$3::text[],$4::text[]) AS f(id,agent_id,volume_id)
          JOIN store_removals r ON r.agent_id=f.agent_id AND r.volume_id=f.volume_id
        ORDER BY 1,2,3`, host, ids, agents, volumes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ArchiveBinding, 0)
	for rows.Next() {
		var b ArchiveBinding
		if err = rows.Scan(&b.ID, &b.AgentID, &b.VolumeID); err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// PurgedVolumeArchive records that the worker deleted an archive whose volume
// key is destroyed. size is the size of the manifest the worker found on disk,
// or zero when the archive was not there. A capture never settled is then
// adopted, as of its start, if its archive was on disk, and forgotten
// otherwise. An unrecorded archive (taken on demand) and an archive of a key
// not destroyed are left as they are. Repeating it keeps the first time.
func (s *Store) PurgedVolumeArchive(ctx context.Context, archiveID string, size int64) error {
	if !archiveIDPattern.MatchString(archiveID) || size < 0 {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	const destroyed = ` AND EXISTS(SELECT 1 FROM store_removals r
          WHERE r.agent_id=volume_archives.agent_id AND r.volume_id=volume_archives.volume_id)`
	if size > 0 {
		_, err = tx.Exec(ctx, `UPDATE volume_archives SET size=coalesce(size,$2),captured_at=coalesce(captured_at,started_at),
            removed_at=coalesce(removed_at,clock_timestamp()) WHERE archive_id=$1`+destroyed, archiveID, size)
	} else {
		if _, err = tx.Exec(ctx, `DELETE FROM volume_archives WHERE archive_id=$1 AND captured_at IS NULL`+destroyed, archiveID); err == nil {
			_, err = tx.Exec(ctx, `UPDATE volume_archives SET removed_at=coalesce(removed_at,clock_timestamp())
                WHERE archive_id=$1 AND captured_at IS NOT NULL`+destroyed, archiveID)
		}
	}
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}
