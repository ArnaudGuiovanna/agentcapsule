package controlplane

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrArchiveNotDue reports that an agent no longer needs an archive: another
// capture recorded one, its VM changed state, or it is no longer LIVE.
var ErrArchiveNotDue = errors.New("agent volume archive is not due")

// ErrArchiveRecord refuses to record another size for a published archive.
var ErrArchiveRecord = errors.New("volume archive record conflicts with the published archive")

var archiveIDPattern = regexp.MustCompile(`^arc_[0-9a-f]{32}$`)

// VolumeArchiveCandidate is an agent of a host that is due for a volume
// archive (REC-02, ADR 004).
type VolumeArchiveCandidate struct {
	AgentID string
	// Running is true when the agent's VM runs: its capture stops the VM.
	Running bool
	// Last is the agent's newest archive kept on the host; nil when none.
	Last *time.Time
}

// VolumeArchive is the record of one capture: metadata only.
type VolumeArchive struct {
	ID, AgentID, HostID, VolumeID string
	Incarnation                   uint64
	StartedAt                     time.Time
	// CapturedAt is nil while the archive is not known to be published.
	CapturedAt *time.Time
	Size       int64
	RemovedAt  *time.Time
}

// ArchivePolicy says when an agent is due. A sleeping agent is due once its
// newest archive is Every-SleepWindow old, or at once when it has none. A
// running agent is due once its newest archive, or its initialization when it
// has none, is Every old: its capture stops it. Every is thus the bound on the
// age of the newest archive, give or take one pass and one capture.
type ArchivePolicy struct {
	Every, SleepWindow time.Duration
}

func (p ArchivePolicy) valid() bool {
	return p.Every >= time.Microsecond && p.SleepWindow >= 0 && p.SleepWindow < p.Every
}

// archiveCandidates selects the LIVE agents of a host ($2) with a ready,
// initialized volume, due for an archive at $1 (dbNow), under the policy ($3
// Every, $4 SleepWindow, in microseconds). Only cleanly stopped or ordinarily
// running VMs qualify: a capture refuses an unclean stop, and STARTING or
// STOPPING are transient. Sleeping agents come first, then the oldest
// archive. $6 restricts it to one agent.
const archiveCandidates = `SELECT a.id, p.state='RUNNING', l.captured_at
        FROM agents a JOIN agent_placements p ON p.agent_id=a.id
        JOIN store_enrollments e ON e.agent_id=a.id
        JOIN store_initializations i ON i.agent_id=e.agent_id AND i.volume_id=e.volume_id AND i.incarnation=e.incarnation
        LEFT JOIN LATERAL (SELECT max(v.captured_at) AS captured_at FROM volume_archives v
          WHERE v.agent_id=a.id AND v.host_id=p.host_id AND v.captured_at IS NOT NULL AND v.removed_at IS NULL) l ON true
        WHERE p.host_id=$2 AND a.phase='LIVE' AND e.stage='READY' AND ($6::text IS NULL OR a.id=$6::text)
          AND ((p.state='STOPPED' AND NOT p.unclean_stop
                AND (l.captured_at IS NULL OR l.captured_at <= ` + dbNow + ` - ($3::bigint-$4::bigint) * interval '1 microsecond'))
            OR (p.state='RUNNING' AND NOT p.fence_only
                AND coalesce(l.captured_at, i.initialized_at) <= ` + dbNow + ` - $3::bigint * interval '1 microsecond'))
        ORDER BY p.state='RUNNING', coalesce(l.captured_at, CASE WHEN p.state='RUNNING' THEN i.initialized_at END, '-infinity'), a.id
        LIMIT $5`

// DueVolumeArchives lists up to limit agents of host due for an archive at
// now (nil: the database clock): sleeping agents first, oldest archive first.
// It is an observation; BeginVolumeArchive checks again under the agent's lock.
func (s *Store) DueVolumeArchives(ctx context.Context, host string, now *time.Time, policy ArchivePolicy, limit int) ([]VolumeArchiveCandidate, error) {
	if host == "" || !policy.valid() || limit < 1 || limit > 1024 {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, archiveCandidates, nowArg(now), host, policy.Every.Microseconds(), policy.SleepWindow.Microseconds(), limit, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]VolumeArchiveCandidate, 0)
	for rows.Next() {
		var c VolumeArchiveCandidate
		if err = rows.Scan(&c.AgentID, &c.Running, &c.Last); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// BeginVolumeArchive records a capture before it starts, once the agent is
// still due under its lock. The worker calls it under the agent's host
// barrier, after reconciliation, with whether the agent's VM runs; a VM whose
// state disagrees with the database is not captured (ErrArchiveNotDue).
func (s *Store) BeginVolumeArchive(ctx context.Context, host, agentID, archiveID string, running bool, now *time.Time, policy ArchivePolicy) error {
	if host == "" || agentID == "" || !archiveIDPattern.MatchString(archiveID) || !policy.valid() {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return err
	}
	if agents[agentID].Phase != "LIVE" {
		return ErrArchiveNotDue
	}
	var c VolumeArchiveCandidate
	err = tx.QueryRow(ctx, archiveCandidates, nowArg(now), host, policy.Every.Microseconds(), policy.SleepWindow.Microseconds(), 1, agentID).Scan(&c.AgentID, &c.Running, &c.Last)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrArchiveNotDue
	}
	if err != nil {
		return err
	}
	if c.Running != running {
		return ErrArchiveNotDue
	}
	if _, err = tx.Exec(ctx, `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation)
        SELECT $1,e.agent_id,$3,e.volume_id,e.incarnation FROM store_enrollments e WHERE e.agent_id=$2`, archiveID, agentID, host); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// CompleteVolumeArchive records that the archive is published, with its size.
// adopted settles a capture interrupted after publication: its time is then
// the start of the capture, an older and safe estimate. A repeated call with
// the same size succeeds.
func (s *Store) CompleteVolumeArchive(ctx context.Context, archiveID string, size int64, adopted bool) error {
	if !archiveIDPattern.MatchString(archiveID) || size <= 0 {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var recorded *int64
	if err = tx.QueryRow(ctx, "SELECT size FROM volume_archives WHERE archive_id=$1 FOR UPDATE", archiveID).Scan(&recorded); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if recorded != nil {
		if *recorded != size {
			return ErrArchiveRecord
		}
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE volume_archives SET size=$2,
        captured_at=CASE WHEN $3::boolean THEN started_at ELSE greatest(clock_timestamp(),started_at) END
        WHERE archive_id=$1`, archiveID, size, adopted); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// AbandonVolumeArchive forgets a capture that published nothing. Only the
// worker that checked the archive root may call it; a published archive is
// never forgotten.
func (s *Store) AbandonVolumeArchive(ctx context.Context, archiveID string) error {
	if !archiveIDPattern.MatchString(archiveID) {
		return ErrInput
	}
	_, err := s.pool.Exec(ctx, "DELETE FROM volume_archives WHERE archive_id=$1 AND captured_at IS NULL", archiveID)
	return err
}

// PendingVolumeArchives lists the captures of an agent on host that are not
// settled: each one published its archive or nothing.
func (s *Store) PendingVolumeArchives(ctx context.Context, agentID, host string) ([]string, error) {
	return s.archiveIDs(ctx, `SELECT archive_id FROM volume_archives WHERE agent_id=$1 AND host_id=$2
        AND captured_at IS NULL ORDER BY started_at,archive_id`, agentID, host)
}

// ExpiredVolumeArchives lists the archives of an agent on host beyond the keep
// newest ones, oldest last. keep is at least one: the newest archive of an
// agent is never expired.
func (s *Store) ExpiredVolumeArchives(ctx context.Context, agentID, host string, keep int) ([]string, error) {
	if keep < 1 || keep > 10000 {
		return nil, ErrInput
	}
	return s.archiveIDs(ctx, `SELECT archive_id FROM volume_archives WHERE agent_id=$1 AND host_id=$2
        AND captured_at IS NOT NULL AND removed_at IS NULL ORDER BY captured_at DESC,archive_id DESC OFFSET $3`, agentID, host, keep)
}

func (s *Store) archiveIDs(ctx context.Context, query, agentID, host string, args ...any) ([]string, error) {
	if agentID == "" || host == "" {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, query, append([]any{agentID, host}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RemovedVolumeArchive records that retention deleted the local archive.
// Repeating it keeps the first time.
func (s *Store) RemovedVolumeArchive(ctx context.Context, archiveID string) error {
	if !archiveIDPattern.MatchString(archiveID) {
		return ErrInput
	}
	tag, err := s.pool.Exec(ctx, `UPDATE volume_archives SET removed_at=coalesce(removed_at,clock_timestamp())
        WHERE archive_id=$1 AND captured_at IS NOT NULL`, archiveID)
	if err == nil && tag.RowsAffected() != 1 {
		err = ErrNotFound
	}
	return err
}

// VolumeArchives lists an agent's capture records, newest first.
func (s *Store) VolumeArchives(ctx context.Context, agentID string) ([]VolumeArchive, error) {
	rows, err := s.pool.Query(ctx, `SELECT archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,coalesce(size,0),removed_at
        FROM volume_archives WHERE agent_id=$1 ORDER BY started_at DESC,archive_id DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]VolumeArchive, 0)
	for rows.Next() {
		var a VolumeArchive
		var incarnation int64
		if err = rows.Scan(&a.ID, &a.AgentID, &a.HostID, &a.VolumeID, &incarnation, &a.StartedAt, &a.CapturedAt, &a.Size, &a.RemovedAt); err != nil {
			return nil, err
		}
		a.Incarnation = uint64(incarnation)
		result = append(result, a)
	}
	return result, rows.Err()
}

// VolumeArchiveFreshness returns, for the LIVE agents of host with an
// initialized volume, how many there are and the age of the oldest among
// their newest archives. An agent never archived counts from its
// initialization. No agent gives zero.
func (s *Store) VolumeArchiveFreshness(ctx context.Context, host string) (int, time.Duration, error) {
	if host == "" {
		return 0, 0, ErrInput
	}
	var agents int
	var oldest float64
	err := s.pool.QueryRow(ctx, `SELECT count(*),coalesce(extract(epoch FROM max(clock_timestamp()-coalesce(l.captured_at,i.initialized_at))),0)::float8
        FROM agents a JOIN agent_placements p ON p.agent_id=a.id
        JOIN store_enrollments e ON e.agent_id=a.id
        JOIN store_initializations i ON i.agent_id=e.agent_id AND i.volume_id=e.volume_id AND i.incarnation=e.incarnation
        LEFT JOIN LATERAL (SELECT max(v.captured_at) AS captured_at FROM volume_archives v
          WHERE v.agent_id=a.id AND v.host_id=p.host_id AND v.captured_at IS NOT NULL AND v.removed_at IS NULL) l ON true
        WHERE p.host_id=$1 AND a.phase='LIVE' AND e.stage='READY'`, host).Scan(&agents, &oldest)
	if err != nil {
		return 0, 0, err
	}
	return agents, time.Duration(max(oldest, 0) * float64(time.Second)), nil
}
