package controlplane

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// WALArchiving describes PostgreSQL's continuous archiving (REC-03, ADR 004),
// for metrics: states and durations only, never a WAL file name, a command or
// a path.
type WALArchiving struct {
	// Enabled: archive_mode is on (or always), and an archive_command or an
	// archive_library is set.
	Enabled bool
	// Timeout is archive_timeout, 0 when it is off: the longest a change waits
	// in an open segment before PostgreSQL closes the segment for archiving.
	Timeout time.Duration
	// Age is the time since PostgreSQL last archived a WAL file successfully.
	// When it archived none since its archiver statistics began (the cluster's
	// creation, a crash recovery or a reset), it is the time since they began:
	// nothing was archived for at least that long.
	Age time.Duration
	// Pending: a completed WAL segment waits for archiving. The open segment
	// does not count; archive_timeout closes it. An idle database has nothing
	// pending, however old its last archive.
	Pending bool
	// Failing: the latest archive attempt failed. PostgreSQL retries the
	// segment, so this stays true until the segment is archived.
	Failing bool
}

// walArchivingQuery reads pg_stat_archiver and five settings. Every role may
// read them and call these functions: the worker's role needs no grant. The
// archive command is only checked for being empty, never returned. The last
// completed segment is the one before the segment holding the current write
// position; its name, from pg_walfile_name, carries the current timeline. A
// standby (in recovery) has no write position: nothing is pending.
const walArchivingQuery = `SELECT current_setting('archive_mode') IN ('on', 'always')
        AND (current_setting('archive_command') <> '' OR current_setting('archive_library') <> ''),
    (SELECT setting::bigint FROM pg_settings WHERE name = 'archive_timeout'),
    a.last_archived_wal,
    extract(epoch FROM clock_timestamp() - a.last_archived_time)::float8,
    extract(epoch FROM clock_timestamp() - a.last_failed_time)::float8,
    extract(epoch FROM clock_timestamp() - coalesce(a.stats_reset, pg_postmaster_start_time()))::float8,
    CASE WHEN w.boundary >= w.segment THEN pg_walfile_name('0/0'::pg_lsn + (w.boundary - 1)) END
FROM pg_stat_archiver a,
    (SELECT p.position - p.position % p.segment AS boundary, p.segment
       FROM (SELECT CASE WHEN pg_is_in_recovery() THEN NULL ELSE pg_current_wal_lsn() - '0/0'::pg_lsn END AS position,
                    (SELECT setting::numeric FROM pg_settings WHERE name = 'wal_segment_size') AS segment) p) w`

// archiverRow is walArchivingQuery's row. The ages are in seconds; NULL is
// "none since the statistics began" (archived, failed) or "no completed
// segment" (lastComplete).
type archiverRow struct {
	enabled                bool
	timeout                int64
	lastArchived           *string
	archivedAge, failedAge *float64
	statisticsAge          float64
	lastComplete           *string
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readWALArchiving(ctx context.Context, db rowQuerier) (WALArchiving, error) {
	var r archiverRow
	err := db.QueryRow(ctx, walArchivingQuery).Scan(&r.enabled, &r.timeout, &r.lastArchived, &r.archivedAge, &r.failedAge,
		&r.statisticsAge, &r.lastComplete)
	if err != nil {
		return WALArchiving{}, err
	}
	return r.state(), nil
}

// WALArchiving reads the state of PostgreSQL's WAL archiving.
func (s *Store) WALArchiving(ctx context.Context) (WALArchiving, error) {
	return readWALArchiving(ctx, s.pool)
}

func ageOf(seconds float64) time.Duration {
	return time.Duration(max(seconds, 0) * float64(time.Second))
}

// walFileSegment is the segment a WAL file name refers to: a backup label
// (…05.00000028.backup) or a partial segment (…05.partial) refers to its
// segment. A timeline history file (00000002.history) has none, and sorts
// before every segment of its timeline.
func walFileSegment(name string) string {
	if len(name) > 24 {
		return name[:24]
	}
	return name
}

func (r archiverRow) state() WALArchiving {
	w := WALArchiving{Enabled: r.enabled, Timeout: time.Duration(max(r.timeout, 0)) * time.Second, Age: ageOf(r.statisticsAge)}
	if r.archivedAge != nil {
		w.Age = ageOf(*r.archivedAge)
	}
	// A failure older than the last success is over: a retry archived it.
	w.Failing = r.failedAge != nil && (r.archivedAge == nil || *r.failedAge < *r.archivedAge)
	// Segment names sort by timeline, then by position. A completed segment
	// after the last archived one waits; so does any segment of a newer
	// timeline than the last archived file.
	w.Pending = r.lastComplete != nil && (r.lastArchived == nil || walFileSegment(*r.lastArchived) < *r.lastComplete)
	return w
}
