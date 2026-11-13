package controlplane

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// WorkKindStats describes one kind of durable job of a host, for metrics
// (OPS-02). Counts only: no job, agent or organization identifier.
type WorkKindStats struct {
	Kind string
	// Jobs is every job of the kind; Due, those whose time has come and that
	// no worker holds; Failing, those that failed three times or more.
	Jobs, Due, Failing int
	// OldestDue is how long the oldest due job has waited past its time. A job
	// waiting for a retry is not due, so a backoff does not count as delay.
	OldestDue time.Duration
}

// WorkQueue returns the host's job queue by kind.
func (s *Store) WorkQueue(ctx context.Context, host string) ([]WorkKindStats, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, count(*),
        count(*) FILTER (WHERE lease_token='' AND available_at<=clock_timestamp()),
        count(*) FILTER (WHERE failures>=3),
        coalesce(extract(epoch FROM clock_timestamp()-min(available_at) FILTER (WHERE lease_token='' AND available_at<=clock_timestamp())),0)
        FROM worker_jobs WHERE host_id=$1 GROUP BY kind ORDER BY kind`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkKindStats
	for rows.Next() {
		var k WorkKindStats
		var seconds float64
		if err = rows.Scan(&k.Kind, &k.Jobs, &k.Due, &k.Failing, &seconds); err != nil {
			return nil, err
		}
		k.OldestDue = time.Duration(seconds * float64(time.Second))
		out = append(out, k)
	}
	return out, rows.Err()
}

// RunningPlacements counts the host's VMs published as running.
func (s *Store) RunningPlacements(ctx context.Context, host string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM agent_placements WHERE host_id=$1 AND state='RUNNING'", host).Scan(&n)
	return n, err
}

// originOfRequest is the API request behind a request between agents: the
// one that created the invocation whose mandate the sender used.
const originOfRequest = `SELECT o.request_id FROM agent_requests r JOIN owner_instructions i ON i.mandate_id=r.mandate_id
    JOIN platform_operations o ON o.id=i.operation_id WHERE r.id=$1`

// JobOrigin returns the X-Request-ID of the API request that started a job
// (OPS-02), or "" when none did: a delivery of an invocation, or of a request,
// reply or status between agents under the mandate an invocation granted; a
// closure or an expiration of such a request; a provisioning or lifecycle
// operation; the deletion of an agent.
func (s *Store) JobOrigin(ctx context.Context, j WorkerJob) (string, error) {
	var query string
	switch j.Kind {
	case "delivery":
		query = `SELECT coalesce((SELECT o.request_id FROM platform_operations o WHERE o.id=m.instruction_id),
            (` + strings.ReplaceAll(originOfRequest, "$1", "m.ref_id") + `)) FROM agent_mailboxes m WHERE m.id=$1`
	case "closure", "expiration":
		query = originOfRequest
	case "provision", "lifecycle":
		query = "SELECT request_id FROM platform_operations WHERE id=$1"
	case "deletion":
		query = "SELECT request_id FROM platform_operations WHERE agent_id=$1 AND kind='delete' ORDER BY seq DESC LIMIT 1"
	default:
		return "", nil
	}
	var id *string
	err := s.pool.QueryRow(ctx, query, j.ID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) || id == nil {
		return "", nil
	}
	return *id, err
}
