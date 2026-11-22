package workqueue

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
func (q Queue) WorkQueue(ctx context.Context, host string) ([]WorkKindStats, error) {
	rows, err := q.reader.Query(ctx, `SELECT kind, count(*),
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

// InvocationBacklog counts the invocations accepted for the agents of the host
// and not yet delivered, and how long the oldest has waited since it was
// accepted, or released for a scheduled one (OPS-03). Worker jobs do not
// show this wait: an agent's deliveries share one job, its head.
func (q Queue) InvocationBacklog(ctx context.Context, host string) (int, time.Duration, error) {
	var n int
	var seconds float64
	err := q.reader.QueryRow(ctx, `SELECT count(*),
        coalesce(extract(epoch FROM clock_timestamp()-min(coalesce(i.released_at,o.created_at))),0)
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id JOIN platform_operations o ON o.id=i.operation_id
        WHERE m.kind='instruction' AND m.delivery_state='PENDING' AND o.host_id=$1`, host).Scan(&n, &seconds)
	return n, time.Duration(seconds * float64(time.Second)), err
}

// RunningPlacements counts the host's VMs published as running.
func (q Queue) RunningPlacements(ctx context.Context, host string) (int, error) {
	var n int
	err := q.reader.QueryRow(ctx, "SELECT count(*) FROM agent_placements WHERE host_id=$1 AND state='RUNNING'", host).Scan(&n)
	return n, err
}

// RequestOriginSQL is the API request behind a request between agents: the
// one that created the invocation whose mandate the sender used.
const RequestOriginSQL = `SELECT o.request_id FROM agent_requests r JOIN owner_instructions i ON i.mandate_id=r.mandate_id
    JOIN platform_operations o ON o.id=i.operation_id WHERE r.id=$1`

// JobOrigin returns the X-Request-ID of the API request that started a job
// (OPS-02), or "" when none did: a delivery of an invocation, or of a request,
// reply or status between agents under the mandate an invocation granted; a
// closure or an expiration of such a request; a provisioning or lifecycle
// operation; the deletion of an agent.
func (q Queue) JobOrigin(ctx context.Context, j WorkerJob) (string, error) {
	var query string
	switch j.Kind {
	case "delivery":
		query = `SELECT coalesce((SELECT o.request_id FROM platform_operations o WHERE o.id=m.instruction_id),
            (` + strings.ReplaceAll(RequestOriginSQL, "$1", "m.ref_id") + `)) FROM agent_mailboxes m WHERE m.id=$1`
	case "closure", "expiration":
		query = RequestOriginSQL
	case "provision", "lifecycle":
		query = "SELECT request_id FROM platform_operations WHERE id=$1"
	case "deletion":
		query = "SELECT request_id FROM platform_operations WHERE agent_id=$1 AND kind='delete' ORDER BY seq DESC LIMIT 1"
	default:
		return "", nil
	}
	var id *string
	err := q.reader.QueryRow(ctx, query, j.ID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) || id == nil {
		return "", nil
	}
	return *id, err
}
