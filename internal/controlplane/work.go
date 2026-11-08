package controlplane

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrNoWork = errors.New("no eligible worker job")
var ErrWorkLeaseLost = errors.New("worker job lease is no longer current")

type WorkerJob struct {
	HostID, Kind, ID, AgentID, Token string
	Failures                         int
	LeaseUntil                       time.Time
}

func lockWorkerHost(ctx context.Context, tx pgx.Tx, host string) error {
	if host == "" {
		return ErrPlacement
	}
	if _, err := tx.Exec(ctx, "INSERT INTO worker_hosts(host_id) VALUES ($1) ON CONFLICT DO NOTHING", host); err != nil {
		return err
	}
	var ignored int64
	return tx.QueryRow(ctx, "SELECT next_ticket FROM worker_hosts WHERE host_id=$1 FOR NO KEY UPDATE", host).Scan(&ignored)
}
func nextWorkTicket(ctx context.Context, tx pgx.Tx, host string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, "UPDATE worker_hosts SET next_ticket=next_ticket+1 WHERE host_id=$1 AND next_ticket<$2 RETURNING next_ticket", host, int64(math.MaxInt64)).Scan(&n)
	return n, err
}

// DiscoverWork projects durable business intents onto a host-local work queue.
// Only a mailbox head is scheduled. A bounded oldest-first batch admits new
// work; existing tickets are unchanged by repeated discovery. Multi-host fence
// transport remains separate from this initial single-host coordinator.
func (s *Store) DiscoverWork(ctx context.Context, host string, limit int) error {
	if limit < 1 || limit > 1024 {
		return errors.New("invalid work discovery limit")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT kind,object_id,agent_id FROM (
        SELECT 'delivery' AS kind,m.id AS object_id,m.dest_agent_id AS agent_id,o.available_at AS created
          FROM outbox o JOIN agent_mailboxes m ON m.id=o.mailbox_id
          JOIN agent_placements p ON p.agent_id=m.dest_agent_id
          WHERE p.host_id=$1 AND m.delivery_state='PENDING' AND o.available_at<=clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM agent_mailboxes h WHERE h.dest_agent_id=m.dest_agent_id AND h.delivery_state='PENDING' AND h.seq<m.seq)
        UNION ALL
        SELECT 'closure',c.request_id,r.sender_agent_id,c.requested_at
          FROM request_closures c JOIN agent_requests r ON r.id=c.request_id
          JOIN agent_placements p ON p.agent_id=r.sender_agent_id WHERE p.host_id=$1 AND c.phase='FENCING'
        UNION ALL
        SELECT 'deletion',d.agent_id,d.agent_id,d.requested_at FROM deletion_operations d
          JOIN agent_placements p ON p.agent_id=d.agent_id WHERE p.host_id=$1
            AND (NOT EXISTS(SELECT 1 FROM store_seals x WHERE x.agent_id=d.agent_id)
              OR EXISTS(SELECT 1 FROM store_enrollments e JOIN agents a ON a.id=e.agent_id
                        WHERE e.agent_id=d.agent_id AND a.phase<>'DELETED'))
        UNION ALL
        SELECT 'expiration',r.id,r.sender_agent_id,r.expires_at FROM agent_requests r
          JOIN agent_placements p ON p.agent_id=r.sender_agent_id WHERE p.host_id=$1
            AND r.state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING') AND r.expires_at<=clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM request_closures c WHERE c.request_id=r.id)
        UNION ALL
        SELECT 'provision',o.id,o.agent_id,o.created_at FROM platform_operations o
          JOIN agents a ON a.id=o.agent_id JOIN store_enrollments e ON e.agent_id=a.id
          WHERE o.host_id=$1 AND o.kind='provision' AND o.status IN ('PENDING','RUNNING')
            AND a.phase='PROVISIONING' AND e.stage IN ('INSTALLING','FENCING') AND e.operation_id=o.id
        UNION ALL
        SELECT 'lifecycle',o.id,o.agent_id,o.created_at FROM platform_operations o
          WHERE o.host_id=$1 AND o.kind IN ('wake','sleep') AND o.status IN ('PENDING','RUNNING')
            AND NOT EXISTS(SELECT 1 FROM platform_operations earlier WHERE earlier.agent_id=o.agent_id AND earlier.seq<o.seq
                AND earlier.kind IN ('wake','sleep') AND earlier.status IN ('PENDING','RUNNING'))
      ) work WHERE NOT EXISTS(SELECT 1 FROM worker_jobs j WHERE j.host_id=$1 AND j.kind=work.kind AND j.object_id=work.object_id)
      ORDER BY created,kind,object_id LIMIT $2`, host, limit)
	if err != nil {
		return err
	}
	var jobs []WorkerJob
	for rows.Next() {
		var j WorkerJob
		if err = rows.Scan(&j.Kind, &j.ID, &j.AgentID); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, j := range jobs {
		n, err := nextWorkTicket(ctx, tx, host)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO worker_jobs(host_id,kind,object_id,agent_id,ticket)
            VALUES ($1,$2,$3,$4,$5) ON CONFLICT(host_id,kind,object_id) DO NOTHING`, host, j.Kind, j.ID, j.AgentID, n); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}

// ClaimWork moves the job to the tail BEFORE execution, so a crashed/failed job
// cannot monopolize the next claim. No SQL lock spans an RPC. Jobs that become
// eligible again retain this ticket while newer arrivals join behind it.
func (s *Store) ClaimWork(ctx context.Context, host string, lease time.Duration) (WorkerJob, error) {
	var j WorkerJob
	j.HostID = host
	if lease < time.Microsecond || lease > 24*time.Hour {
		return j, errors.New("invalid worker job lease")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return j, err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return j, err
	}
	err = tx.QueryRow(ctx, `SELECT kind,object_id,agent_id,failures FROM worker_jobs WHERE host_id=$1
        AND available_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())
        ORDER BY ticket LIMIT 1 FOR UPDATE`, host).Scan(&j.Kind, &j.ID, &j.AgentID, &j.Failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrNoWork
	}
	if err != nil {
		return j, err
	}
	n, err := nextWorkTicket(ctx, tx, host)
	if err != nil {
		return j, err
	}
	j.Token = newID("work")
	err = tx.QueryRow(ctx, `UPDATE worker_jobs SET ticket=$4,lease_token=$5,
        lease_until=clock_timestamp()+$6*interval '1 microsecond'
        WHERE host_id=$1 AND kind=$2 AND object_id=$3 RETURNING lease_until`, host, j.Kind, j.ID, n, j.Token, lease.Microseconds()).Scan(&j.LeaseUntil)
	if err != nil {
		return j, err
	}
	return j, commit(ctx, tx)
}

func (s *Store) CompleteWork(ctx context.Context, j WorkerJob) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `DELETE FROM worker_jobs WHERE host_id=$1 AND kind=$2 AND object_id=$3
        AND lease_token=$4 AND lease_until>clock_timestamp()`, j.HostID, j.Kind, j.ID, j.Token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrWorkLeaseLost
	}
	return commit(ctx, tx)
}

func (s *Store) RetryWork(ctx context.Context, j WorkerJob, delay time.Duration) error {
	if delay < time.Microsecond || delay > 24*time.Hour {
		return errors.New("invalid worker retry delay")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `UPDATE worker_jobs SET available_at=clock_timestamp()+$5*interval '1 microsecond',
        failures=least(failures+1,30),lease_token='',lease_until=NULL
        WHERE host_id=$1 AND kind=$2 AND object_id=$3 AND lease_token=$4 AND lease_until>clock_timestamp()`,
		j.HostID, j.Kind, j.ID, j.Token, delay.Microseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrWorkLeaseLost
	}
	return commit(ctx, tx)
}
