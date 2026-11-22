// Package workqueue schedules, leases, and observes the durable worker jobs for each host.
package workqueue

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// Reader is the read-only part of the pool used for job statistics.
type Reader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Queue uses the control plane's transaction preamble, rollback, and post-commit recording.
type Queue struct {
	reader   Reader
	transact func(context.Context, func(pgx.Tx) error) error
}

func New(reader Reader, transact func(context.Context, func(pgx.Tx) error) error) Queue {
	return Queue{reader: reader, transact: transact}
}

var ErrPlacement = errors.New("obsolete or foreign VM placement")
var ErrHostLost = errors.New("this host was lost and another host took it over")

// WorkInProgress holds while agent a holds work that its harness resumes
// after a restart: an invocation it acknowledged "working", before its result
// is due, or a request it was processing, before its deadline and not
// closing; and no sleep was requested for the agent since that work began.
const WorkInProgress = `(EXISTS(SELECT 1 FROM platform_operations wo JOIN owner_instructions wi ON wi.operation_id=wo.id
        WHERE wo.agent_id=a.id AND wo.kind='instruction' AND wo.status='RUNNING' AND wi.working_since IS NOT NULL
          AND wi.result_due_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM platform_operations ws WHERE ws.agent_id=a.id AND ws.kind='sleep' AND ws.created_at>=wi.working_since))
    OR EXISTS(SELECT 1 FROM agent_requests wr WHERE wr.recipient_agent_id=a.id AND wr.state='PROCESSING' AND wr.expires_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM request_closures wc WHERE wc.request_id=wr.id)
          AND NOT EXISTS(SELECT 1 FROM platform_operations ws WHERE ws.agent_id=a.id AND ws.kind='sleep' AND ws.created_at>=wr.created_at)))`

// ResumeDuePredicate holds while live agent a, not FAILED, holds work in progress.
const ResumeDuePredicate = `a.phase='LIVE' AND NOT EXISTS(SELECT 1 FROM failed_agents f WHERE f.agent_id=a.id) AND ` + WorkInProgress

var ErrNoWork = errors.New("no eligible worker job")
var ErrWorkLeaseLost = errors.New("worker job lease is no longer current")

type WorkerJob struct {
	HostID, Kind, ID, AgentID, Token string
	Failures                         int
	LeaseUntil                       time.Time
}

// LockHost serializes with the host's work queue and its reservations.
// A lost host (ADR 020) gets no work and no agent: ErrHostLost, with the lock
// held all the same, so that a caller with nothing to schedule may go on.
func LockHost(ctx context.Context, tx pgx.Tx, host string) error {
	if host == "" {
		return ErrPlacement
	}
	if _, err := tx.Exec(ctx, "INSERT INTO worker_hosts(host_id) VALUES ($1) ON CONFLICT DO NOTHING", host); err != nil {
		return err
	}
	var ignored int64
	if err := tx.QueryRow(ctx, "SELECT next_ticket FROM worker_hosts WHERE host_id=$1 FOR NO KEY UPDATE", host).Scan(&ignored); err != nil {
		return err
	}
	// A new statement, after the lock: TakeOverHost commits under it.
	var lost bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM host_takeovers WHERE lost_host_id=$1)", host).Scan(&lost); err != nil {
		return err
	}
	if lost {
		return ErrHostLost
	}
	return nil
}
func NextTicket(ctx context.Context, tx pgx.Tx, host string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, "UPDATE worker_hosts SET next_ticket=next_ticket+1 WHERE host_id=$1 AND next_ticket<$2 RETURNING next_ticket", host, int64(math.MaxInt64)).Scan(&n)
	return n, err
}

// DiscoverySQL lists host $1's work that has no job yet, oldest first, at
// most $2. Its open-state indexes keep it off the tables' history (P-04).
const DiscoverySQL = `SELECT kind,object_id,agent_id FROM (
        SELECT 'delivery' AS kind,m.id AS object_id,m.dest_agent_id AS agent_id,o.available_at AS created
          FROM outbox o JOIN agent_mailboxes m ON m.id=o.mailbox_id
          JOIN agent_placements p ON p.agent_id=m.dest_agent_id
          WHERE p.host_id=$1 AND m.delivery_state='PENDING' AND o.available_at<=clock_timestamp()
            AND (NOT EXISTS(SELECT 1 FROM agent_mailboxes h WHERE h.dest_agent_id=m.dest_agent_id AND h.delivery_state='PENDING' AND h.seq<m.seq)
              OR m.kind<>'request' AND NOT m.may_have_reached AND m.expires_at<=clock_timestamp())
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
        UNION ALL
        SELECT 'resume',a.id,a.id,clock_timestamp() FROM agents a JOIN agent_placements p ON p.agent_id=a.id
          WHERE p.host_id=$1 AND p.state='STOPPED' AND ` + ResumeDuePredicate + `
      ) work WHERE NOT EXISTS(SELECT 1 FROM worker_jobs j WHERE j.host_id=$1 AND j.kind=work.kind AND j.object_id=work.object_id)
      ORDER BY created,kind,object_id LIMIT $2`

// DiscoverWork projects durable business intents onto a host-local work queue.
// Only a mailbox head is scheduled, and a reply, status or instruction past
// its deadline that no attempt reached, which dies wherever it is in the
// queue (ADR 007). An agent whose VM stopped while it held work in progress
// is resumed (ADR 017). A bounded oldest-first batch admits new
// work; existing tickets are unchanged by repeated discovery. Multi-host fence
// transport remains separate from this initial single-host coordinator.
func (q Queue) DiscoverWork(ctx context.Context, host string, limit int) error {
	if limit < 1 || limit > 1024 {
		return errors.New("invalid work discovery limit")
	}
	return q.transact(ctx, func(tx pgx.Tx) error {
		if err := LockHost(ctx, tx, host); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, DiscoverySQL, host, limit)
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
			n, err := NextTicket(ctx, tx, host)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO worker_jobs(host_id,kind,object_id,agent_id,ticket)
            VALUES ($1,$2,$3,$4,$5) ON CONFLICT(host_id,kind,object_id) DO NOTHING`, host, j.Kind, j.ID, j.AgentID, n); err != nil {
				return err
			}
		}
		return nil
	})
}

// ClaimWork moves the job to the tail BEFORE execution, so a crashed/failed job
// cannot monopolize the next claim. No SQL lock spans an RPC. Jobs that become
// eligible again retain this ticket while newer arrivals join behind it.
func (q Queue) ClaimWork(ctx context.Context, host string, lease time.Duration) (WorkerJob, error) {
	var j WorkerJob
	j.HostID = host
	if lease < time.Microsecond || lease > 24*time.Hour {
		return j, errors.New("invalid worker job lease")
	}
	err := q.transact(ctx, func(tx pgx.Tx) error {
		if err := LockHost(ctx, tx, host); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT kind,object_id,agent_id,failures FROM worker_jobs WHERE host_id=$1
        AND available_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())
        ORDER BY ticket LIMIT 1 FOR UPDATE`, host).Scan(&j.Kind, &j.ID, &j.AgentID, &j.Failures)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoWork
		}
		if err != nil {
			return err
		}
		n, err := NextTicket(ctx, tx, host)
		if err != nil {
			return err
		}
		j.Token = persistence.ID("work")
		err = tx.QueryRow(ctx, `UPDATE worker_jobs SET ticket=$4,lease_token=$5,
        lease_until=clock_timestamp()+$6*interval '1 microsecond'
        WHERE host_id=$1 AND kind=$2 AND object_id=$3 RETURNING lease_until`, host, j.Kind, j.ID, n, j.Token, lease.Microseconds()).Scan(&j.LeaseUntil)
		if err != nil {
			return err
		}
		return nil
	})
	return j, err
}

func (q Queue) CompleteWork(ctx context.Context, j WorkerJob) error {
	return q.transact(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM worker_jobs WHERE host_id=$1 AND kind=$2 AND object_id=$3
        AND lease_token=$4 AND lease_until>clock_timestamp()`, j.HostID, j.Kind, j.ID, j.Token)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrWorkLeaseLost
		}
		return nil
	})
}

func (q Queue) RetryWork(ctx context.Context, j WorkerJob, delay time.Duration) error {
	return q.RetryWorkWithCapacity(ctx, j, delay, false)
}

func (q Queue) RetryWorkWithCapacity(ctx context.Context, j WorkerJob, delay time.Duration, capacity bool) error {
	if delay < time.Microsecond || delay > 24*time.Hour {
		return errors.New("invalid worker retry delay")
	}
	return q.transact(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE worker_jobs SET available_at=clock_timestamp()+$5*interval '1 microsecond',
        failures=least(failures+1,30),lease_token='',lease_until=NULL,capacity_wait=$6
        WHERE host_id=$1 AND kind=$2 AND object_id=$3 AND lease_token=$4 AND lease_until>clock_timestamp()`,
			j.HostID, j.Kind, j.ID, j.Token, delay.Microseconds(), capacity)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrWorkLeaseLost
		}
		return nil
	})
}
