package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Work that waits for a VM slot (EVT-007, RUN-011, ADR 017, migration 0033).
//
// A host runs at most max_active VMs. Work that needs a VM for an agent whose
// VM is stopped (a delivery, a wake, the resume of interrupted work) asks for
// a slot under the host's exclusive admission turn. It may take a free slot, or
// stop a VM that is not computing: an idle one first (owesWork), then one that
// only waits (for its next delivery, a wake, or another agent's answer), the
// least recently active first. It never stops a VM that is computing. When
// neither is possible, the agent waits in its host's capacity queue, in
// arrival order, and shows QUEUED. An agent boots only when every older waiter
// of its host can boot too: new work never overtakes older work that waits for
// capacity, whatever its organization. This is the fifo policy of
// fair_admission.qnt with exclusive clients, one per slot. Barriers are not
// queued here: a fence boot reserves its slot ahead of new work
// (barrier_capacity.qnt) and may stop any VM, a computing one last.

// SlotDecision says whether an agent may boot now and, when the host is full,
// which VM to stop for it first.
type SlotDecision struct {
	Admit bool
	Evict string
}

// workInProgress holds while agent a holds work that its harness resumes
// after a restart: an invocation it acknowledged "working", before its result
// is due, or a request it was processing, before its deadline and not
// closing; and no sleep was requested for the agent since that work began.
const workInProgress = `(EXISTS(SELECT 1 FROM platform_operations wo JOIN owner_instructions wi ON wi.operation_id=wo.id
        WHERE wo.agent_id=a.id AND wo.kind='instruction' AND wo.status='RUNNING' AND wi.working_since IS NOT NULL
          AND wi.result_due_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM platform_operations ws WHERE ws.agent_id=a.id AND ws.kind='sleep' AND ws.created_at>=wi.working_since))
    OR EXISTS(SELECT 1 FROM agent_requests wr WHERE wr.recipient_agent_id=a.id AND wr.state='PROCESSING' AND wr.expires_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM request_closures wc WHERE wc.request_id=wr.id)
          AND NOT EXISTS(SELECT 1 FROM platform_operations ws WHERE ws.agent_id=a.id AND ws.kind='sleep' AND ws.created_at>=wr.created_at)))`

// resumeDue holds while live agent a, not FAILED, holds work in progress.
const resumeDue = `a.phase='LIVE' AND NOT EXISTS(SELECT 1 FROM failed_agents f WHERE f.agent_id=a.id) AND ` + workInProgress

// slotDue holds while agent a still needs a VM slot for work: it is live, not
// FAILED, not running, and has a pending delivery, an open wake, or work in
// progress to resume. A waiter for which it fails leaves the queue. A delivery
// past its deadline that no attempt reached keeps its agent waiting until it
// dies, a pass later at most, so that its death can say it waited for
// capacity; one an attempt may have reached waits for a fence, not a slot.
const slotDue = `a.phase='LIVE' AND NOT EXISTS(SELECT 1 FROM failed_agents f WHERE f.agent_id=a.id)
    AND NOT EXISTS(SELECT 1 FROM agent_placements sp WHERE sp.agent_id=a.id AND sp.state='RUNNING' AND NOT sp.fence_only)
    AND (EXISTS(SELECT 1 FROM agent_mailboxes sm WHERE sm.dest_agent_id=a.id AND sm.delivery_state='PENDING' AND NOT sm.closing
           AND (sm.expires_at>clock_timestamp() OR NOT sm.may_have_reached))
      OR EXISTS(SELECT 1 FROM platform_operations so WHERE so.agent_id=a.id AND so.kind='wake' AND so.status IN ('PENDING','RUNNING'))
      OR ` + workInProgress + `)`

// computing holds while agent a works on something only its running VM can
// carry on: work in progress, unless it waits for another agent's answer, or
// a model call in flight. Work never stops such a VM. An agent that waits for
// another agent may be stopped: the answer's delivery boots it again, and its
// harness resumes. Holding its slot could instead keep the other agent from
// booting until a deadline.
const computing = `((` + workInProgress + `
        AND NOT EXISTS(SELECT 1 FROM agent_requests pr WHERE pr.sender_agent_id=a.id
          AND pr.state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING') AND pr.expires_at>clock_timestamp()))
    OR EXISTS(SELECT 1 FROM llm_usage cu WHERE cu.agent_id=a.id AND cu.state='reserved'))`

// lastActivity is the latest time agent a did or received something the
// platform tracks; the least recently active idle VM is stopped first.
const lastActivity = `greatest(coalesce(x.created_at,'-infinity'::timestamptz),
        coalesce((SELECT max(greatest(o.created_at,coalesce(o.completed_at,o.created_at))) FROM platform_operations o WHERE o.agent_id=a.id),'-infinity'::timestamptz),
        coalesce((SELECT max(greatest(r.created_at,coalesce(r.decided_at,r.created_at))) FROM agent_requests r
                   WHERE r.sender_agent_id=a.id OR r.recipient_agent_id=a.id),'-infinity'::timestamptz),
        coalesce((SELECT max(coalesce(u.settled_at,u.created_at)) FROM llm_usage u WHERE u.agent_id=a.id),'-infinity'::timestamptz))`

// AdmitToSlot decides whether agent may boot now on host. The caller holds the
// host's exclusive admission turn and passes its census: the other agents
// whose VMs run there, and how many slots are free. An agent is admitted when
// fewer older waiters remain than slots it could use: free ones, then the
// slots of VMs that are not computing, which it stops first (Evict).
// Otherwise it waits in the queue, keeping its first place; asking again
// never moves it back.
func (s *Store) AdmitToSlot(ctx context.Context, host, agent string, running []string, free int) (SlotDecision, error) {
	if host == "" || agent == "" || free < 0 {
		return SlotDecision{}, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return SlotDecision{}, err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return SlotDecision{}, err
	}
	if err = pruneCapacityWaits(ctx, tx, host); err != nil {
		return SlotDecision{}, err
	}
	// An agent with nothing that needs a slot (FAILED, being deleted, its work
	// gone) never waits: the boot itself gives the precise refusal, such as
	// restart_budget_exhausted for the wake of a FAILED agent.
	var due bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents a WHERE a.id=$1 AND `+slotDue+`)`, agent).Scan(&due); err != nil {
		return SlotDecision{}, err
	}
	if !due {
		return SlotDecision{Admit: true}, commit(ctx, tx)
	}
	var ticket *int64
	err = tx.QueryRow(ctx, "SELECT ticket FROM capacity_waits WHERE agent_id=$1 AND host_id=$2", agent, host).Scan(&ticket)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SlotDecision{}, err
	}
	var older int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM capacity_waits WHERE host_id=$1 AND agent_id<>$2 AND ($3::bigint IS NULL OR ticket<$3)`,
		host, agent, ticket).Scan(&older); err != nil {
		return SlotDecision{}, err
	}
	var d SlotDecision
	if older < free {
		d.Admit = true
	} else {
		others := make([]string, 0, len(running))
		for _, id := range running {
			if id != agent {
				others = append(others, id)
			}
		}
		stoppable, err := evictionOrder(ctx, tx, others, true)
		if err != nil {
			return SlotDecision{}, err
		}
		if older < free+len(stoppable) {
			d = SlotDecision{Admit: true, Evict: stoppable[0]}
		}
	}
	if !d.Admit && ticket == nil {
		n, err := nextWorkTicket(ctx, tx, host)
		if err != nil {
			return SlotDecision{}, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO capacity_waits(agent_id,host_id,ticket) VALUES($1,$2,$3)", agent, host, n); err != nil {
			return SlotDecision{}, err
		}
	}
	return d, commit(ctx, tx)
}

// SlotTaken records that agent booted on host: it leaves the queue, and the
// jobs of the next waiter are tried at once rather than after their backoff.
func (s *Store) SlotTaken(ctx context.Context, host, agent string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM capacity_waits WHERE agent_id=$1 AND host_id=$2", agent, host); err != nil {
		return err
	}
	if err = promoteCapacityHead(ctx, tx, host); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// PromoteCapacityHead drops the waiters of host whose work is no longer due,
// and makes the jobs of the oldest remaining one available now. The worker
// calls it on each pass, so a slot freed by a sleep, a deletion or a crash is
// offered to the oldest waiter first.
func (s *Store) PromoteCapacityHead(ctx context.Context, host string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	if err = pruneCapacityWaits(ctx, tx, host); err != nil {
		return err
	}
	if err = promoteCapacityHead(ctx, tx, host); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// EvictionOrder orders the running agents a barrier may stop to boot a
// store: idle ones first, then those that only wait, then those computing,
// each the least recently active first.
func (s *Store) EvictionOrder(ctx context.Context, host string, running []string) ([]string, error) {
	if host == "" {
		return nil, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	order, err := evictionOrder(ctx, tx, running, false)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(order))
	for _, id := range order {
		known[id] = true
	}
	for _, id := range running {
		if !known[id] {
			order = append(order, id)
		}
	}
	return order, commit(ctx, tx)
}

// CapacityQueue counts the agents of host that wait for a VM slot and how long
// the oldest has waited, for the operator's metrics.
func (s *Store) CapacityQueue(ctx context.Context, host string) (int, time.Duration, error) {
	var n int
	var oldest float64
	err := s.pool.QueryRow(ctx, `SELECT count(*),coalesce(extract(epoch FROM clock_timestamp()-min(since)),0)::float8
        FROM capacity_waits WHERE host_id=$1`, host).Scan(&n, &oldest)
	return n, time.Duration(oldest * float64(time.Second)), err
}

// ResumeDue reports whether agent, whose VM is not running, holds work in
// progress that its harness resumes once it boots again (the resume job).
func (s *Store) ResumeDue(ctx context.Context, agent string) (bool, error) {
	var due bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents a WHERE a.id=$1 AND `+resumeDue+`
        AND NOT EXISTS(SELECT 1 FROM agent_placements sp WHERE sp.agent_id=a.id AND sp.state='RUNNING' AND NOT sp.fence_only))`, agent).Scan(&due)
	return due, err
}

// evictionOrder orders running agents for stopping: idle first, then those
// that only wait, then those computing, unless forWork leaves those out.
func evictionOrder(ctx context.Context, tx pgx.Tx, running []string, forWork bool) ([]string, error) {
	if len(running) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT a.id FROM agents a LEFT JOIN agent_specs x ON x.agent_id=a.id
        WHERE a.id=ANY($1) AND (NOT $2 OR NOT `+computing+`)
        ORDER BY `+computing+`,`+owesWork("clock_timestamp()")+`,`+lastActivity+`,a.id`, running, forWork)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func pruneCapacityWaits(ctx context.Context, tx pgx.Tx, host string) error {
	_, err := tx.Exec(ctx, `DELETE FROM capacity_waits w USING agents a WHERE w.host_id=$1 AND a.id=w.agent_id AND NOT (`+slotDue+`)`, host)
	return err
}

func promoteCapacityHead(ctx context.Context, tx pgx.Tx, host string) error {
	_, err := tx.Exec(ctx, `UPDATE worker_jobs SET available_at=clock_timestamp()
        WHERE host_id=$1 AND lease_token='' AND available_at>clock_timestamp() AND kind IN ('delivery','lifecycle','resume')
          AND agent_id=(SELECT agent_id FROM capacity_waits WHERE host_id=$1 ORDER BY ticket LIMIT 1)`, host)
	return err
}
