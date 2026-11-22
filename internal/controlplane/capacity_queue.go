package controlplane

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Work that waits for a VM slot (EVT-007, RUN-011, ADR 017, migration 0035).
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
//
// An organization's quotas on active VMs, vCPUs and RAM (TEN-007, ADR 021)
// make its work wait in the same queue, with the reason organization_quota.
// Such a waiter holds no slot against other organizations' work: it does not
// count among the older waiters others wait for. Within its organization,
// order holds: an agent fits only if its organization's older waiters on the
// host fit too. The organization's oldest waiter on the host may stop the
// organization's own VMs there that are not computing, as work does for a
// full host; VMs on other hosts are not stopped for it. claimPlacement
// checks the quotas again when it reserves the boot.

// SlotDecision says whether an agent may boot now and, when the host is full,
// which VM to stop for it first.
type SlotDecision struct {
	Admit bool
	Evict string
	// EvictForQuota are VMs of the agent's own organization on this host to
	// stop first, so that its boot fits the organization's quotas.
	EvictForQuota []string
	// Quota names the organization's quota the agent waits for, when it waits
	// for its organization rather than for a slot of the host.
	Quota string
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
// platform tracks; the least recently active idle VM is stopped first. Its
// operations, requests and model calls keep agent_activity (migration 0067).
const lastActivity = `greatest(coalesce(x.created_at,'-infinity'::timestamptz),
        coalesce((SELECT v.at FROM agent_activity v WHERE v.agent_id=a.id),'-infinity'::timestamptz))`

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
	if err = allowRolloutBoot(ctx, tx, agent, ""); err != nil {
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
	// Older waiters that wait for their own organization's quota hold no
	// slot against this one.
	var older int
	if err = tx.QueryRow(ctx, `WITH `+quotaWaiters+` SELECT count(*) FROM waiting w
        WHERE w.agent_id<>$2 AND ($3::bigint IS NULL OR w.ticket<$3) AND NOT w.held`, host, agent, ticket).Scan(&older); err != nil {
		return SlotDecision{}, err
	}
	quota, forQuota, err := organizationRoom(ctx, tx, host, agent, ticket, running)
	if err != nil {
		return SlotDecision{}, err
	}
	d := SlotDecision{Quota: quota}
	if quota == "" {
		// The organization's own VMs stopped for its quota free slots too.
		free += len(forQuota)
		if older < free {
			d = SlotDecision{Admit: true, EvictForQuota: forQuota}
		} else {
			others := make([]string, 0, len(running))
			for _, id := range running {
				if id != agent && !slices.Contains(forQuota, id) {
					others = append(others, id)
				}
			}
			stoppable, err := evictionOrder(ctx, tx, others, true)
			if err != nil {
				return SlotDecision{}, err
			}
			if older < free+len(stoppable) {
				d = SlotDecision{Admit: true, Evict: stoppable[0], EvictForQuota: forQuota}
			}
		}
	}
	if !d.Admit {
		reason := "capacity"
		if d.Quota != "" {
			reason = "organization_quota"
		}
		if ticket == nil {
			n, err := nextWorkTicket(ctx, tx, host)
			if err != nil {
				return SlotDecision{}, err
			}
			if _, err = tx.Exec(ctx, "INSERT INTO capacity_waits(agent_id,host_id,ticket,reason) VALUES($1,$2,$3,$4)", agent, host, n, reason); err != nil {
				return SlotDecision{}, err
			}
		} else if _, err = tx.Exec(ctx, `UPDATE capacity_waits SET reason=$3,since=clock_timestamp()
            WHERE agent_id=$1 AND host_id=$2 AND reason<>$3`, agent, host, reason); err != nil {
			// A change of reason restarts the wait's clock: the operator's
			// alert measures waits for the host alone. The ticket, its
			// place, stays.
			return SlotDecision{}, err
		}
	}
	return d, commit(ctx, tx)
}

// quotaWaiters defines "waiting": host $1's waiters, each with held, true
// while its organization's quotas leave no room for it and for the
// organization's older waiters on this host. Usage counts the organization's
// VMs booted for work on every host.
const quotaWaiters = `used AS (
    SELECT a.tenant_id,count(*) AS vms,sum(x.vcpus) AS vcpus,sum(x.memory_mib) AS memory
    FROM agent_placements p JOIN agents a ON a.id=p.agent_id JOIN agent_specs x ON x.agent_id=a.id
    WHERE a.tenant_id IN (SELECT tenant_id FROM organization_quotas) AND ` + workVMs + `
    GROUP BY a.tenant_id
  ), queued AS (
    SELECT w.agent_id,w.ticket,a.tenant_id,count(*) OVER o AS vms,
      sum(coalesce(x.vcpus,0)) OVER o AS vcpus,sum(coalesce(x.memory_mib,0)) OVER o AS memory
    FROM capacity_waits w JOIN agents a ON a.id=w.agent_id LEFT JOIN agent_specs x ON x.agent_id=w.agent_id
    WHERE w.host_id=$1
    WINDOW o AS (PARTITION BY a.tenant_id ORDER BY w.ticket)
  ), waiting AS (
    SELECT w.agent_id,w.ticket,coalesce(coalesce(u.vms,0)+w.vms>q.max_active_vms
      OR coalesce(u.vcpus,0)+w.vcpus>q.max_vcpus OR coalesce(u.memory,0)+w.memory>q.max_memory_mib,false) AS held
    FROM queued w LEFT JOIN organization_quotas q ON q.tenant_id=w.tenant_id LEFT JOIN used u ON u.tenant_id=w.tenant_id
  )`

// organizationRoom says whether agent's organization has room under its
// quotas for agent's boot on host, after its older waiters there. When it has
// none, it names the first quota exceeded; when agent is its organization's
// oldest waiter on host, it lists instead the organization's VMs among running
// that are not computing, the idle and least recently active first, whose
// stop makes the room.
func organizationRoom(ctx context.Context, tx pgx.Tx, host, agent string, ticket *int64, running []string) (string, []string, error) {
	var tenant *string
	var vcpus int
	var memory int64
	err := tx.QueryRow(ctx, `SELECT a.tenant_id,x.vcpus,x.memory_mib FROM agents a JOIN agent_specs x ON x.agent_id=a.id WHERE a.id=$1`, agent).Scan(&tenant, &vcpus, &memory)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && tenant == nil) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	q, set, err := organizationQuotas(ctx, tx, *tenant)
	if err != nil || set == nil || (q.MaxActiveVMs == nil && q.MaxVCPUs == nil && q.MaxMemoryMiB == nil) {
		return "", nil, err
	}
	u, err := organizationUsage(ctx, tx, *tenant, agent)
	if err != nil {
		return "", nil, err
	}
	var ahead, aheadVCPUs int
	var aheadMemory int64
	if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(x.vcpus),0),coalesce(sum(x.memory_mib),0)
        FROM capacity_waits w JOIN agents a ON a.id=w.agent_id JOIN agent_specs x ON x.agent_id=a.id
        WHERE w.host_id=$1 AND a.tenant_id=$2 AND w.agent_id<>$3 AND ($4::bigint IS NULL OR w.ticket<$4)`,
		host, *tenant, agent, ticket).Scan(&ahead, &aheadVCPUs, &aheadMemory); err != nil {
		return "", nil, err
	}
	vms, cpu, mem := u.ActiveVMs+ahead+1, u.VCPUs+aheadVCPUs+vcpus, u.MemoryMiB+aheadMemory+memory
	exceeded := func() string {
		return firstOf(overInt(q.MaxActiveVMs, vms, "max_active_vms"), overInt(q.MaxVCPUs, cpu, "max_vcpus"), over(q.MaxMemoryMiB, mem, "max_memory_mib"))
	}
	name := exceeded()
	if name == "" || ahead > 0 {
		return name, nil, nil
	}
	// The organization's oldest waiter here: its own VMs on this host that
	// are not computing may make the room.
	rows, err := tx.Query(ctx, `SELECT a.id,x.vcpus,x.memory_mib FROM agents a JOIN agent_specs x ON x.agent_id=a.id
        JOIN agent_placements p ON p.agent_id=a.id
        WHERE a.id=ANY($1) AND a.id<>$2 AND a.tenant_id=$3 AND p.host_id=$4 AND `+workVMs, running, agent, *tenant, host)
	if err != nil {
		return "", nil, err
	}
	type held struct {
		vcpus  int
		memory int64
	}
	mine := map[string]held{}
	var ids []string
	for rows.Next() {
		var id string
		var h held
		if err = rows.Scan(&id, &h.vcpus, &h.memory); err != nil {
			rows.Close()
			return "", nil, err
		}
		mine[id] = h
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return "", nil, err
	}
	order, err := evictionOrder(ctx, tx, ids, true)
	if err != nil {
		return "", nil, err
	}
	var stop []string
	for _, id := range order {
		stop = append(stop, id)
		vms, cpu, mem = vms-1, cpu-mine[id].vcpus, mem-mine[id].memory
		if exceeded() == "" {
			return "", stop, nil
		}
	}
	return name, nil, nil
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
// the oldest has waited, for the operator's metrics. Agents that wait for
// their organization's quota are not counted: QuotaWaits counts them.
func (s *Store) CapacityQueue(ctx context.Context, host string) (int, time.Duration, error) {
	var n int
	var oldest float64
	err := s.pool.QueryRow(ctx, `SELECT count(*),coalesce(extract(epoch FROM clock_timestamp()-min(since)),0)::float8
        FROM capacity_waits WHERE host_id=$1 AND reason='capacity'`, host).Scan(&n, &oldest)
	return n, time.Duration(oldest * float64(time.Second)), err
}

// QuotaWaits counts the agents of host whose work waits for their
// organization's quota (TEN-007).
func (s *Store) QuotaWaits(ctx context.Context, host string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM capacity_waits WHERE host_id=$1 AND reason='organization_quota'`, host).Scan(&n)
	return n, err
}

// ResumeDue reports whether agent, whose VM is not running, holds work in
// progress that its harness resumes once it boots again (the resume job).
func (s *Store) ResumeDue(ctx context.Context, agent string) (bool, error) {
	var due bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents a WHERE a.id=$1 AND `+resumeDue+`
        AND NOT EXISTS(SELECT 1 FROM agent_placements sp WHERE sp.agent_id=a.id AND sp.state='RUNNING' AND NOT sp.fence_only))`, agent).Scan(&due)
	return due, err
}

// evictionOrderQuery orders the agents $1 for stopping, leaving out those
// computing when $2 (evictionOrder).
var evictionOrderQuery = `SELECT a.id FROM agents a LEFT JOIN agent_specs x ON x.agent_id=a.id
        WHERE a.id=ANY($1) AND (NOT $2 OR NOT ` + computing + `)
        ORDER BY ` + computing + `,` + owesWork("clock_timestamp()") + `,` + lastActivity + `,a.id`

// evictionOrder orders running agents for stopping: idle first, then those
// that only wait, then those computing, unless forWork leaves those out.
func evictionOrder(ctx context.Context, tx pgx.Tx, running []string, forWork bool) ([]string, error) {
	if len(running) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, evictionOrderQuery, running, forWork)
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

// promoteCapacityHead makes available now the jobs of the oldest waiter for
// the host's capacity, and of each organization's oldest waiter for its
// quota: a slot or an organization's room may have freed.
func promoteCapacityHead(ctx context.Context, tx pgx.Tx, host string) error {
	_, err := tx.Exec(ctx, `UPDATE worker_jobs SET available_at=clock_timestamp()
        WHERE host_id=$1 AND lease_token='' AND available_at>clock_timestamp() AND kind IN ('delivery','lifecycle','resume')
          AND agent_id IN ((SELECT agent_id FROM capacity_waits WHERE host_id=$1 AND reason='capacity' ORDER BY ticket LIMIT 1)
            UNION (SELECT DISTINCT ON (a.tenant_id) w.agent_id FROM capacity_waits w JOIN agents a ON a.id=w.agent_id
                   WHERE w.host_id=$1 AND w.reason='organization_quota' ORDER BY a.tenant_id,w.ticket))`, host)
	return err
}
