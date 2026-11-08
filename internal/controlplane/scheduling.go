package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// nowArg lets tests drive the clock. In production now is nil and every
// comparison uses the database clock, the same one that stamps leases and
// deadlines, so a skewed worker host cannot release or stop early.
func nowArg(now *time.Time) any {
	if now == nil {
		return nil
	}
	return *now
}

const dbNow = `coalesce($1::timestamptz,clock_timestamp())`

// ReleaseDueInstructions turns scheduled instructions whose time has come into
// ordinary deliverable ones. It is safe to run from several workers and to
// repeat after a crash: each instruction is released exactly once, under its own
// row lock, and keeps the operation id it was given at admission. An instruction
// is never released before its due time.
func (s *Store) ReleaseDueInstructions(ctx context.Context, now *time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1024 {
		return 0, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT i.operation_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        WHERE i.run_at IS NOT NULL AND i.released_at IS NULL AND o.status='PENDING' AND i.run_at<=`+dbNow+`
        ORDER BY i.run_at,i.operation_id LIMIT $2`, nowArg(now), limit)
	if err != nil {
		return 0, err
	}
	var due []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	released := 0
	var result error
	for _, id := range due {
		ok, err := s.releaseOne(ctx, id, now)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if ok {
			released++
		}
	}
	return released, result
}

func (s *Store) releaseOne(ctx context.Context, op string, now *time.Time) (bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	var agentID string
	var ttl int64
	err = tx.QueryRow(ctx, `SELECT o.agent_id,i.ttl_micros FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        WHERE i.operation_id=$2 AND i.run_at IS NOT NULL AND i.released_at IS NULL AND o.status='PENDING' AND i.run_at<=`+dbNow+`
        FOR UPDATE OF i SKIP LOCKED`, nowArg(now), op).Scan(&agentID, &ttl)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // released, canceled or taken by another worker
	}
	if err != nil {
		return false, err
	}
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return false, err
	}
	a, ok := agents[agentID]
	if !ok || a.Phase != "LIVE" {
		// The agent is on its way out: the work will never run. Close it visibly
		// and drop the content instead of leaving it queued forever.
		if err = cancelScheduled(ctx, tx, op, "agent_unavailable"); err != nil {
			return false, err
		}
		return false, commit(ctx, tx)
	}
	var seq int64
	if err = tx.QueryRow(ctx, "UPDATE agents SET next_seq=next_seq+1 WHERE id=$1 AND next_seq<9223372036854775807 RETURNING next_seq", agentID).Scan(&seq); err != nil {
		return false, err
	}
	mbx := newID("mbx")
	if _, err = tx.Exec(ctx, `INSERT INTO agent_mailboxes(id,dest_agent_id,seq,kind,instruction_id,expires_at)
        VALUES($1,$2,$3,'instruction',$4,coalesce($6::timestamptz,clock_timestamp())+$5::bigint*interval '1 microsecond')`,
		mbx, agentID, seq, op, ttl, nowArg(now)); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES($1,$2)", newID("out"), mbx); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET released_at=clock_timestamp() WHERE operation_id=$1", op); err != nil {
		return false, err
	}
	return true, commit(ctx, tx)
}

// cancelScheduled closes a scheduled, unreleased instruction and destroys its
// stored content. Callers hold the row lock.
func cancelScheduled(ctx context.Context, tx pgx.Tx, op, code string) error {
	if _, err := tx.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code=$2,completed_at=clock_timestamp()
        WHERE id=$1 AND status='PENDING'`, op, code); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE owner_instructions SET released_at=clock_timestamp() WHERE operation_id=$1 AND released_at IS NULL`, op); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
        WHERE purged_at IS NULL AND id=(SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1)`, op)
	return err
}

// CancelInvocation cancels a scheduled invocation before it is released, or a
// "working" one before its agent posts the outcome. Only the requester who still
// holds the invoke right may. Queued or in-flight delivery is never interrupted
// from here: that is refused (409) rather than raced.
func (c *AgentCatalog) CancelInvocation(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentInvoke); err != nil {
		return APIReceipt{}, err
	}
	var agentID string
	err = tx.QueryRow(ctx, `SELECT o.agent_id FROM platform_operations o JOIN agents a ON a.id=o.agent_id
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction'`, id, p.TenantID, p.ID).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, agentID)
	if err != nil {
		return APIReceipt{}, err
	}
	if !authorization.CanAccessAssignedAgent(tenantAccess(p), authorization.InvokeAgent, toPermissions(perms)) {
		return APIReceipt{}, ErrNotFound
	}
	// Same agent-first lock order as admission and release.
	if _, err = lockAgents(ctx, tx, agentID); err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		Invocation string `json:"invocation_id"`
	}{id}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "invocation.cancel/"+id, key, in, func() (int, any, error) {
		var scheduled bool
		err := tx.QueryRow(ctx, `SELECT run_at IS NOT NULL AND released_at IS NULL FROM owner_instructions WHERE operation_id=$1 FOR UPDATE`, id).Scan(&scheduled)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrTransition
		}
		if err != nil {
			return 0, nil, err
		}
		if scheduled {
			if err = cancelScheduled(ctx, tx, id, "canceled"); err != nil {
				return 0, nil, err
			}
		} else if ok, err := cancelWorking(ctx, tx, id, "canceled"); err != nil {
			return 0, nil, err
		} else if !ok {
			// Queued for delivery, being delivered, or already finished: a
			// delivery in flight is never interrupted from here.
			return 0, nil, ErrTransition
		}
		v, err := scanInvocation(tx.QueryRow(ctx, invocationSelect+`WHERE o.id=$1`, id), false)
		return 200, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// SetIdlePolicy turns idle closure on (60 s to 7 days) or off (0) for one agent.
// It needs the same right as putting the agent to sleep, and the principal who
// sets it answers for the sleeps the policy later causes.
func (c *AgentCatalog) SetIdlePolicy(ctx context.Context, p Principal, id, key string, seconds int) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || seconds < 0 || (seconds != 0 && (seconds < 60 || seconds > 604800)) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.SleepAgent); err != nil {
		return APIReceipt{}, err
	}
	if _, _, err = tenantAgentForUpdate(ctx, tx, p, id); err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		AgentID string `json:"agent_id"`
		Seconds int    `json:"idle_timeout_seconds"`
	}{id, seconds}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.idle-policy/"+id, key, in, func() (int, any, error) {
		var by any
		var secs any
		if seconds > 0 {
			by, secs = p.ID, seconds
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_specs SET idle_timeout_seconds=$2,idle_policy_by=$3 WHERE agent_id=$1`, id, secs, by); err != nil {
			return 0, nil, err
		}
		if seconds == 0 {
			if _, err := tx.Exec(ctx, "DELETE FROM agent_idle_watch WHERE agent_id=$1", id); err != nil {
				return 0, nil, err
			}
		}
		if err := auditTenantAgent(ctx, tx, p, id, nil, "agent.idle_policy_set"); err != nil {
			return 0, nil, err
		}
		return 200, struct {
			AgentID string `json:"agent_id"`
			Seconds int    `json:"idle_timeout_seconds"`
		}{id, seconds}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// idleCandidates selects running tenant agents whose idle clock has elapsed and
// that owe no work. $1 now, $2 host, $3 agent filter (” for all). "Work" is any
// of: a delivery waiting for the agent, a lifecycle or instruction operation
// still open, an exchange with another agent not yet closed, a model call in
// flight, or a scheduled instruction due before the idle window would end.
const idleCandidates = `
SELECT a.id,x.idle_policy_by FROM agents a
  JOIN agent_specs x ON x.agent_id=a.id
  JOIN agent_placements p ON p.agent_id=a.id
  JOIN agent_idle_watch w ON w.agent_id=a.id AND w.generation=p.generation
 WHERE a.tenant_id IS NOT NULL AND a.phase='LIVE' AND x.idle_timeout_seconds IS NOT NULL AND p.host_id=$2
   AND p.state='RUNNING' AND NOT p.fence_only AND ($3='' OR a.id=$3)
   AND greatest(w.observed_at,
        coalesce((SELECT max(greatest(o.created_at,coalesce(o.completed_at,o.created_at))) FROM platform_operations o
                   WHERE o.agent_id=a.id AND o.kind IN ('wake','instruction')),w.observed_at),
        coalesce((SELECT max(greatest(r.created_at,coalesce(r.decided_at,r.created_at))) FROM agent_requests r
                   WHERE r.sender_agent_id=a.id OR r.recipient_agent_id=a.id),w.observed_at),
        coalesce((SELECT max(coalesce(u.settled_at,u.created_at)) FROM llm_usage u WHERE u.agent_id=a.id),w.observed_at))
       + x.idle_timeout_seconds*interval '1 second' <= ` + dbNow + `
   AND NOT EXISTS(SELECT 1 FROM agent_mailboxes m WHERE m.dest_agent_id=a.id AND m.delivery_state='PENDING')
   AND NOT EXISTS(SELECT 1 FROM platform_operations o LEFT JOIN owner_instructions i ON i.operation_id=o.id
                   WHERE o.agent_id=a.id AND o.status IN ('PENDING','RUNNING')
                     AND NOT (o.kind='instruction' AND i.run_at IS NOT NULL AND i.released_at IS NULL))
   AND NOT EXISTS(SELECT 1 FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
                   WHERE o.agent_id=a.id AND o.status='PENDING' AND i.run_at IS NOT NULL AND i.released_at IS NULL
                     AND i.run_at <= ` + dbNow + ` + x.idle_timeout_seconds*interval '1 second')
   AND NOT EXISTS(SELECT 1 FROM agent_requests r WHERE (r.sender_agent_id=a.id OR r.recipient_agent_id=a.id)
                     AND r.state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING') AND r.expires_at > ` + dbNow + `)
   AND NOT EXISTS(SELECT 1 FROM llm_usage u WHERE u.agent_id=a.id AND u.state='reserved')
 ORDER BY a.id LIMIT $4`

// ScheduleIdleSleeps asks agents with an idle policy and no work to go to sleep.
// It does not stop anything itself: it writes the ordinary sleep command, which
// the worker executes with the usual guest-acknowledged quiescence. Repeating it
// is harmless; an open lifecycle operation is itself "work", so there is at most
// one idle sleep in flight per agent.
func (s *Store) ScheduleIdleSleeps(ctx context.Context, host string, now *time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1024 || host == "" {
		return 0, ErrInput
	}
	if err := s.observeRunning(ctx, host, now); err != nil {
		return 0, err
	}
	rows, err := s.pool.Query(ctx, idleCandidates, nowArg(now), host, "", limit)
	if err != nil {
		return 0, err
	}
	type candidate struct{ id, by string }
	var found []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.by); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, c)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	var result error
	for _, c := range found {
		ok, err := s.idleSleepOne(ctx, host, c.id, now)
		if err != nil {
			result = errors.Join(result, err)
		} else if ok {
			n++
		}
	}
	return n, result
}

// observeRunning starts the idle clock of every newly running generation and
// forgets agents that are not running. The clock can only start late.
func (s *Store) observeRunning(ctx context.Context, host string, now *time.Time) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `DELETE FROM agent_idle_watch w WHERE w.agent_id IN (SELECT agent_id FROM agent_placements WHERE host_id=$1)
        AND NOT EXISTS(SELECT 1 FROM agent_placements p WHERE p.agent_id=w.agent_id AND p.state='RUNNING')`, host); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_idle_watch(agent_id,generation,observed_at)
        SELECT p.agent_id,p.generation,`+dbNow+` FROM agent_placements p JOIN agent_specs x ON x.agent_id=p.agent_id
        WHERE p.host_id=$2 AND p.state='RUNNING' AND NOT p.fence_only AND x.idle_timeout_seconds IS NOT NULL
        ON CONFLICT (agent_id) DO UPDATE SET generation=EXCLUDED.generation,observed_at=EXCLUDED.observed_at
        WHERE agent_idle_watch.generation<>EXCLUDED.generation`, nowArg(now), host); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// idleSleepOne re-checks every condition under the agent lock, the same lock
// admission takes, so an invocation that arrives meanwhile either lands first and
// keeps the agent awake or lands after and wakes it through ordinary delivery.
func (s *Store) idleSleepOne(ctx context.Context, host, id string, now *time.Time) (bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, id); err != nil {
		return false, err
	}
	var by string
	err = tx.QueryRow(ctx, `SELECT c.idle_policy_by FROM (`+idleCandidates+`) c`, nowArg(now), host, id, 1).Scan(&by)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var seq int64
	if err = tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
        WHERE agent_id=$1 AND next_operation_seq<9223372036854775807 RETURNING next_operation_seq`, id).Scan(&seq); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind,cause)
        VALUES($1,$2,$3,$4,$5,'sleep','idle_policy')`, newID("op"), by, id, host, seq); err != nil {
		return false, err
	}
	var tenant string
	if err = tx.QueryRow(ctx, "SELECT tenant_id FROM agents WHERE id=$1", id).Scan(&tenant); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action)
        VALUES($1,$2,$3,$4,'agent.idle_sleep_requested')`, newID("audit"), tenant, by, id); err != nil {
		return false, err
	}
	return true, commit(ctx, tx)
}
