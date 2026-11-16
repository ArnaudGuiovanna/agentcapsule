package controlplane

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Replays of dead letters (EVT-02, ADR 017, migration 0033). The operator, or
// an administrator of the agent's organization, puts an instruction that died
// without reaching its agent back in its agent's queue:
//
//   - under the same identifier and the same mailbox ID, which is the event ID
//     the agent deduplicates on, as a rerun does (ADR 003);
//   - with a new attempt budget;
//   - before its deadline, or with a new delivery window (ttl), counted from
//     the replay, at most 24 hours, as a rerun's;
//   - at the end of its agent's queue: the agent processed later work since,
//     and receives events in their queue order. A rerun keeps its place,
//     since the restore took back what came after it;
//   - with its mandate, if a rerun had created one: the same remaining budget,
//     valid again, its expiry moved to the new deadline;
//   - counted in the queue limits, like new work.
//
// A replay is refused, and nothing changes, when the dead letter may have
// reached its agent (outcome_unknown: the agent's store fenced its event for
// good, and another event ID could apply it twice), when its requester can no
// longer invoke the agent (requester_revoked), when its content or a file is
// no longer stored (input_purged, attachments_purged), when its deadline
// passed and no new window is given (ErrExpired), when the agent is being
// deleted (ErrUnavailable), and when it is not a dead letter (ErrTransition).
// Each replay is recorded in instruction_replays: who, when, how the
// instruction had died and its new deadline.

// Why a dead letter cannot be replayed, besides the rerun's skip reasons.
const ReplayOutcomeUnknown = "outcome_unknown"

// ReplayRefusal names why a dead letter cannot be replayed. The API answers
// 409 with the reason as its code.
type ReplayRefusal struct{ Reason string }

func (e *ReplayRefusal) Error() string { return "dead letter cannot be replayed: " + e.Reason }

// ReplayInput is the body of a replay. TTLSeconds gives the replay a new
// delivery window counted from now (1 to 86400); without it the instruction
// keeps its deadline, which must not have passed.
type ReplayInput struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// Replay is what a replay did: the instruction, now pending again, and its
// deadline.
type Replay struct {
	OperationID string    `json:"operation_id"`
	AgentID     string    `json:"agent_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	ReplayedAt  time.Time `json:"replayed_at"`
	// Replayed is set when the same key already replayed it: nothing changed.
	Replayed bool `json:"-"`
}

type replayActor struct {
	operator  bool
	principal string
}

func (in ReplayInput) window() (time.Duration, error) {
	if in.TTLSeconds == 0 {
		return 0, nil
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds < 0 || ttl < MinInstructionTTL || ttl > MaxInstructionTTL {
		return 0, ErrInput
	}
	return ttl, nil
}

// ReplayDeadInstruction is the operator's replay (agentcapsule-admin
// replay-dead-letter). The key makes it idempotent: the same key for the same
// instruction returns the first replay and changes nothing.
func (s *Store) ReplayDeadInstruction(ctx context.Context, operation, key string, in ReplayInput) (Replay, error) {
	ttl, err := in.window()
	if err != nil || !validOrganizationText(operation, 100) || key == "" || len(key) > 200 {
		return Replay{}, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Replay{}, err
	}
	defer rollback(tx)
	var agentID string
	err = tx.QueryRow(ctx, "SELECT agent_id FROM platform_operations WHERE id=$1 AND kind='instruction'", operation).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Replay{}, ErrNotFound
	}
	if err != nil {
		return Replay{}, err
	}
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return Replay{}, err
	}
	a, ok := agents[agentID]
	if !ok {
		return Replay{}, ErrNotFound
	}
	var done Replay
	err = tx.QueryRow(ctx, `SELECT operation_id,agent_id,expires_at,replayed_at FROM instruction_replays
        WHERE operation_id=$1 AND actor_kind='operator' AND request_key=$2`, operation, key).Scan(&done.OperationID, &done.AgentID, &done.ExpiresAt, &done.ReplayedAt)
	if err == nil {
		done.Replayed = true
		return done, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Replay{}, err
	}
	r, err := replayDeadInstruction(ctx, tx, a, operation, ttl, replayActor{operator: true}, key)
	if err != nil {
		return Replay{}, err
	}
	return r, commit(ctx, tx)
}

// ReplayInvocation is the organization's replay: an owner or administrator
// (quota:manage, the right that manages the organization's queues) puts a
// dead letter of one of its agents back in the queue. It grants no access to
// the content, which stays bound to its requester, and the requester must
// still hold the right to invoke the agent (D-02).
func (c *AgentCatalog) ReplayInvocation(ctx context.Context, p Principal, id, key string, in ReplayInput) (APIReceipt, error) {
	ttl, err := in.window()
	if err != nil {
		return APIReceipt{}, err
	}
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	var agentID string
	err = tx.QueryRow(ctx, `SELECT o.agent_id FROM platform_operations o JOIN agents a ON a.id=o.agent_id
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.kind='instruction'`, id, p.TenantID).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return APIReceipt{}, err
	}
	a, ok := agents[agentID]
	if !ok {
		return APIReceipt{}, ErrNotFound
	}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "invocation.replay/"+id, key, in, func() (int, any, error) {
		if _, err := replayDeadInstruction(ctx, tx, a, id, ttl, replayActor{principal: p.ID}, key); err != nil {
			return 0, nil, err
		}
		v, err := scanInvocation(tx.QueryRow(ctx, invocationSelect+`WHERE o.id=$1`, id), true)
		return 202, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// replayDeadInstruction puts dead letter op back in the queue of agent a,
// whose lock the caller holds.
func replayDeadInstruction(ctx context.Context, tx pgx.Tx, a agent, op string, ttl time.Duration, actor replayActor, key string) (Replay, error) {
	var mailbox, state, mandate, input, reason, status, requester string
	var reached bool
	var deadline, now time.Time
	err := tx.QueryRow(ctx, `SELECT m.id,m.delivery_state,m.may_have_reached,m.expires_at,coalesce(i.mandate_id,''),i.input_payload_id,
            i.close_reason,o.status,coalesce(o.owner_user_id,o.requested_by_principal_id,''),clock_timestamp()
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN platform_operations o ON o.id=i.operation_id
        WHERE o.id=$1 AND o.agent_id=$2 AND m.dest_agent_id=$2 FOR UPDATE OF m,i,o`, op, a.ID).
		Scan(&mailbox, &state, &reached, &deadline, &mandate, &input, &reason, &status, &requester, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return Replay{}, ErrTransition
	}
	if err != nil {
		return Replay{}, err
	}
	if state != "DEAD" || status != "FAILED" || reason == "" {
		return Replay{}, ErrTransition
	}
	if reached {
		return Replay{}, &ReplayRefusal{ReplayOutcomeUnknown}
	}
	if a.Phase != "LIVE" {
		return Replay{}, ErrUnavailable
	}
	if ok, err := mayInvokeAgain(ctx, tx, a, requester); err != nil {
		return Replay{}, err
	} else if !ok {
		return Replay{}, &ReplayRefusal{SkipRequesterRevoked}
	}
	var purged bool
	if err = tx.QueryRow(ctx, "SELECT purged_at IS NOT NULL FROM transit_payloads WHERE id=$1 FOR UPDATE", input).Scan(&purged); err != nil {
		return Replay{}, err
	}
	if purged {
		return Replay{}, &ReplayRefusal{SkipInputPurged}
	}
	if gone, err := attachmentsGone(ctx, tx, op); err != nil {
		return Replay{}, err
	} else if gone != "" {
		return Replay{}, &ReplayRefusal{gone}
	}
	if ttl > 0 {
		deadline = now.Add(ttl)
	} else if !deadline.After(now) {
		return Replay{}, ErrExpired
	}
	if a.Tenant != "" {
		if err = checkQueueRoom(ctx, tx, a.Tenant, a.ID); err != nil {
			return Replay{}, err
		}
	}
	var seq int64
	if err = tx.QueryRow(ctx, "UPDATE agents SET next_seq=next_seq+1 WHERE id=$1 AND next_seq<$2 RETURNING next_seq", a.ID, int64(math.MaxInt64)).Scan(&seq); err != nil {
		return Replay{}, err
	}
	if err = tx.QueryRow(ctx, `UPDATE agent_mailboxes SET delivery_state='PENDING',seq=$2,attempts=0,lease_token='',lease_until=NULL,
        dispatch_authorized=false,closing=false,expires_at=$3 WHERE id=$1 RETURNING expires_at`, mailbox, seq, deadline).Scan(&deadline); err != nil {
		return Replay{}, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES($1,$2) ON CONFLICT (mailbox_id) DO NOTHING", newID("out"), mailbox); err != nil {
		return Replay{}, err
	}
	if mandate != "" {
		if _, err = tx.Exec(ctx, "UPDATE mandates SET valid=true,expires_at=$2 WHERE id=$1 AND origin_event_id=$3", mandate, deadline, mailbox); err != nil {
			return Replay{}, err
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='PENDING',error_code='',completed_at=NULL WHERE id=$1", op); err != nil {
		return Replay{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE owner_instructions SET working_since=NULL,result_due_at=NULL,completion_key=NULL,
        completion_hash=NULL,close_reason='' WHERE operation_id=$1`, op); err != nil {
		return Replay{}, err
	}
	if err = holdInput(ctx, tx, input); err != nil {
		return Replay{}, err
	}
	kind, principal := "principal", &actor.principal
	if actor.operator {
		kind, principal = "operator", nil
	}
	tenant := &a.Tenant
	if a.Tenant == "" {
		tenant = nil
	}
	r := Replay{OperationID: op, AgentID: a.ID, ExpiresAt: deadline}
	err = tx.QueryRow(ctx, `INSERT INTO instruction_replays(id,operation_id,agent_id,tenant_id,actor_kind,actor_principal_id,request_key,previous_reason,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING replayed_at`, newID("rpl"), op, a.ID, tenant, kind, principal, key, reason, deadline).Scan(&r.ReplayedAt)
	return r, err
}
