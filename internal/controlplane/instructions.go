package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

type TextContent = capsuleprotocol.TextContent
type OwnerInstruction = capsuleprotocol.OwnerMessage

// Instruct commits encrypted content, operation, shared FIFO mailbox/outbox and
// the original HTTP receipt atomically. Authentication is rechecked before any
// replay. Admission creates no mandate; first authorized delivery owns that
// transition and must never replenish the grant on a retry.
func (c *AgentCatalog) Instruct(ctx context.Context, p Principal, id, key string, in OwnerInstruction) (APIReceipt, error) {
	if in.Validate() != nil {
		return APIReceipt{}, ErrInput
	}
	if c.transit == nil {
		return APIReceipt{}, ErrTransitKey
	}
	if p.Kind == "tenant" {
		return c.instructTenant(ctx, p, id, key, in)
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	scope := scope(p, "POST", "/v1/agents/"+id+"/messages", key)
	if err = lockHTTPReceipt(ctx, tx, scope); err != nil {
		return APIReceipt{}, err
	}
	if err = authorizePrincipal(ctx, tx, p, "user", "agent:own"); err != nil {
		return APIReceipt{}, err
	}
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return APIReceipt{}, err
	}
	a, ok := agents[id]
	if !ok || a.Owner != p.ID {
		return APIReceipt{}, ErrNotFound
	}
	var host string
	err = tx.QueryRow(ctx, "SELECT host_id FROM agent_specs WHERE agent_id=$1", id).Scan(&host)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withReceipt(ctx, tx, scope, in, func() (int, any, error) {
		return c.enqueueInstruction(ctx, tx, a, id, host, a.Owner, in, DefaultInstructionTTL, nil)
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// InstructionResult returns only a completed private result to its current
// authenticated owner. Administrative operation-status access grants no data
// access. Reading does not reset the original post-delivery retention deadline.
func (c *AgentCatalog) InstructionResult(ctx context.Context, p Principal, operation string) (json.RawMessage, error) {
	if c.transit == nil {
		return nil, ErrTransitKey
	}
	if p.Kind == "tenant" {
		return c.instructionResultTenant(ctx, p, operation)
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", "agent:own"); err != nil {
		return nil, err
	}
	var payload string
	err = tx.QueryRow(ctx, `SELECT i.result_payload_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        JOIN transit_payloads payload ON payload.id=i.result_payload_id AND payload.kind='instruction_result' AND payload.ref_id=o.id
        WHERE o.id=$1 AND o.owner_user_id=$2 AND o.kind='instruction' AND o.status='SUCCEEDED' AND i.result_payload_id IS NOT NULL`, operation, p.ID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	parties, err := payloadParties(ctx, tx, payload)
	if err != nil {
		return nil, err
	}
	if len(parties) != 1 || parties[0].Owner != p.ID {
		return nil, ErrNotFound
	}
	body, err := c.transit.read(ctx, tx, payload, parties)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		clear(body)
		return nil, ErrTransitPayload
	}
	if err = c.transit.delivered(ctx, tx, payload); err != nil {
		clear(body)
		return nil, err
	}
	if err = commit(ctx, tx); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

// enqueueInstruction is the transactional core shared by both domains: it records
// the operation, the encrypted content bound to the requester, and the FIFO
// mailbox and outbox entries. The caller holds the agent lock and has already
// authorized the requester and recorded the HTTP receipt.
func (c *AgentCatalog) enqueueInstruction(ctx context.Context, tx pgx.Tx, a agent, id, host, requester string, in OwnerInstruction, ttl time.Duration, runAt *time.Time) (int, any, error) {
	if a.Phase != "LIVE" {
		return 0, nil, ErrUnavailable
	}
	if a.Tenant != "" {
		if err := checkQueueRoom(ctx, tx, a.Tenant, id); err != nil {
			return 0, nil, err
		}
	}
	body, err := json.Marshal(in)
	if err != nil {
		return 0, nil, err
	}
	defer clear(body)
	var seq int64
	err = tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
            WHERE agent_id=$1 AND next_operation_seq<$2 RETURNING next_operation_seq`, id, int64(math.MaxInt64)).Scan(&seq)
	if err != nil {
		return 0, nil, err
	}
	op := newID("op")
	owner, principal := &a.Owner, (*string)(nil)
	if a.Tenant != "" {
		owner, principal = nil, &requester
	}
	if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,owner_user_id,requested_by_principal_id,agent_id,host_id,seq,kind)
            VALUES($1,$2,$3,$4,$5,$6,'instruction')`, op, owner, principal, id, host, seq); err != nil {
		return 0, nil, err
	}
	payload, err := c.transit.putOwned(ctx, tx, "instruction", op, []string{id}, map[string]string{id: requester}, body)
	if err != nil {
		return 0, nil, err
	}
	var ttlMicros *int64
	if runAt != nil {
		v := ttl.Microseconds()
		ttlMicros = &v
	}
	if _, err = tx.Exec(ctx, "INSERT INTO owner_instructions(operation_id,input_payload_id,run_at,ttl_micros) VALUES($1,$2,$3,$4)", op, payload.ID, runAt, ttlMicros); err != nil {
		return 0, nil, err
	}
	if runAt != nil {
		// Scheduled: identity and content exist now, delivery is created at the
		// due time by ReleaseDueInstructions so the FIFO is never blocked.
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
	}
	if err = tx.QueryRow(ctx, "UPDATE agents SET next_seq=next_seq+1 WHERE id=$1 AND next_seq<$2 RETURNING next_seq", id, int64(math.MaxInt64)).Scan(&seq); err != nil {
		return 0, nil, err
	}
	mbx := newID("mbx")
	if _, err = tx.Exec(ctx, `INSERT INTO agent_mailboxes(id,dest_agent_id,seq,kind,instruction_id,expires_at)
            VALUES($1,$2,$3,'instruction',$4,clock_timestamp()+$5::bigint*interval '1 microsecond')`, mbx, id, seq, op, ttl.Microseconds()); err != nil {
		return 0, nil, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES($1,$2)", newID("out"), mbx); err != nil {
		return 0, nil, err
	}
	return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
}
