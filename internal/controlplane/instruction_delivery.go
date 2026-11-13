package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

type InstructionRuntime interface {
	DeliveryRuntime
	Invoke(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error)
}

type InstructionAttempt struct {
	ID, OperationID, Destination, Token string
}

type instructionRow struct {
	mailboxRow
	Operation, Input, Mandate, Status string
	// Requester is the identity the private content is bound to: the owner user
	// of a historical agent, or the requesting principal of a tenant agent.
	Requester string
	Budget    int
}

// Every writer takes the agent before its mailbox/operation. No SQL lock spans
// an RPC. The worker owns execution admission independently of these leases.
func lockInstruction(ctx context.Context, tx pgx.Tx, id string) (instructionRow, agent, error) {
	var i instructionRow
	i.ID = id
	var destination string
	err := tx.QueryRow(ctx, "SELECT dest_agent_id FROM agent_mailboxes WHERE id=$1 AND kind='instruction'", id).Scan(&destination)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNoDelivery
	}
	if err != nil {
		return i, agent{}, err
	}
	agents, err := lockAgents(ctx, tx, destination)
	if err != nil {
		return i, agent{}, err
	}
	a, ok := agents[destination]
	if !ok {
		return i, a, ErrNotFound
	}
	var owner, target string
	err = tx.QueryRow(ctx, `SELECT m.dest_agent_id,m.kind,m.delivery_state,m.seq,m.attempts,m.attempt_limit,
        m.lease_token,m.lease_until,m.closing,m.expires_at,m.may_have_reached,
        i.operation_id,i.input_payload_id,coalesce(i.mandate_id,''),i.max_agent_requests,
        o.status,coalesce(o.owner_user_id,o.requested_by_principal_id,''),o.agent_id
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN platform_operations o ON o.id=i.operation_id
        WHERE m.id=$1 AND m.kind='instruction' AND o.kind='instruction' FOR UPDATE OF m,i,o`, id).
		Scan(&i.Destination, &i.Kind, &i.State, &i.Sequence, &i.Attempts, &i.Limit,
			&i.Token, &i.LeaseUntil, &i.Closing, &i.Deadline, &i.MayHaveReached,
			&i.Operation, &i.Input, &i.Mandate, &i.Budget, &i.Status, &owner, &target)
	if err != nil {
		return i, a, err
	}
	if i.Destination != destination || target != destination || owner == "" {
		return i, a, ErrTransition
	}
	if a.Tenant == "" && owner != a.Owner {
		return i, a, ErrTransition
	}
	if a.Tenant != "" {
		var known bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals WHERE tenant_id=$1 AND id=$2)`, a.Tenant, owner).Scan(&known); err != nil {
			return i, a, err
		}
		if !known {
			return i, a, ErrTransition
		}
	}
	i.Requester = owner
	return i, a, nil
}

// ClaimInstruction consumes an attempt before any permission to invoke. It does
// not create a grant: a failed boot or unclaimed instruction has no mandate.
func (t *Transit) ClaimInstruction(ctx context.Context, id string, lease time.Duration) (InstructionAttempt, error) {
	var attempt InstructionAttempt
	if lease < time.Microsecond {
		return attempt, ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return attempt, err
	}
	defer rollback(tx)
	i, a, err := lockInstruction(ctx, tx, id)
	if err != nil {
		return attempt, err
	}
	if err = isHead(ctx, tx, i.mailboxRow); err != nil {
		return attempt, err
	}
	if a.Phase != "LIVE" {
		return attempt, ErrUnavailable
	}
	if i.Status != "PENDING" && i.Status != "RUNNING" {
		return attempt, ErrTransition
	}
	if i.Closing {
		return attempt, ErrDeliveryClosing
	}
	// The rerun of a lost invocation is due only while its requester may
	// still invoke the agent. Checked before any attempt, so nothing is sent.
	if skipped, err := t.skipRevokedRerun(ctx, tx, i, a); err != nil {
		return attempt, err
	} else if skipped {
		if err = commit(ctx, tx); err != nil {
			return attempt, err
		}
		return attempt, ErrRerunSkipped
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return attempt, err
	}
	if !i.Deadline.After(now) {
		return attempt, ErrExpired
	}
	if i.LeaseUntil != nil && i.LeaseUntil.After(now) {
		return attempt, ErrDeliveryBusy
	}
	if i.Attempts >= i.Limit {
		return attempt, ErrAttemptsExhausted
	}
	token := newID("lease")
	if _, err = tx.Exec(ctx, `UPDATE agent_mailboxes SET attempts=attempts+1,lease_token=$2,dispatch_authorized=false,
        lease_until=clock_timestamp()+$3::bigint*interval '1 microsecond' WHERE id=$1`, id, token, lease.Microseconds()); err != nil {
		return attempt, err
	}
	if _, err = tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1 WHERE mailbox_id=$1", id); err != nil {
		return attempt, err
	}
	if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='RUNNING' WHERE id=$1", i.Operation); err != nil {
		return attempt, err
	}
	attempt = InstructionAttempt{ID: id, OperationID: i.Operation, Destination: i.Destination, Token: token}
	return attempt, commit(ctx, tx)
}

// AuthorizeInstruction commits the possibility of an effect and creates the
// single stable grant before returning an envelope. Reauthorization never resets
// remaining, validity or expiry. The guest cannot replenish its own authority.
func (t *Transit) AuthorizeInstruction(ctx context.Context, id, token string) (harnessstore.Event, error) {
	var event harnessstore.Event
	if token == "" {
		return event, ErrLeaseLost
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return event, err
	}
	defer rollback(tx)
	i, a, err := lockInstruction(ctx, tx, id)
	if err != nil {
		return event, err
	}
	if a.Phase != "LIVE" {
		return event, ErrUnavailable
	}
	if err = isHead(ctx, tx, i.mailboxRow); err != nil {
		return event, err
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT lease_token=$2 AND lease_until>clock_timestamp() AND NOT closing
        AND expires_at>clock_timestamp() FROM agent_mailboxes WHERE id=$1`, id, token).Scan(&current)
	if err != nil {
		return event, err
	}
	if !current {
		return event, ErrLeaseLost
	}
	// Verify exact input ownership before reading; do not acquire arbitrary
	// additional agent locks from a malformed/misbound payload reference.
	var bound bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM transit_payloads p WHERE p.id=$1 AND p.kind='instruction' AND p.ref_id=$2)
        AND (SELECT count(*)=1 FROM transit_parties WHERE payload_id=$1)
        AND EXISTS(SELECT 1 FROM transit_parties WHERE payload_id=$1 AND agent_id=$3 AND owner_user_id=$4)`,
		i.Input, i.Operation, i.Destination, i.Requester).Scan(&bound)
	if err != nil {
		return event, err
	}
	if !bound {
		return event, ErrTransitPayload
	}
	body, err := t.read(ctx, tx, i.Input, []transitParty{{Agent: i.Destination, Owner: i.Requester}})
	if err != nil {
		return event, err
	}
	defer clear(body)
	var input OwnerInstruction
	if json.Unmarshal(body, &input) != nil || input.Validate() != nil {
		return event, ErrTransitPayload
	}
	if i.Mandate == "" {
		i.Mandate = newID("mdt")
		if _, err = tx.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
            VALUES($1,$2,$3,$4,$4,$5)`, i.Mandate, i.Destination, i.ID, i.Budget, i.Deadline); err != nil {
			return event, err
		}
		if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET mandate_id=$2 WHERE operation_id=$1", i.Operation, i.Mandate); err != nil {
			return event, err
		}
	}
	grant := capsuleprotocol.InstructionMandate{ID: i.Mandate}
	err = tx.QueryRow(ctx, `SELECT max_requests,expires_at FROM mandates WHERE id=$1 AND agent_id=$2 AND origin_event_id=$3`,
		i.Mandate, i.Destination, i.ID).Scan(&grant.MaxAgentRequests, &grant.ExpiresAt)
	if err != nil {
		return event, err
	}
	if grant.MaxAgentRequests != i.Budget || !grant.ExpiresAt.Equal(i.Deadline) {
		return event, ErrTransition
	}
	// The guest learns which files were sent and reads them over the platform
	// channel while this invocation runs; their bytes never ride in the envelope.
	refs, err := attachmentRefs(ctx, tx, i.Operation)
	if err != nil {
		return event, err
	}
	encoded, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: i.Operation, Mandate: grant, Content: input.Content, Attachments: refs})
	if err != nil {
		return event, err
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET dispatch_authorized=true,may_have_reached=true
        WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() AND NOT closing`, id, token)
	if err != nil {
		clear(encoded)
		return event, err
	}
	if tag.RowsAffected() != 1 {
		clear(encoded)
		return event, ErrLeaseLost
	}
	if err = commit(ctx, tx); err != nil {
		clear(encoded)
		return event, err
	}
	return harnessstore.Event{ID: id, Subjects: []string{"agent/" + i.Destination, "event/" + id}, Body: encoded}, nil
}

// AcknowledgeInstruction publishes encrypted result, terminal operation and FIFO
// advancement in one commit. A lost/stale ACK cannot replace an existing result.
func (t *Transit) AcknowledgeInstruction(ctx context.Context, id, token string, result []byte) error {
	if token == "" {
		return ErrLeaseLost
	}
	if len(result) > capsuleprotocol.MaxContentBytes || !json.Valid(result) {
		return ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	i, a, err := lockInstruction(ctx, tx, id)
	if err != nil {
		return err
	}
	if a.Phase != "LIVE" {
		return ErrUnavailable
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT lease_token=$2 AND lease_until>clock_timestamp() AND delivery_state='PENDING'
        AND NOT closing AND dispatch_authorized FROM agent_mailboxes WHERE id=$1`, id, token).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return ErrLeaseLost
	}
	if i.Status != "RUNNING" || i.Mandate == "" {
		return ErrTransition
	}
	if capsuleprotocol.IsWorkingResult(result) {
		// Delivered, not finished: the agent will post the outcome later over the
		// platform channel, which it cannot use during this exclusive delivery.
		// The operation stays RUNNING until then, or until result_due_at.
		if _, err = tx.Exec(ctx, `UPDATE owner_instructions SET working_since=clock_timestamp(),
            result_due_at=clock_timestamp()+work_timeout_seconds*interval '1 second' WHERE operation_id=$1`, i.Operation); err != nil {
			return err
		}
	} else {
		payload, err := t.putResult(ctx, tx, i.Operation, i.Destination, i.Requester, result)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET result_payload_id=$2 WHERE operation_id=$1", i.Operation, payload.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1", i.Operation); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='DELIVERED',lease_token='',lease_until=NULL WHERE id=$1", id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM outbox WHERE mailbox_id=$1", id); err != nil {
		return err
	}
	if err = t.delivered(ctx, tx, i.Input); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// RetireInstruction fences even an uncertain delayed RPC before releasing FIFO.
// Revoking its mandate prevents future new requests; already committed requests
// retain their own lifecycle. A timeout never asserts the absence of an effect.
func (t *Transit) RetireInstruction(ctx context.Context, id string, runtime RevocationRuntime) error {
	if runtime == nil {
		return ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	i, _, err := lockInstruction(ctx, tx, id)
	if err != nil {
		return err
	}
	if i.State != "PENDING" {
		return commit(ctx, tx)
	}
	if err = isHead(ctx, tx, i.mailboxRow); err != nil {
		return err
	}
	var due bool
	err = tx.QueryRow(ctx, `SELECT closing OR expires_at<=clock_timestamp() OR
        (attempts>=attempt_limit AND (lease_until IS NULL OR lease_until<=clock_timestamp())) FROM agent_mailboxes WHERE id=$1`, id).Scan(&due)
	if err != nil {
		return err
	}
	if !due {
		return ErrTransition
	}
	if _, err = tx.Exec(ctx, "UPDATE agent_mailboxes SET closing=true WHERE id=$1", id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE mandates SET valid=false WHERE id=$1", i.Mandate); err != nil {
		return err
	}
	if err = publishRevocation(ctx, tx, "event/"+id); err != nil {
		return err
	}
	if err = commit(ctx, tx); err != nil {
		return err
	}
	if err = runtime.Fence(ctx, i.Destination, "event/"+id); err != nil {
		return err
	}
	return commitBarrier(ctx, runtime, "event/"+id, []string{i.Destination}, func() error {
		finish, err := t.store.begin(ctx)
		if err != nil {
			return err
		}
		defer rollback(finish)
		i, _, err = lockInstruction(ctx, finish, id)
		if err != nil {
			return err
		}
		if i.State == "PENDING" && i.Closing {
			code := "delivery_failed"
			if i.MayHaveReached {
				code = "delivery_outcome_unknown"
			}
			if _, err = finish.Exec(ctx, "UPDATE platform_operations SET status='FAILED',error_code=$2,completed_at=clock_timestamp() WHERE id=$1 AND status IN ('PENDING','RUNNING')", i.Operation, code); err != nil {
				return err
			}
			// Expiry wins when both hold: time is what the requester chose.
			if _, err = finish.Exec(ctx, `UPDATE owner_instructions SET close_reason=(SELECT CASE
                WHEN expires_at<=clock_timestamp() THEN 'expired' WHEN attempts>=attempt_limit THEN 'attempts_exhausted' ELSE 'closed' END
                FROM agent_mailboxes WHERE id=$2) WHERE operation_id=$1`, i.Operation, id); err != nil {
				return err
			}
			if _, err = finish.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='DEAD',lease_token='',lease_until=NULL WHERE id=$1", id); err != nil {
				return err
			}
			if _, err = finish.Exec(ctx, "DELETE FROM outbox WHERE mailbox_id=$1", id); err != nil {
				return err
			}
			if err = t.delivered(ctx, finish, i.Input); err != nil {
				return err
			}
		}
		return commit(ctx, finish)
	})
}

// DispatchMailbox routes the exact durable job, preserving the shared FIFO with
// request/reply/status deliveries. Preparation failures consume no attempt.
func (t *Transit) DispatchMailbox(ctx context.Context, id string, lease time.Duration, runtime InstructionRuntime) error {
	if runtime == nil {
		return ErrInput
	}
	var destination, kind, state string
	err := t.store.pool.QueryRow(ctx, "SELECT dest_agent_id,kind,delivery_state FROM agent_mailboxes WHERE id=$1", id).Scan(&destination, &kind, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoDelivery
	}
	if err != nil {
		return err
	}
	if state != "PENDING" {
		return ErrNoDelivery
	}
	if kind != "instruction" {
		return t.store.dispatchMailboxWithTransit(ctx, destination, id, lease, runtime, t)
	}
	retire := false
	dispatch := func(ctx context.Context) error {
		a, err := t.ClaimInstruction(ctx, id, lease)
		if errors.Is(err, ErrExpired) || errors.Is(err, ErrAttemptsExhausted) || errors.Is(err, ErrDeliveryClosing) {
			retire = true
			return nil
		}
		if errors.Is(err, ErrRerunSkipped) {
			return nil
		}
		if err != nil {
			return err
		}
		e, err := t.AuthorizeInstruction(ctx, a.ID, a.Token)
		if err != nil {
			return err
		}
		defer clear(e.Body)
		r, err := runtime.Invoke(ctx, a.Destination, e)
		defer clear(r.Result)
		if err != nil {
			return err
		}
		return t.AcknowledgeInstruction(ctx, a.ID, a.Token, r.Result)
	}
	if admission, ok := runtime.(PreparedDeliveryAdmission); ok {
		err = admission.WithPreparedDelivery(ctx, destination, dispatch)
	} else if admission, ok := runtime.(DeliveryAdmission); ok {
		err = admission.WithDeliveryAdmission(ctx, dispatch)
	} else {
		err = dispatch(ctx)
	}
	if err != nil {
		return err
	}
	if retire {
		return t.RetireInstruction(ctx, id, runtime)
	}
	return nil
}
