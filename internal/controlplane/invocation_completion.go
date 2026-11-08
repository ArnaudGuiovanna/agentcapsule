package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

// Invocations acknowledged "working" end in exactly one of four ways, each under
// the same row locks (agent, then instruction and operation):
//   - the destination agent posts the outcome (CompleteInvocationFromVM);
//   - result_due_at passes first (ExpireWorkingInvocations): FAILED work_timeout;
//   - the requester cancels it (CancelInvocation): CANCELED;
//   - the agent is deleted (requestDeletion): CANCELED agent_unavailable.
// Whichever commits first wins; the others then see a terminal operation.

const (
	MinWorkTimeout = time.Minute
	MaxWorkTimeout = 24 * time.Hour
)

// workingFilter selects instructions waiting for their agent's outcome.
const workingFilter = `i.working_since IS NOT NULL AND i.completion_key IS NULL AND o.status='RUNNING'`

// CompleteInvocationFromVM records the later outcome of a "working" invocation.
// Only the destination agent's current boot may post it, once, before its due
// time. The same key and body replay the receipt; anything else is refused.
func (t *Transit) CompleteInvocationFromVM(ctx context.Context, caller VMCaller, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	var out capsuleprotocol.CompletionReceipt
	if requireIdentity(caller.AgentID, key) != nil || len(key) > 256 || in.Validate() != nil {
		return out, ErrInput
	}
	body, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	hash := sha256.Sum256(body)
	clear(body)
	tx, err := t.store.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return out, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return out, err
	}
	var status, requester string
	var working, due bool
	var oldKey *string
	var oldHash []byte
	err = tx.QueryRow(ctx, `SELECT o.status,coalesce(o.owner_user_id,o.requested_by_principal_id,''),i.working_since IS NOT NULL,
            coalesce(i.result_due_at<=clock_timestamp(),false),i.completion_key,i.completion_hash
        FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        WHERE i.operation_id=$1 AND o.agent_id=$2 AND o.kind='instruction' FOR UPDATE OF i,o`, in.OperationID, caller.AgentID).
		Scan(&status, &requester, &working, &due, &oldKey, &oldHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.OperationID = in.OperationID
	if oldKey != nil {
		if *oldKey != key || !bytes.Equal(oldHash, hash[:]) {
			return capsuleprotocol.CompletionReceipt{}, ErrConflict
		}
		out.State, out.Replayed = in.Outcome, true
		return out, commit(ctx, tx)
	}
	switch {
	case !working:
		return capsuleprotocol.CompletionReceipt{}, ErrTransition // answered at delivery, or not delivered
	case status == "FAILED":
		return capsuleprotocol.CompletionReceipt{}, ErrExpired
	case status != "RUNNING":
		return capsuleprotocol.CompletionReceipt{}, ErrTransition // canceled
	case due:
		return capsuleprotocol.CompletionReceipt{}, ErrExpired
	}
	if in.Outcome == "completed" {
		result, err := json.Marshal(capsuleprotocol.OwnerMessage{Content: in.Content})
		if err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
		payload, err := t.putOwned(ctx, tx, "instruction_result", in.OperationID, []string{caller.AgentID}, map[string]string{caller.AgentID: requester}, result)
		clear(result)
		if err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
		if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET result_payload_id=$2 WHERE operation_id=$1", in.OperationID, payload.ID); err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
		_, err = tx.Exec(ctx, "UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1", in.OperationID)
		if err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
	} else if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='FAILED',error_code='agent_failed',completed_at=clock_timestamp() WHERE id=$1", in.OperationID); err != nil {
		return capsuleprotocol.CompletionReceipt{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE owner_instructions SET completion_key=$2,completion_hash=$3 WHERE operation_id=$1", in.OperationID, key, hash[:]); err != nil {
		return capsuleprotocol.CompletionReceipt{}, err
	}
	out.State = in.Outcome
	return out, commit(ctx, tx)
}

// ExpireWorkingInvocations fails invocations whose agent did not post an outcome
// in time. Each one is closed under its agent lock, so it races cleanly with a
// late completion: exactly one of them commits.
func (s *Store) ExpireWorkingInvocations(ctx context.Context, now *time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT o.id,o.agent_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        WHERE `+workingFilter+` AND i.result_due_at<=`+dbNow+` ORDER BY i.result_due_at,o.id LIMIT $2`, nowArg(now), limit)
	if err != nil {
		return 0, err
	}
	type item struct{ op, agent string }
	var due []item
	for rows.Next() {
		var it item
		if err = rows.Scan(&it.op, &it.agent); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, it)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	var result error
	for _, it := range due {
		ok, err := s.expireWorking(ctx, it.op, it.agent, now)
		if err != nil {
			result = errors.Join(result, err)
		} else if ok {
			n++
		}
	}
	return n, result
}

func (s *Store) expireWorking(ctx context.Context, op, agentID string, now *time.Time) (bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, agentID); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE platform_operations o SET status='FAILED',error_code='work_timeout',completed_at=clock_timestamp()
        FROM owner_instructions i WHERE i.operation_id=o.id AND o.id=$2 AND `+workingFilter+` AND i.result_due_at<=`+dbNow, nowArg(now), op)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, commit(ctx, tx)
}

// cancelWorking closes a working invocation for its requester. The agent's late
// outcome is then refused; it learns so when it tries to post it.
func cancelWorking(ctx context.Context, tx pgx.Tx, op, code string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE platform_operations o SET status='CANCELED',error_code=$2,completed_at=clock_timestamp()
        FROM owner_instructions i WHERE i.operation_id=o.id AND o.id=$1 AND `+workingFilter, op, code)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
