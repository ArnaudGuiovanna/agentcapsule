package controlplane

import (
	"context"
	"errors"
	"math"

	"github.com/jackc/pgx/v5"
)

type CancellationReceipt struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// CancelRequest records intent; final CANCELED still requires every barrier.
// The receipt remains PENDING on replay; the request read exposes live progress.
func (c *AgentCatalog) CancelRequest(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	scope := scope(p, "POST", "/v1/agent-requests/"+id+"/cancel", key)
	if err = lockHTTPReceipt(ctx, tx, scope); err != nil {
		return APIReceipt{}, err
	}
	if err = authorizePrincipal(ctx, tx, p, "user", "inbox:own"); err != nil {
		return APIReceipt{}, err
	}
	r, agents, err := lockRequest(ctx, tx, id)
	if err != nil {
		return APIReceipt{}, err
	}
	if agents[r.Sender].Owner != p.ID {
		return APIReceipt{}, ErrNotFound
	}
	result, err := c.accounts.withReceipt(ctx, tx, scope, struct{}{}, func() (int, any, error) {
		if err := beginClosure(ctx, tx, r, "CANCELED", "sender_canceled"); err != nil {
			return 0, nil, err
		}
		return 202, CancellationReceipt{RequestID: id, Status: "PENDING"}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// Delete records the operation, durable revocation census and HTTP receipt in
// one commit. It does not publish DELETED or promise key/volume destruction.
func (c *AgentCatalog) Delete(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if p.Kind == "tenant" {
		return c.deleteTenant(ctx, p, id, key)
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	scope := scope(p, "DELETE", "/v1/agents/"+id, key)
	if err = lockHTTPReceipt(ctx, tx, scope); err != nil {
		return APIReceipt{}, err
	}
	if err = agentPermission(ctx, tx, p, "agent:manage"); err != nil {
		return APIReceipt{}, err
	}
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return APIReceipt{}, err
	}
	a, ok := agents[id]
	if !ok || a.Tenant != "" || p.Kind != "service" && a.Owner != p.ID {
		return APIReceipt{}, ErrNotFound
	}
	var host string
	if err = tx.QueryRow(ctx, "SELECT host_id FROM agent_specs WHERE agent_id=$1", id).Scan(&host); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withReceipt(ctx, tx, scope, struct{}{}, func() (int, any, error) {
		if err := requestDeletion(ctx, tx, a, p.ID); err != nil {
			return 0, nil, err
		}
		var op string
		if err := tx.QueryRow(ctx, "SELECT coalesce(operation_id,'') FROM deletion_operations WHERE agent_id=$1", id).Scan(&op); err != nil {
			return 0, nil, err
		}
		if op == "" {
			var seq int64
			if err := tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1 WHERE agent_id=$1 AND next_operation_seq<$2 RETURNING next_operation_seq`, id, int64(math.MaxInt64)).Scan(&seq); err != nil {
				return 0, nil, err
			}
			op = newID("op")
			if _, err := tx.Exec(ctx, `INSERT INTO platform_operations(id,owner_user_id,agent_id,host_id,seq,kind) VALUES($1,$2,$3,$4,$5,'delete')`, op, a.Owner, id, host, seq); err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, "UPDATE deletion_operations SET operation_id=$2 WHERE agent_id=$1", id, op); err != nil {
				return 0, nil, err
			}
		}
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}
