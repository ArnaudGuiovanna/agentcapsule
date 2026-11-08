package controlplane

import (
	"context"
	"errors"
	"math"

	"github.com/jackc/pgx/v5"
)

var ErrOperationPending = errors.New("an earlier lifecycle operation is still pending")

// RequestLifecycle records an explicit wake/sleep command. It does not change
// placement authority or publish physical completion. Commands retain their
// order per agent; an ordinary mailbox may subsequently wake a sleeping agent.
func (c *AgentCatalog) RequestLifecycle(ctx context.Context, p Principal, id, key, kind string) (APIReceipt, error) {
	if kind != "wake" && kind != "sleep" {
		return APIReceipt{}, ErrInput
	}
	if p.Kind == "tenant" {
		return c.requestLifecycleTenant(ctx, p, id, key, kind)
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	scope := scope(p, "POST", "/v1/agents/"+id+"/"+kind, key)
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
	if !ok || a.Tenant != "" || (p.Kind != "service" && a.Owner != p.ID) {
		return APIReceipt{}, ErrNotFound
	}
	var host string
	if err = tx.QueryRow(ctx, "SELECT host_id FROM agent_specs WHERE agent_id=$1", id).Scan(&host); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withReceipt(ctx, tx, scope, struct{}{}, func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		var seq int64
		err := tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
            WHERE agent_id=$1 AND next_operation_seq<$2 RETURNING next_operation_seq`, id, int64(math.MaxInt64)).Scan(&seq)
		if err != nil {
			return 0, nil, err
		}
		op := newID("op")
		_, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,owner_user_id,agent_id,host_id,seq,kind)
            VALUES($1,$2,$3,$4,$5,$6)`, op, a.Owner, id, host, seq, kind)
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

type LifecycleOperation struct {
	ID, AgentID, HostID, Kind, Status string
	Placement                         Placement
}

func lifecycleOperation(ctx context.Context, tx pgx.Tx, id, agentID, host string) (LifecycleOperation, agent, error) {
	a, p, err := placementLock(ctx, tx, agentID, host)
	if err != nil {
		return LifecycleOperation{}, a, err
	}
	op := LifecycleOperation{ID: id, AgentID: agentID, HostID: host, Placement: p}
	var seq int64
	err = tx.QueryRow(ctx, `SELECT kind,status,seq FROM platform_operations WHERE id=$1 AND agent_id=$2 AND host_id=$3`, id, agentID, host).Scan(&op.Kind, &op.Status, &seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return op, a, ErrNotFound
	}
	if err != nil {
		return op, a, err
	}
	if op.Kind != "wake" && op.Kind != "sleep" {
		return op, a, ErrInput
	}
	if op.Status != "PENDING" && op.Status != "RUNNING" {
		return op, a, nil
	}
	var earlier bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_operations WHERE agent_id=$1 AND seq<$2
        AND kind IN ('wake','sleep') AND status IN ('PENDING','RUNNING'))`, agentID, seq).Scan(&earlier); err != nil {
		return op, a, err
	}
	if earlier {
		return op, a, ErrOperationPending
	}
	return op, a, nil
}

func cancelLifecycle(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code='agent_unavailable',completed_at=clock_timestamp()
        WHERE id=$1 AND status IN ('PENDING','RUNNING')`, id)
	return err
}

// BeginLifecycleOperation is called inside host exclusive admission. A job
// snapshot or expired queue lease cannot authorize a completed/newer command.
// No SQL lock survives this call or crosses a physical start/stop operation.
func (s *Store) BeginLifecycleOperation(ctx context.Context, id, agentID, host string) (LifecycleOperation, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return LifecycleOperation{}, err
	}
	defer rollback(tx)
	op, a, err := lifecycleOperation(ctx, tx, id, agentID, host)
	if err != nil {
		return op, err
	}
	if op.Status != "PENDING" && op.Status != "RUNNING" {
		return op, nil
	}
	if a.Phase != "LIVE" {
		if err = cancelLifecycle(ctx, tx, id); err != nil {
			return op, err
		}
		op.Status = "CANCELED"
	} else {
		if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='RUNNING' WHERE id=$1", id); err != nil {
			return op, err
		}
		op.Status = "RUNNING"
	}
	return op, commit(ctx, tx)
}

// CompleteLifecycleOperation follows the host's durable RUNNING publication or
// observed physical retirement. It rechecks the current SQL placement; a lease
// expiry, an unconfirmed attempt or a prior generation cannot prove completion.
func (s *Store) CompleteLifecycleOperation(ctx context.Context, wanted LifecycleOperation, generation uint64, vmID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	op, a, err := lifecycleOperation(ctx, tx, wanted.ID, wanted.AgentID, wanted.HostID)
	if err != nil {
		return err
	}
	if op.Status != "PENDING" && op.Status != "RUNNING" {
		return nil
	}
	if a.Phase != "LIVE" {
		if err = cancelLifecycle(ctx, tx, op.ID); err != nil {
			return err
		}
		return commit(ctx, tx)
	}
	if op.Status != "RUNNING" || op.Kind != wanted.Kind || op.Placement.Generation != generation {
		return ErrPlacement
	}
	var unclean any
	if op.Kind == "wake" {
		if generation == 0 || vmID == "" || op.Placement.State != "RUNNING" || op.Placement.VMID != vmID || op.Placement.FenceOnly {
			return ErrPlacement
		}
		var compatible bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM placement_control_contracts pc
		  WHERE pc.agent_id=$1 AND pc.host_id=$2 AND pc.generation=$3 AND pc.vm_id=$4 AND pc.protocol='capsule.v1'
		  AND pc.incarnation=coalesce((SELECT incarnation FROM store_enrollments WHERE agent_id=$1),1))`,
			op.AgentID, op.HostID, generation, vmID).Scan(&compatible); err != nil {
			return err
		}
		if !compatible {
			return ErrPlacement
		}
	} else {
		if vmID != "" || op.Placement.State != "STOPPED" {
			return ErrPlacement
		}
		unclean = op.Placement.UncleanStop
	}
	_, err = tx.Exec(ctx, `UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp(),unclean_stop=$2 WHERE id=$1`, op.ID, unclean)
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}
