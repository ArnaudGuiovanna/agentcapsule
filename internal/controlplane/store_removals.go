package controlplane

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// StoreRemovalPlan binds the worker's final cleanup to the completed distributed
// deletion and the immutable physical execution seal. It contains no key.
type StoreRemovalPlan struct {
	Enrollment Enrollment
	Seal       StoreSeal
}

func removalPlan(ctx context.Context, tx pgx.Tx, id, host string) (StoreRemovalPlan, error) {
	var plan StoreRemovalPlan
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return plan, err
	}
	if (a.Phase != "DELETING" && a.Phase != "DELETED") || p.State != "STOPPED" {
		return plan, ErrPlacement
	}
	var tombstoned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deletion_operations WHERE agent_id=$1 AND phase='TOMBSTONED')`, id).Scan(&tombstoned); err != nil {
		return plan, err
	}
	if !tombstoned {
		return plan, ErrPendingFences
	}
	plan.Enrollment, err = enrollment(ctx, tx, id, host)
	if err != nil {
		return plan, err
	}
	if plan.Enrollment.Stage != "READY" {
		return plan, ErrStoreEnrollment
	}
	var device, inode string
	err = tx.QueryRow(ctx, `SELECT agent_id,host_id,seal_id,generation,volume_device,volume_inode FROM store_seals WHERE agent_id=$1`, id).Scan(
		&plan.Seal.AgentID, &plan.Seal.HostID, &plan.Seal.ID, &plan.Seal.Generation, &device, &inode)
	if errors.Is(err, pgx.ErrNoRows) {
		return plan, ErrNotFound
	}
	if err != nil {
		return plan, err
	}
	plan.Seal.Device, err = strconv.ParseUint(device, 16, 64)
	if err != nil {
		return plan, ErrPlacement
	}
	plan.Seal.Inode, err = strconv.ParseUint(inode, 16, 64)
	if err != nil || plan.Seal.Inode == 0 || plan.Seal.HostID != host || plan.Seal.Generation != p.Generation {
		return plan, ErrPlacement
	}
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT volume_device=$2 AND volume_inode=$3 FROM store_enrollments WHERE agent_id=$1`, id, device, inode).Scan(&matches); err != nil {
		return plan, err
	}
	if !matches {
		return plan, ErrPlacement
	}
	return plan, nil
}

func (s *Store) StoreRemovalTarget(ctx context.Context, id, host string) (StoreRemovalPlan, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return StoreRemovalPlan{}, err
	}
	defer rollback(tx)
	return removalPlan(ctx, tx, id, host)
}

// RecordStoreRemoval is a trusted worker observation, never an API/guest claim.
// The caller has rechecked physical retirement, durable key revocation and local
// volume removal. It does not attest destruction of external copies/backups.
func (s *Store) RecordStoreRemoval(ctx context.Context, proof StoreSeal, volume string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	plan, err := removalPlan(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if plan.Seal != proof || plan.Enrollment.VolumeID != volume {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, `INSERT INTO store_removals(agent_id,volume_id,seal_id) VALUES($1,$2,$3) ON CONFLICT(agent_id) DO NOTHING`, proof.AgentID, volume, proof.ID); err != nil {
		return err
	}
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT volume_id=$2 AND seal_id=$3 FROM store_removals WHERE agent_id=$1`, proof.AgentID, volume, proof.ID).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, `UPDATE agents SET phase='DELETED' WHERE id=$1`, proof.AgentID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE platform_operations SET status='SUCCEEDED',completed_at=coalesce(completed_at,clock_timestamp())
        WHERE kind='delete' AND id=(SELECT operation_id FROM deletion_operations WHERE agent_id=$1)`, proof.AgentID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
