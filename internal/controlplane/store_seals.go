package controlplane

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

// StoreSeal is a worker-only observation of the host's durable admission ban,
// empty attempt cgroup and registered inode. It is never accepted from a guest
// or public API. The host must be rechecked before EACH future fence ACK; this
// SQL record alone is not a physical proof or permission to omit a target.
type StoreSeal struct {
	AgentID, HostID, ID       string
	Generation, Device, Inode uint64
}

// StoreSealTarget distinguishes a fully tombstoned store from a merely offline
// or QUIESCING one. No database lock spans the subsequent host operation.
func (s *Store) StoreSealTarget(ctx context.Context, id, host string) (Placement, bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return Placement{}, false, err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return p, false, err
	}
	if a.Phase != "DELETING" && a.Phase != "DELETED" {
		return p, false, nil
	}
	var tombstoned bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deletion_operations WHERE agent_id=$1 AND phase='TOMBSTONED')`, id).Scan(&tombstoned)
	if err != nil {
		return p, false, err
	}
	if !tombstoned {
		return p, false, ErrPendingFences
	}
	return p, true, nil
}

// RecordStoreSeal is called only after the trusted host completed SealAgent.
// Publication and placement STOPPED commit together. Neither this operation nor
// a successful future fence advances the agent to DELETED or claims erasure.
func (s *Store) RecordStoreSeal(ctx context.Context, proof StoreSeal) error {
	b, err := hex.DecodeString(proof.ID)
	if err != nil || len(b) != 16 || strings.ToLower(proof.ID) != proof.ID || proof.Inode == 0 {
		return ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if p.Generation != proof.Generation || (a.Phase != "DELETING" && a.Phase != "DELETED") {
		return ErrPlacement
	}
	var tombstoned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deletion_operations WHERE agent_id=$1 AND phase='TOMBSTONED')`, proof.AgentID).Scan(&tombstoned); err != nil {
		return err
	}
	if !tombstoned {
		return ErrPendingFences
	}
	device, inode := fmt.Sprintf("%016x", proof.Device), fmt.Sprintf("%016x", proof.Inode)
	if _, err = tx.Exec(ctx, `INSERT INTO store_seals(agent_id,host_id,generation,seal_id,volume_device,volume_inode)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (agent_id) DO NOTHING`, proof.AgentID, proof.HostID, proof.Generation, proof.ID, device, inode); err != nil {
		return err
	}
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT host_id=$2 AND generation=$3 AND seal_id=$4 AND volume_device=$5 AND volume_inode=$6
        FROM store_seals WHERE agent_id=$1`, proof.AgentID, proof.HostID, proof.Generation, proof.ID, device, inode).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_placements SET state='STOPPED',lease_until=NULL,worker_id='',vm_id='',
        unclean_stop=unclean_stop OR state<>'STOPPED' WHERE agent_id=$1`, proof.AgentID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
