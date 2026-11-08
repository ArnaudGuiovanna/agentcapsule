package controlplane

import (
	"context"
	"math"
)

// PlacementControlObservation is supplied only by the trusted host after a
// boot-authenticated probe. It proves compatibility at observation time, not
// continuous health, physical presence, tenant authority or successful effects.
type PlacementControlObservation struct {
	AgentID, HostID, VMID   string
	Generation, Incarnation uint64
	Compatible              bool
}

// ObservePlacementControl serializes with placement replacement/stop. A late
// positive or negative observation can neither bless nor erase another boot.
// No caller may turn a physical census or a guest payload into this observation.
func (s *Store) ObservePlacementControl(ctx context.Context, o PlacementControlObservation) error {
	if o.AgentID == "" || o.HostID == "" || o.VMID == "" || o.Generation == 0 || o.Generation > math.MaxInt64 || o.Incarnation == 0 || o.Incarnation > math.MaxInt64 {
		return ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, o.AgentID, o.HostID)
	if err != nil {
		return err
	}
	if p.Generation != o.Generation || p.VMID != o.VMID {
		return ErrPlacement
	}
	if !o.Compatible {
		_, err = tx.Exec(ctx, `DELETE FROM placement_control_contracts WHERE agent_id=$1 AND host_id=$2
		  AND generation=$3 AND vm_id=$4 AND incarnation=$5`, o.AgentID, o.HostID, o.Generation, o.VMID, o.Incarnation)
		if err != nil {
			return err
		}
		return commit(ctx, tx)
	}
	if p.State != "RUNNING" || (a.Phase != "LIVE" && a.Phase != "QUIESCING" && !(a.Phase == "PROVISIONING" && p.FenceOnly)) {
		return ErrPlacement
	}
	var incarnation uint64
	if err = tx.QueryRow(ctx, `SELECT coalesce((SELECT incarnation FROM store_enrollments WHERE agent_id=$1),1)`, o.AgentID).Scan(&incarnation); err != nil {
		return err
	}
	if incarnation != o.Incarnation {
		return ErrPlacement
	}
	_, err = tx.Exec(ctx, `INSERT INTO placement_control_contracts(agent_id,host_id,generation,vm_id,incarnation,protocol)
	  VALUES($1,$2,$3,$4,$5,'capsule.v1') ON CONFLICT(agent_id) DO UPDATE SET
	  host_id=excluded.host_id,generation=excluded.generation,vm_id=excluded.vm_id,
	  incarnation=excluded.incarnation,protocol=excluded.protocol,observed_at=clock_timestamp()`, o.AgentID, o.HostID, o.Generation, o.VMID, o.Incarnation)
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}
