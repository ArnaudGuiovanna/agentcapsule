package controlplane

import (
	"context"
	"errors"
	"time"
)

var ErrNoRenewal = errors.New("automatic VM replacement is no longer pending")

type CredentialRenewal struct {
	AgentID, HostID, VMID string
	Generation            uint64
}

// BeginCredentialRenewal is worker-only: a verified ordinary LIVE boot needs
// fresh credentials. Replacement intent and STOPPING have one commit boundary.
// No physical absence or completion is inferred here.
func (s *Store) BeginCredentialRenewal(ctx context.Context, id, host string, generation uint64, vmID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if a.Phase != "LIVE" {
		return ErrUnavailable
	}
	if generation == 0 || vmID == "" || p.Generation != generation || p.VMID != vmID || p.FenceOnly {
		return ErrPlacement
	}
	if p.State == "STOPPING" {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM placement_renewals
            WHERE agent_id=$1 AND host_id=$2 AND from_generation=$3 AND from_vm_id=$4)`, id, host, generation, vmID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		return ErrNoRenewal // Do not undo an explicit stop.
	}
	if p.State != "RUNNING" {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, `INSERT INTO placement_renewals(agent_id,host_id,from_generation,from_vm_id)
        VALUES ($1,$2,$3,$4) ON CONFLICT(agent_id) DO UPDATE
        SET host_id=excluded.host_id,from_generation=excluded.from_generation,
            from_vm_id=excluded.from_vm_id,requested_at=clock_timestamp()`, id, host, generation, vmID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_placements SET state='STOPPING',lease_until=NULL WHERE agent_id=$1`, id); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// PendingCredentialRenewals is a snapshot, not permission to launch. A later
// ClaimRenewalPlacement rechecks this exact intent under the placement lock.
func (s *Store) PendingCredentialRenewals(ctx context.Context, host string) ([]CredentialRenewal, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT agent_id,host_id,from_generation,from_vm_id
        FROM placement_renewals WHERE host_id=$1 ORDER BY requested_at,agent_id`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CredentialRenewal
	for rows.Next() {
		var r CredentialRenewal
		if err := rows.Scan(&r.AgentID, &r.HostID, &r.Generation, &r.VMID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) ClaimRenewalPlacement(ctx context.Context, r CredentialRenewal, worker string, lease time.Duration) (Placement, error) {
	if r.Generation == 0 {
		return Placement{}, ErrNoRenewal
	}
	return s.claimPlacement(ctx, r.AgentID, r.HostID, worker, lease, false, r.Generation)
}

// ObserveRenewalSatisfied must follow the host's durable RUNNING publication,
// never just SQL confirmation: a crash between those two kills the unfinished
// VMM and still needs a replacement. Stale observations cannot erase a new job.
func (s *Store) ObserveRenewalSatisfied(ctx context.Context, id, host string, generation uint64, vmID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if a.Phase != "LIVE" || p.State != "RUNNING" || p.Generation != generation || p.VMID != vmID || p.FenceOnly {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, `DELETE FROM placement_renewals WHERE agent_id=$1 AND host_id=$2 AND from_generation<$3`, id, host, generation); err != nil {
		return err
	}
	return commit(ctx, tx)
}
