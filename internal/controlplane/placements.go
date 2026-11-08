package controlplane

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrPlacement     = errors.New("obsolete or foreign VM placement")
	ErrPlacementBusy = errors.New("VM placement operation already in progress")
)

// Placement describes durable authority, not proof of a live/absent process.
// Host and worker identities come from the trusted worker configuration.
// LeaseValid is a database-clock observation, never an authority to confirm.
type Placement struct {
	AgentID, HostID, WorkerID, State, VMID string
	Generation                             uint64
	LeaseUntil                             *time.Time
	LeaseValid, UncleanStop                bool
	FenceOnly                              bool
}

const placementColumns = `agent_id,host_id,worker_id,state,vm_id,generation,lease_until,
    coalesce(lease_until>clock_timestamp(),false),unclean_stop,fence_only`

func scanPlacement(row pgx.Row) (Placement, error) {
	var p Placement
	var gen int64
	err := row.Scan(&p.AgentID, &p.HostID, &p.WorkerID, &p.State, &p.VMID, &gen,
		&p.LeaseUntil, &p.LeaseValid, &p.UncleanStop, &p.FenceOnly)
	p.Generation = uint64(gen)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrPlacement
	}
	return p, err
}

// Lock order matches messaging/deletion: agent first, placement second.
func placementLock(ctx context.Context, tx pgx.Tx, id, host string) (agent, Placement, error) {
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return agent{}, Placement{}, err
	}
	a, ok := agents[id]
	if !ok {
		return a, Placement{}, ErrPlacement
	}
	p, err := scanPlacement(tx.QueryRow(ctx, `SELECT `+placementColumns+` FROM agent_placements
        WHERE agent_id=$1 FOR UPDATE`, id))
	if err == nil && p.HostID != host {
		err = ErrPlacement
	}
	return a, p, err
}

// RegisterPlacement binds an already provisioned volume to its host. It cannot
// migrate/rebind an existing volume, including after its lease has expired.
func (s *Store) RegisterPlacement(ctx context.Context, id, host string) error {
	if id == "" || host == "" {
		return ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return err
	}
	a, ok := agents[id]
	if !ok {
		return ErrNotFound
	}
	if a.Phase != "LIVE" {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_placements(agent_id,host_id) VALUES ($1,$2)
        ON CONFLICT (agent_id) DO NOTHING`, id, host); err != nil {
		return err
	}
	var assigned string
	if err = tx.QueryRow(ctx, `SELECT host_id FROM agent_placements WHERE agent_id=$1`, id).Scan(&assigned); err != nil {
		return err
	}
	if assigned != host {
		return ErrPlacement
	}
	return commit(ctx, tx)
}

// ClaimPlacement allocates a monotone boot generation. Only STARTING has an
// expiring job lease. A RUNNING placement survives worker death; another worker
// on the same host must reconcile the VMM, not infer its death from elapsed time.
func (s *Store) ClaimPlacement(ctx context.Context, id, host, worker string, lease time.Duration) (Placement, error) {
	return s.claimPlacement(ctx, id, host, worker, lease, false, 0)
}

// ClaimFencePlacement may wake a LIVE, QUIESCING or provisioned but not yet
// activated store solely for barriers.
// A new boot always has that restricted purpose; an existing ordinary RUNNING
// boot can be reused. The purpose must match the post-boot confirmation.
func (s *Store) ClaimFencePlacement(ctx context.Context, id, host, worker string, lease time.Duration) (Placement, error) {
	return s.claimPlacement(ctx, id, host, worker, lease, true, 0)
}

func (s *Store) claimPlacement(ctx context.Context, id, host, worker string, lease time.Duration, forFence bool, renewal uint64) (Placement, error) {
	if worker == "" || lease < time.Microsecond || lease > 24*time.Hour {
		return Placement{}, ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Placement{}, err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return p, err
	}
	if renewal != 0 {
		var pending bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM placement_renewals
            WHERE agent_id=$1 AND host_id=$2 AND from_generation=$3)`, id, host, renewal).Scan(&pending); err != nil {
			return p, err
		}
		if !pending {
			return p, ErrNoRenewal
		}
		if a.Phase != "LIVE" {
			if _, err = tx.Exec(ctx, "DELETE FROM placement_renewals WHERE agent_id=$1", id); err != nil {
				return p, err
			}
			if err = commit(ctx, tx); err != nil {
				return p, err
			}
			return p, ErrNoRenewal
		}
		if p.Generation < renewal || (p.Generation == renewal && p.State == "RUNNING") {
			return p, ErrPlacement
		}
	}
	if a.Phase != "LIVE" && !(forFence && (a.Phase == "QUIESCING" || a.Phase == "PROVISIONING")) {
		return p, ErrUnavailable
	}
	if !forFence {
		if err := ordinaryStoreReady(ctx, tx, id); err != nil {
			return p, err
		}
	}
	if a.Phase == "PROVISIONING" {
		e, err := enrollment(ctx, tx, id, host)
		if err != nil {
			return p, err
		}
		if e.Stage != "FENCING" {
			return p, ErrStoreEnrollment
		}
	}
	if p.State == "RUNNING" {
		if p.FenceOnly && !forFence {
			return p, ErrPlacementBusy
		}
		return p, nil
	}
	if p.State == "STOPPING" {
		return p, ErrPlacementBusy
	}
	// Read the clock AFTER obtaining the row lock; a timestamp computed while
	// waiting for a lock must not extend a lease or authorize stale confirmation.
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT coalesce(lease_until>clock_timestamp(),false)
        FROM agent_placements WHERE agent_id=$1`, id).Scan(&valid); err != nil {
		return p, err
	}
	if p.State == "STARTING" && valid {
		if p.WorkerID != worker || (p.FenceOnly && !forFence) {
			return p, ErrPlacementBusy
		}
		p.LeaseValid = true
		return p, nil
	}
	if p.Generation >= math.MaxInt64 {
		return p, fmt.Errorf("placement generation exhausted")
	}
	p, err = scanPlacement(tx.QueryRow(ctx, `UPDATE agent_placements SET generation=generation+1,
        state='STARTING',worker_id=$2,lease_until=clock_timestamp()+$3*interval '1 microsecond',vm_id='',fence_only=$4
        WHERE agent_id=$1 RETURNING `+placementColumns, id, worker, lease.Microseconds(), forFence))
	if err != nil {
		return p, err
	}
	return p, commit(ctx, tx)
}

// ConfirmPlacement is the post-boot compare-and-set. vmID is generated by the
// host driver and identifies this actual VMM attempt, not a reusable PID.
func (s *Store) ConfirmPlacement(ctx context.Context, id, host, worker string, generation uint64, vmID string) error {
	return s.confirmPlacement(ctx, id, host, worker, generation, vmID, false)
}

func (s *Store) ConfirmFencePlacement(ctx context.Context, id, host, worker string, generation uint64, vmID string) error {
	return s.confirmPlacement(ctx, id, host, worker, generation, vmID, true)
}

func (s *Store) confirmPlacement(ctx context.Context, id, host, worker string, generation uint64, vmID string, fenceOnly bool) error {
	if generation == 0 || vmID == "" {
		return ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if (a.Phase != "LIVE" && !(fenceOnly && (a.Phase == "QUIESCING" || a.Phase == "PROVISIONING"))) || p.FenceOnly != fenceOnly || p.Generation != generation || p.WorkerID != worker {
		return ErrPlacement
	}
	if !fenceOnly {
		if err := ordinaryStoreReady(ctx, tx, id); err != nil {
			return err
		}
	}
	if p.State == "RUNNING" && p.VMID == vmID {
		return nil
	}
	if p.State != "STARTING" {
		return ErrPlacement
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_placements SET state='RUNNING',vm_id=$2,lease_until=NULL
        WHERE agent_id=$1 AND lease_until>clock_timestamp()`, id, vmID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrPlacement
	}
	return commit(ctx, tx)
}

// ValidatePlacement permits adoption by a new worker on the same host. QUIESCING
// retains the guest for data fences; DELETING/DELETED cannot be adopted. A SQL
// outage is returned unchanged so the host will not mistake it for obsolescence.
func (s *Store) ValidatePlacement(ctx context.Context, id, host string, generation uint64, vmID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if (a.Phase != "LIVE" && a.Phase != "QUIESCING" && !(a.Phase == "PROVISIONING" && p.FenceOnly)) || p.State != "RUNNING" ||
		p.Generation != generation || p.VMID != vmID {
		return ErrPlacement
	}
	if !p.FenceOnly {
		return ordinaryStoreReady(ctx, tx, id)
	}
	return nil
}

// BeginPlacementStop commits intent before killing a VMM. Keeping its generation
// prevents an old Stop or delayed absence report from affecting a replacement.
func (s *Store) BeginPlacementStop(ctx context.Context, id, host string, generation uint64) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	_, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if p.Generation != generation || generation == 0 {
		return ErrPlacement
	}
	// An intentional stop supersedes a queued automatic replacement. The
	// renewal-specific path commits its own STOPPING without this cancellation.
	if _, err = tx.Exec(ctx, "DELETE FROM placement_renewals WHERE agent_id=$1", id); err != nil {
		return err
	}
	if p.State == "STOPPED" || p.State == "STOPPING" {
		return commit(ctx, tx)
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_placements SET state='STOPPING',lease_until=NULL
        WHERE agent_id=$1`, id); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// ObservePlacementStopped may ONLY be called after the trusted host has durably
// retired this generation and verified its cgroup empty. Absence in a snapshot,
// lease expiry, or failure of a health probe alone is not sufficient.
func (s *Store) ObservePlacementStopped(ctx context.Context, id, host string, generation uint64, unclean bool) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	_, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if p.Generation != generation {
		return ErrPlacement
	}
	if p.State == "STOPPED" {
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_placements SET state='STOPPED',lease_until=NULL,
        worker_id='',vm_id='',unclean_stop=$2 WHERE agent_id=$1`, id, unclean); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// Placements is an observation for reconciliation, never permission to launch.
func (s *Store) Placements(ctx context.Context, host string) ([]Placement, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT `+placementColumns+` FROM agent_placements WHERE host_id=$1 ORDER BY agent_id`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Placement
	for rows.Next() {
		p, err := scanPlacement(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
