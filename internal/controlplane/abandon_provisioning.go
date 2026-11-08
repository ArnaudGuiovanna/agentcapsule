package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// AbandonProvisioning is a trusted operator operation for a reservation that can
// never complete, for example one pinned to a release the worker does not serve.
// Such an agent otherwise stays PROVISIONING forever: deletion refuses it and
// the owner cannot reserve another.
//
// It is deliberately narrow. The reservation must still be at INSTALLING, with
// no volume identity recorded, no placement, no seal and no initialization, and
// no worker may hold a live lease on its job. Under those conditions nothing
// physical or externally visible exists, so the catalogue rows can be removed
// as if the reservation never happened. Anything further along is refused with
// ErrTransition and must use the regular deletion path. If a worker created a
// volume file but crashed before recording it, that file is not tracked here and
// has to be removed by the operator.
func (s *Store) AbandonProvisioning(ctx context.Context, agentID string) error {
	if !validOrganizationText(agentID, 100) {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return err
	}
	a, ok := agents[agentID]
	if !ok {
		return ErrNotFound
	}
	if a.Phase != "PROVISIONING" {
		return ErrTransition
	}
	var host string
	err = tx.QueryRow(ctx, "SELECT host_id FROM agent_specs WHERE agent_id=$1", agentID).Scan(&host)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTransition
	}
	if err != nil {
		return err
	}
	// Serialize with discovery so that no job is created while this runs.
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	var stage string
	err = tx.QueryRow(ctx, "SELECT stage FROM store_enrollments WHERE agent_id=$1 FOR UPDATE", agentID).Scan(&stage)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTransition
	}
	if err != nil {
		return err
	}
	var blocked bool
	if err = tx.QueryRow(ctx, `SELECT $2<>'INSTALLING'
        OR EXISTS(SELECT 1 FROM agent_placements WHERE agent_id=$1)
        OR EXISTS(SELECT 1 FROM store_seals WHERE agent_id=$1)
        OR EXISTS(SELECT 1 FROM store_initializations WHERE agent_id=$1)
        OR EXISTS(SELECT 1 FROM worker_jobs WHERE agent_id=$1 AND lease_until>clock_timestamp())`,
		agentID, stage).Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		return ErrTransition
	}
	// Children first. Any dependent row not listed here (for example mail) makes
	// the foreign keys refuse the final DELETE and rolls everything back.
	for _, statement := range []string{
		"DELETE FROM worker_jobs WHERE agent_id=$1",
		"DELETE FROM store_enrollments WHERE agent_id=$1",
		"DELETE FROM platform_operations WHERE agent_id=$1",
		"DELETE FROM agent_specs WHERE agent_id=$1",
		"DELETE FROM agents WHERE id=$1",
	} {
		if _, err = tx.Exec(ctx, statement, agentID); err != nil {
			return fmt.Errorf("abandon provisioning: %w", ErrTransition)
		}
	}
	return commit(ctx, tx)
}
