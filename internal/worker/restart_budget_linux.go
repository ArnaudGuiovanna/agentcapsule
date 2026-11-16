//go:build linux

package worker

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// SetRestartBudget sets how many failed boots and crashes of an agent's
// guest this worker allows within a window before the agent is FAILED (CAP-03,
// ADR 012). Without it, controlplane.DefaultRestartBudget applies. Every
// worker of a host must use the same budget.
func (w *Placements) SetRestartBudget(b controlplane.RestartBudget) error {
	if !b.Valid() {
		return controlplane.ErrInput
	}
	w.restart.Store(&b)
	return nil
}

func (w *Placements) restartBudget() controlplane.RestartBudget {
	if b := w.restart.Load(); b != nil {
		return *b
	}
	return controlplane.DefaultRestartBudget
}

// observeGuestFailure publishes a retired generation STOPPED after its guest
// failed, at boot or by crashing, and counts it against the agent's restart
// budget. The host must already have retired that generation.
func (w *Placements) observeGuestFailure(ctx context.Context, id string, generation uint64, kind string) error {
	failed, err := w.store.ObserveGuestFailure(ctx, controlplane.GuestFailure{AgentID: id, HostID: w.hostID, Kind: kind, Generation: generation}, w.restartBudget())
	if err != nil {
		return err
	}
	w.countGuestFailure(kind, failed)
	return nil
}
