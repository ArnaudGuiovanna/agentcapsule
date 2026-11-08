//go:build linux

package worker

import (
	"context"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// Caller holds exclusive host admission until retirement and SQL observation.
// Capture the current boot session BEFORE STOPPING: the census reconciles against
// SQL and must not be used to adopt that boot again after its authority closes.
func (w *Placements) quiesceStop(ctx context.Context, id string, generation uint64) error {
	client, err := w.host.ControlForRetirement(ctx, id)
	if err != nil {
		client = nil // unavailable/expired control requires a forced stop
	}
	return w.stopPrepared(ctx, id, generation, client, func(ctx context.Context) error {
		return w.host.Retire(ctx, id, generation)
	})
}

// retire is the trusted host's physical retirement operation, not a database
// observation. Keeping this boundary explicit permits transaction/RPC failure
// tests without claiming those tests execute a real VMM.
func (w *Placements) stopPrepared(ctx context.Context, id string, generation uint64, client runtime.RetirementControl, retire func(context.Context) error) error {
	if client != nil && (client.Identity().AgentID != id || client.Identity().Generation != generation) {
		return controlplane.ErrPlacement
	}
	if err := w.store.BeginPlacementStop(ctx, id, w.hostID, generation); err != nil {
		return err
	}
	if w.afterStopIntent != nil {
		w.afterStopIntent()
	}
	unclean := true
	if client != nil {
		unclean = client.Quiesce(ctx) != nil
	}
	// Cancellation after STOPPING or a lost guest ACK must still retire the
	// generation. WithoutCancel retains the live host-admission scope; the
	// caller holds it until this bounded cleanup finishes.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if err := retire(cleanup); err != nil {
		return err // never publish STOPPED or infer absence from the guest ACK
	}
	return w.store.ObservePlacementStopped(cleanup, id, w.hostID, generation, unclean)
}
