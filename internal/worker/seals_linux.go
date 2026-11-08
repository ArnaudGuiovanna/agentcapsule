//go:build linux

package worker

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// SealDeletedStore requires the completed distributed barrier, then permanently
// retires execution on the assigned host. It does not remove/encrypt the volume.
func (w *Placements) SealDeletedStore(ctx context.Context, id string) error {
	return w.host.WithBarrier(ctx, id, func(ctx context.Context) error { return w.sealDeletedStore(ctx, id) })
}

func (w *Placements) sealDeletedStore(ctx context.Context, id string) error {
	p, ready, err := w.store.StoreSealTarget(ctx, id, w.hostID)
	if err != nil {
		return err
	}
	if !ready {
		return controlplane.ErrPendingFences
	}
	return w.seal(ctx, p)
}

func (w *Placements) seal(ctx context.Context, p controlplane.Placement) error {
	proof, err := w.host.SealAgent(ctx, p.AgentID, p.Generation)
	if err != nil {
		return err
	}
	if w.afterSeal != nil {
		w.afterSeal()
	}
	if w.authority != nil {
		e, err := w.store.VolumeEnrollment(ctx, p.AgentID, w.hostID)
		if err != nil {
			return err
		}
		if err = w.authority.RecordRetiredSeal(ctx, enrollmentBinding(e)); err != nil {
			return err
		}
	}
	return w.store.RecordStoreSeal(ctx, controlplane.StoreSeal{AgentID: proof.AgentID, HostID: w.hostID,
		ID: proof.ID, Generation: proof.Generation, Device: proof.Device, Inode: proof.Inode})
}
