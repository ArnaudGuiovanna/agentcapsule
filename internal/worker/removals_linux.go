//go:build linux

package worker

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

// RemoveDeletedStore completes deletion of a managed product volume. Legacy
// preprovisioned hosts have no key authority and can only attest execution seal.
func (w *Placements) RemoveDeletedStore(ctx context.Context, id string) error {
	if w.provisioning == nil {
		return w.SealDeletedStore(ctx, id)
	}
	return w.host.WithBarrier(ctx, id, func(ctx context.Context) error {
		p, ready, err := w.store.StoreSealTarget(ctx, id, w.hostID)
		if err != nil {
			return err
		}
		if !ready {
			return controlplane.ErrPendingFences
		}
		// Once SQL has the seal, resume cleanup directly: a crash may already
		// have removed the volume but not persisted the final host receipt.
		plan, err := w.store.StoreRemovalTarget(ctx, id, w.hostID)
		if errors.Is(err, controlplane.ErrNotFound) || errors.Is(err, controlplane.ErrPlacement) {
			if err = w.seal(ctx, p); err != nil {
				return err
			}
			plan, err = w.store.StoreRemovalTarget(ctx, id, w.hostID)
		}
		if err != nil {
			return err
		}
		e := plan.Enrollment
		proof, err := w.host.RemoveSealedVolume(ctx, id, p.Generation, func(local runtime.StoreSeal) error {
			if local.AgentID != plan.Seal.AgentID || local.ID != plan.Seal.ID || local.Generation != plan.Seal.Generation || local.Device != plan.Seal.Device || local.Inode != plan.Seal.Inode {
				return controlplane.ErrPlacement
			}
			// A pre-existing SQL seal alone is insufficient. This callback
			// follows the host's actual permanent-seal/inode validation.
			if w.authority != nil {
				if err := w.authority.RecordRetiredSeal(ctx, enrollmentBinding(e)); err != nil {
					return err
				}
			}
			if err := w.provisioning.keys.Revoke(ctx, id, e.VolumeID); err != nil {
				return err
			}
			return w.provisioning.volumes.Remove(ctx, volumestore.Spec{AgentID: id, VolumeID: e.VolumeID, SizeMiB: int64(e.Resources.DataVolumeMiB)}, local.Device, local.Inode)
		})
		if err != nil {
			return err
		}
		if w.afterRemoval != nil {
			if err = w.afterRemoval(); err != nil {
				return err
			}
		}
		return w.store.RecordStoreRemoval(ctx, controlplane.StoreSeal{AgentID: proof.AgentID, HostID: w.hostID, ID: proof.ID, Generation: proof.Generation, Device: proof.Device, Inode: proof.Inode}, e.VolumeID)
	})
}
