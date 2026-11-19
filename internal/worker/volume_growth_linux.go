//go:build linux

package worker

import (
	"context"
	"errors"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// GrowthPass runs one durable stage. The exclusive admission barrier serializes
// physical changes. The durable growth and restore records guard the handoffs.
func (w *Placements) GrowthPass(ctx context.Context, archives *volumearchive.Store) error {
	g, err := w.store.NextGrowth(ctx, w.hostID)
	if errors.Is(err, controlplane.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if archives == nil {
		if g.Stage == "pending" {
			return w.store.RefuseGrowth(ctx, g, "archive_unconfigured")
		}
		return ErrArchiveUnavailable
	}
	switch g.Stage {
	case "pending":
		return w.host.WithBarrier(ctx, g.AgentID, func(ctx context.Context) error {
			if err := w.probeVolumeFeatures(ctx, g.AgentID, true); err != nil {
				if errors.Is(err, capsuleprotocol.ErrUnsupportedProtocol) {
					return w.store.RefuseGrowth(ctx, g, "guest_incompatible")
				}
				return err
			}
			return w.store.AdvanceGrowth(ctx, g, "capturing")
		})
	case "capturing":
		if _, err = w.CaptureArchive(ctx, g.AgentID, g.ArchiveID, archives); err != nil {
			return err
		}
		return w.store.AdvanceGrowth(ctx, g, "restoring")
	case "restoring":
		if _, err = w.RestoreFromArchive(ctx, g.RestoreID, g.AgentID, g.ArchiveID, archives, nil); err != nil {
			return err
		}
		return w.store.AdvanceGrowth(ctx, g, "succeeded")
	}
	return controlplane.ErrTransition
}
