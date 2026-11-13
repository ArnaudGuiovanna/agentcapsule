//go:build linux

package worker

import (
	"context"
	"io"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// CaptureArchive is a trusted operator/worker operation. It leaves the agent
// stopped. Owner wake/admission may resume after capture; no restore is implied.
// The archive contains only the LUKS container and its authenticated manifest.
func (w *Placements) CaptureArchive(ctx context.Context, id, archiveID string, archives *volumearchive.Store) (restoreauthority.Archive, error) {
	return w.captureArchive(ctx, id, archiveID, archives, archiveHooks{})
}

// archiveHooks run under the agent's barrier, so that no delivery, wake or
// other capture of the agent interleaves with them.
type archiveHooks struct {
	// begin runs after reconciliation, before anything stops: running says
	// whether a VM of the agent runs. An error captures nothing.
	begin func(ctx context.Context, running bool) error
	// published runs once the archive is published.
	published func(ctx context.Context, a restoreauthority.Archive) error
}

func (w *Placements) captureArchive(ctx context.Context, id, archiveID string, archives *volumearchive.Store, hooks archiveHooks) (restoreauthority.Archive, error) {
	var result restoreauthority.Archive
	if w.provisioning == nil || w.authority == nil || archives == nil || !volumearchive.ValidID(archiveID) {
		return result, controlplane.ErrInput
	}
	keys, ok := w.provisioning.keys.(interface{ SeparateFrom(string) error })
	if !ok {
		return result, controlplane.ErrInput
	}
	for _, check := range []func() error{
		func() error { return restoreauthority.CheckSeparation(w.provisioning.runtimeRoot, archives.Root()) },
		func() error { return w.authority.SeparateFrom(archives.Root()) },
		func() error { return keys.SeparateFrom(archives.Root()) },
	} {
		if err := check(); err != nil {
			return result, err
		}
	}
	err := w.host.WithBarrier(ctx, id, func(ctx context.Context) error {
		runs, err := w.Reconcile(ctx)
		if err != nil {
			return err
		}
		run, exists := runs[id]
		if hooks.begin != nil {
			if err = hooks.begin(ctx, exists); err != nil {
				return err
			}
		}
		if exists {
			if err = w.quiesceStop(ctx, id, run.Generation); err != nil {
				return err
			}
		}
		plan, err := w.store.StoreArchiveTarget(ctx, id, w.hostID)
		if err != nil {
			return err
		}
		e := plan.Enrollment
		binding := enrollmentBinding(e)
		if err = w.authority.WithBinding(ctx, binding, func() error { return nil }); err != nil {
			return err
		}
		err = w.host.WithStoppedVolume(ctx, id, plan.Placement.Generation, plan.Device, plan.Inode, func(reader io.Reader) error {
			result, err = archives.Capture(ctx, volumearchive.Spec{ID: archiveID, Binding: binding, HarnessDigest: e.HarnessDigest, Size: int64(e.Resources.DataVolumeMiB) << 20}, reader, w.authority)
			return err
		})
		if err == nil && hooks.published != nil {
			err = hooks.published(ctx, result)
		}
		return err
	})
	if err != nil {
		return restoreauthority.Archive{}, err
	}
	return result, nil
}
