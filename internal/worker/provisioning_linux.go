//go:build linux

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

type ProvisioningConfig struct {
	FirstUID uint32 `json:"first_uid"`
	LastUID  uint32 `json:"last_uid"`
}

func (c ProvisioningConfig) valid() bool {
	return c.FirstUID >= 10000 && c.LastUID >= c.FirstUID && c.LastUID < ^uint32(0) && c.LastUID-c.FirstUID <= 1<<20
}

type provisioner struct {
	keys        keyauthority.Provider
	volumes     *volumestore.Store
	digest      string
	config      ProvisioningConfig
	runtimeRoot string
}

// NewProvisioningPlacements supports the approved local guest image pinned by
// opts.InitrdSHA256. Its digest must match the reserved harness release. OCI
// artifact fetching/assembly remains a separate future source of approved images.
func NewProvisioningPlacements(store *controlplane.Store, hostID, workerID string, lease time.Duration, opts runtime.FirecrackerOptions, keys *keyauthority.Files, authority *restoreauthority.Catalog, config ProvisioningConfig) (*Placements, error) {
	if keys == nil || authority == nil || !config.valid() {
		return nil, controlplane.ErrInput
	}
	if err := keys.SeparateFrom(opts.Root); err != nil {
		return nil, err
	}
	w, err := NewPlacementsWithAuthority(store, hostID, workerID, lease, opts, keys, authority)
	if err != nil {
		return nil, err
	}
	volumes, err := volumestore.New(opts.Root)
	if err != nil {
		w.Close()
		return nil, err
	}
	w.provisioning = &provisioner{keys: keys, volumes: volumes, digest: "sha256:" + opts.InitrdSHA256, config: config, runtimeRoot: opts.Root}
	return w, nil
}

func (w *Placements) provision(ctx context.Context, job controlplane.WorkerJob) error {
	p := w.provisioning
	if p == nil || job.HostID != w.hostID {
		return errors.New("provisioning not configured for this host")
	}
	e, err := w.store.ProvisioningTarget(ctx, job.AgentID, w.hostID, job.ID)
	if err != nil {
		return err
	}
	if e.Stage == "READY" {
		return nil
	}
	harness, err := w.resolveHarness(ctx, e)
	if err != nil {
		return err
	}
	if e.Stage == "INSTALLING" {
		binding, err := w.authority.Register(ctx, e.AgentID, e.VolumeID)
		if err != nil {
			return err
		}
		if binding != enrollmentBinding(e) {
			return restoreauthority.ErrStale
		}
		if err = p.keys.Ensure(ctx, e.AgentID, e.VolumeID); err != nil {
			return err
		}
		var volume volumestore.Container
		err = w.authority.WithBinding(ctx, enrollmentBinding(e), func() error {
			return p.keys.WithKey(ctx, e.AgentID, e.VolumeID, func(key []byte) error {
				var err error
				volume, err = p.volumes.Prepare(ctx, volumestore.Spec{AgentID: e.AgentID, VolumeID: e.VolumeID, SizeMiB: int64(e.Resources.DataVolumeMiB)}, key)
				return err
			})
		})
		if err != nil {
			return err
		}
		registration := runtime.ProvisionedAgent{ID: e.AgentID, Volume: volume.Path, Device: volume.Device, Inode: volume.Inode, Resources: runtime.VMResources{VCPUs: e.Resources.VCPUs, MemoryMiB: e.Resources.MemoryMiB, VolumeMiB: e.Resources.DataVolumeMiB},
			Harness: harness}
		if err = w.host.RegisterProvisioned(ctx, registration, p.config.FirstUID, p.config.LastUID); err != nil {
			return err
		}
		if err = w.store.RecordProvisionedVolume(ctx, controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: volume.Device, Inode: volume.Inode}); err != nil {
			return err
		}
	}
	return w.host.WithBarrier(ctx, e.AgentID, func(ctx context.Context) (result error) {
		// Another worker may have completed this job while admission waited.
		current, err := w.store.ProvisioningTarget(ctx, e.AgentID, e.HostID, e.OperationID)
		if err != nil {
			return err
		}
		if current.Stage == "READY" {
			return nil
		}
		if current.Stage != "FENCING" {
			return controlplane.ErrStoreEnrollment
		}
		if _, _, err = w.retireDueCredentials(ctx, e.AgentID); err != nil {
			return err
		}
		run, err := w.start(ctx, e.AgentID, true)
		if errors.Is(err, runtime.ErrCapacity) {
			if err = w.makeBarrierCapacity(ctx, e.AgentID); err != nil {
				return err
			}
			run, err = w.start(ctx, e.AgentID, true)
		}
		if err != nil {
			return err
		}
		stopped := false
		defer func() {
			if !stopped {
				cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				result = errors.Join(result, w.stop(cleanup, e.AgentID, run.Generation, true))
			}
		}()
		if !run.FenceOnly {
			return controlplane.ErrPlacement
		}
		client, err := w.host.Control(ctx, e.AgentID)
		if err != nil {
			return err
		}
		pending, err := w.store.EnrollmentPendingFences(ctx, e.AgentID, e.HostID, e.VolumeID)
		if err != nil {
			return err
		}
		for _, subject := range pending {
			if err = client.Fence(ctx, subject); err != nil {
				return err
			}
			if err = w.store.RecordEnrollmentFence(ctx, controlplane.EnrollmentFence{Incarnation: run.Incarnation, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: run.Generation, VMID: run.ID, Subject: subject}); err != nil {
				return err
			}
		}
		// The SQL pending scan may have observed a newer intent than boot
		// preparation. Import and acknowledge that full catalogue before this
		// new store becomes LIVE; otherwise it could escape an older census.
		receipt, err := w.synchronizeAuthority(ctx, e, client)
		if err != nil {
			return err
		}
		if err = w.quiesceStop(ctx, e.AgentID, run.Generation); err != nil {
			return err
		}
		stopped = true
		// This transaction checks the CURRENT revocation catalogue. A new
		// revocation since the scan above retains the job for another pass.
		return w.authority.WithCurrentFences(ctx, receipt, func() error { return w.store.ActivateProvisionedAgent(ctx, e) })
	})
}
