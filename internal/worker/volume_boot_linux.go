//go:build linux

package worker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type preparedVolume struct {
	rootReceipt restoreauthority.Receipt
	caller      controlplane.VMCaller
	plan        controlplane.VolumeBootPlan
}

func volumeCommand(plan controlplane.VolumeBootPlan) (capsuleprotocol.VolumeBoot, error) {
	v := capsuleprotocol.VolumeBoot{Incarnation: plan.Enrollment.Incarnation, VolumeID: plan.Enrollment.VolumeID, Initialize: plan.Initialize, PreviousShutdown: capsuleprotocol.ShutdownClean,
		Restore: plan.Restore}
	if plan.UncleanStop {
		v.PreviousShutdown = capsuleprotocol.ShutdownUnclean
	}
	if len(v.VolumeID) != 36 {
		return v, capsuleprotocol.ErrVolumeBoot
	}
	h := v.VolumeID[4:]
	v.UUID = h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	return v, v.Validate()
}

func (w *Placements) withVolumeBoot(opts runtime.FirecrackerOptions, keys keyauthority.Provider) (runtime.FirecrackerOptions, error) {
	if !opts.AuthenticatedControl || opts.PrepareGuest != nil || opts.Confirm == nil {
		return opts, capsuleprotocol.ErrVolumeBoot
	}
	confirm := opts.Confirm
	// The host lifecycle lock serializes PrepareGuest -> health -> Confirm for
	// every boot, including different agents. Keep only that one transient ACK,
	// never a key. A failed health probe or crashed worker cannot leave a durable
	// initialization receipt. The next attempt invalidates any unconsumed ACK.
	var mu sync.Mutex
	var prepared *preparedVolume
	caller := func(id string, run runtime.VMRun) controlplane.VMCaller {
		return controlplane.VMCaller{AgentID: id, HostID: w.hostID, Generation: run.Generation, VMID: run.ID}
	}
	opts.PrepareGuest = func(ctx context.Context, id string, run runtime.VMRun, client *capsuleprotocol.Client) error {
		mu.Lock()
		prepared = nil
		mu.Unlock()
		proof := caller(id, run)
		plan, err := w.store.PrepareVolumeBoot(ctx, proof, w.workerID)
		if err != nil {
			return err
		}
		command, err := volumeCommand(plan)
		if err != nil || client == nil || run.Incarnation != plan.Enrollment.Incarnation || ((plan.Initialize || plan.Restore) && !run.FenceOnly) {
			return capsuleprotocol.ErrVolumeBoot
		}
		unlock := func() error {
			return keys.WithKey(ctx, id, plan.Enrollment.VolumeID, func(key []byte) error {
				for {
					// WithKey may have waited on a revocation/creation lock. A lost
					// response can also require a retry. Recheck current SQL authority
					// before each transmission, without retaining a SQL transaction.
					current, err := w.store.PrepareVolumeBoot(ctx, proof, w.workerID)
					if err != nil {
						return err
					}
					if current != plan {
						return controlplane.ErrStoreEnrollment
					}
					err = client.OpenVolume(ctx, command, key)
					if !errors.Is(err, capsuleprotocol.ErrTransport) {
						return err
					}
					timer := time.NewTimer(20 * time.Millisecond)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
					}
				}
			})
		}
		if w.authority != nil {
			err = w.authority.WithBinding(ctx, enrollmentBinding(plan.Enrollment), unlock)
		} else {
			err = unlock()
		} // explicit preprovisioned/laboratory path
		if err != nil {
			return err
		}
		health, err := client.HealthStatus(ctx)
		if err != nil {
			return err
		}
		if health.PreviousShutdown != command.PreviousShutdown || health.Identity.Incarnation != run.Incarnation {
			return capsuleprotocol.ErrVolumeBoot
		}
		if err = client.RequireControlContract(ctx); err != nil {
			return err
		}
		var rootReceipt restoreauthority.Receipt
		if w.authority != nil {
			rootReceipt, err = w.synchronizeAuthority(ctx, plan.Enrollment, client)
			if err != nil {
				return err
			}
		}
		mu.Lock()
		prepared = &preparedVolume{caller: proof, plan: plan, rootReceipt: rootReceipt}
		mu.Unlock()
		return nil
	}
	opts.Confirm = func(ctx context.Context, id string, run runtime.VMRun) error {
		mu.Lock()
		ack := prepared
		prepared = nil
		mu.Unlock()
		if ack == nil || ack.caller != caller(id, run) || ack.plan.Enrollment.Incarnation != run.Incarnation || (ack.plan.AcknowledgeInitialization && !run.FenceOnly) {
			return capsuleprotocol.ErrVolumeBoot
		}
		publish := func() error {
			if err := confirm(ctx, id, run); err != nil {
				return err
			}
			if ack.plan.AcknowledgeInitialization {
				// SQL confirmation and this receipt can be interrupted separately.
				// Failure retires this VMM; a missing receipt only causes another
				// restricted validation boot, never premature activation.
				return w.store.RecordEnrollmentInitialized(ctx, controlplane.EnrollmentBoot{Incarnation: run.Incarnation,
					AgentID: id, HostID: w.hostID, VolumeID: ack.plan.Enrollment.VolumeID,
					Generation: run.Generation, VMID: run.ID,
				})
			}
			return nil
		}
		if w.authority != nil {
			return w.authority.WithCurrentFences(ctx, ack.rootReceipt, publish)
		}
		return publish()
	}
	return opts, nil
}
