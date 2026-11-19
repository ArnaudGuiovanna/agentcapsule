//go:build linux

package worker

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func (w *Placements) rolloutPass(ctx context.Context) error {
	id, agent, err := w.store.NextRollout(ctx, w.hostID)
	if errors.Is(err, controlplane.ErrNoWork) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.host.WithBarrier(ctx, agent, func(ctx context.Context) error {
		runs, err := w.reconcileAgent(ctx, agent)
		if err != nil {
			return err
		}
		run, running := runs[agent]
		step, err := w.store.RolloutStep(ctx, id, agent, w.hostID, running && !run.FenceOnly)
		if errors.Is(err, controlplane.ErrNoWork) {
			return nil
		}
		if errors.Is(err, controlplane.ErrRelease) {
			return w.store.PauseRollout(ctx, id, agent, "artifact_unavailable")
		}
		if errors.Is(err, controlplane.ErrUnavailable) {
			return w.store.PauseRollout(ctx, id, agent, "agent_unavailable")
		}
		if err != nil {
			return err
		}
		// The importer's refill loop also sees this campaign's target as pinned.
		// An absent or invalid package stops the canary before the old VM is retired.
		if step.Stage == "draining" || step.Stage == "validating" {
			img, err := w.resolveHarness(ctx, step.Target)
			if err != nil {
				return w.store.PauseRollout(ctx, id, agent, "artifact_unavailable")
			}
			if running && (run.Rollout != id || run.FenceOnly) {
				if err = w.quiesceStop(ctx, agent, run.Generation); err != nil {
					return err
				}
				running = false
			}
			if !running {
				resources := runtime.VMResources{VCPUs: step.Spec.Resources.VCPUs, MemoryMiB: step.Spec.Resources.MemoryMiB, VolumeMiB: step.Spec.Resources.DataVolumeMiB}
				if step.Resize {
					err = w.host.ResizeRollout(ctx, agent, id, resources)
				} else {
					err = w.host.SetRolloutProfile(ctx, agent, id, resources, bootImageID(step.Target), img)
				}
				if err != nil {
					return w.store.PauseRollout(ctx, id, agent, "update_failed")
				}
			}
			if step.Stage == "draining" {
				if err = w.store.InstallRolloutSpec(ctx, step); err != nil {
					return w.store.PauseRollout(ctx, id, agent, "update_failed")
				}
			}
			run, err = w.startPlacement(ctx, agent, false, nil, id)
			if errors.Is(err, runtime.ErrCapacity) || errors.Is(err, controlplane.ErrOrganizationQuota) {
				return w.store.WaitRolloutCapacity(ctx, step)
			}
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return w.store.PauseRollout(ctx, id, agent, "boot_failed")
			}
			if run.Rollout != id || run.FenceOnly {
				return w.store.PauseRollout(ctx, id, agent, "boot_failed")
			}
			if err = w.store.ObserveRolloutBoot(ctx, step, run.Generation, run.ID); err != nil {
				return err
			}
			running = true
		}
		if !step.KeepRunning && running {
			if err = w.quiesceStop(ctx, agent, run.Generation); err != nil {
				return err
			}
		}
		return w.store.FinishRolloutStep(ctx, step)
	})
}
