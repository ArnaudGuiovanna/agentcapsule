//go:build linux

package worker

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (w *Placements) lifecycleOperation(ctx context.Context, job controlplane.WorkerJob) error {
	if job.HostID != w.hostID {
		return controlplane.ErrPlacement
	}
	return w.host.WithBarrier(ctx, job.AgentID, func(ctx context.Context) error {
		runs, err := w.Reconcile(ctx)
		if err != nil {
			return err
		}
		op, err := w.store.BeginLifecycleOperation(ctx, job.ID, job.AgentID, w.hostID)
		if err != nil {
			return err
		}
		if op.Status != "RUNNING" {
			return nil
		}
		if op.Kind == "sleep" {
			// A clean guest ACK precedes physical retirement. Missing or failed
			// quiescence stays visible in the operation's unclean_stop result.
			if op.Placement.State != "STOPPED" {
				if err = w.quiesceStop(ctx, job.AgentID, op.Placement.Generation); err != nil {
					return err
				}
			}
			return w.store.CompleteLifecycleOperation(ctx, op, op.Placement.Generation, "")
		}
		if run, ok := runs[job.AgentID]; ok && run.FenceOnly {
			if err = w.stop(ctx, job.AgentID, run.Generation, true); err != nil {
				return err
			}
		}
		if _, _, err = w.retireDueCredentials(ctx, job.AgentID); err != nil {
			return err
		}
		// A wake waits for capacity like any work, in arrival order (ADR 017).
		run, err := w.bootForWork(ctx, job.AgentID)
		if errors.Is(err, controlplane.ErrAgentFailed) {
			// The agent spent its restart budget: the wake ends FAILED
			// rather than retrying a boot that is refused (ADR 012).
			return w.store.FailWakeOfFailedAgent(ctx, op)
		}
		if err != nil {
			return err
		}
		// start returns only after the host has durably published RUNNING and
		// validated the capsule contract, including reuse of an observed VMM.
		// Reconcile's physical RUNNING census alone must never complete wake.
		// SQL confirmation alone is insufficient: a worker crash in between
		// retires that attempt, leaving this operation discoverable for retry.
		return w.store.CompleteLifecycleOperation(ctx, op, run.Generation, run.ID)
	})
}

// resume boots an agent whose VM stopped while it held work in progress (an
// invocation it acknowledged "working", a request it was processing), so that
// its harness takes that work up again (ADR 017). It waits for capacity like
// any work, and does nothing once the agent runs or the work ended.
func (w *Placements) resume(ctx context.Context, job controlplane.WorkerJob) error {
	if job.HostID != w.hostID {
		return controlplane.ErrPlacement
	}
	return w.host.WithBarrier(ctx, job.AgentID, func(ctx context.Context) error {
		runs, err := w.Reconcile(ctx)
		if err != nil {
			return err
		}
		run, running := runs[job.AgentID]
		if running && !run.FenceOnly {
			return nil
		}
		due, err := w.store.ResumeDue(ctx, job.AgentID)
		if err != nil || !due {
			return err
		}
		if running {
			if err = w.stop(ctx, job.AgentID, run.Generation, true); err != nil {
				return err
			}
		}
		if _, _, err = w.retireDueCredentials(ctx, job.AgentID); err != nil {
			return err
		}
		_, err = w.bootForWork(ctx, job.AgentID)
		return err
	})
}
