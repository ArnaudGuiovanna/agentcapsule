//go:build linux

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

type DispatchOptions struct {
	Batch                                         int
	WorkLease, DeliveryLease, RetryBase, RetryMax time.Duration
}

func (o DispatchOptions) valid() bool {
	return o.Batch >= 1 && o.Batch <= 256 && o.WorkLease >= time.Microsecond && o.WorkLease <= 24*time.Hour && o.DeliveryLease >= time.Microsecond && o.DeliveryLease <= 24*time.Hour && o.RetryBase >= time.Microsecond && o.RetryMax >= o.RetryBase && o.RetryMax <= 24*time.Hour
}
func (o DispatchOptions) backoff(failures int) time.Duration {
	d := o.RetryBase
	for i := 0; i < failures && d < o.RetryMax; i++ {
		if d > o.RetryMax/2 {
			return o.RetryMax
		}
		d *= 2
	}
	return d
}

// DispatchPass processes bounded, durable jobs. Queue leases coordinate workers;
// business leases, immutable envelopes and SQL/host fences remain authoritative.
// ClaimWork moves a job to the tail, so new work and retries cannot monopolize it.
func (w *Placements) DispatchPass(ctx context.Context, o DispatchOptions, attemptTimeout time.Duration) error {
	if !o.valid() || attemptTimeout <= 0 {
		return errors.New("invalid dispatch options")
	}
	// Scheduling runs first so what it produces is discovered in this same pass.
	// Both steps use the database clock and are safe to repeat after a crash.
	var result error
	{
		step, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, releaseErr := w.store.ReleaseDueInstructions(step, nil, o.Batch)
		_, idleErr := w.store.ScheduleIdleSleeps(step, w.hostID, nil, o.Batch)
		_, workErr := w.store.ExpireWorkingInvocations(step, nil, o.Batch)
		result = errors.Join(releaseErr, idleErr, workErr)
		cancel()
	}
	step, cancel := context.WithTimeout(ctx, attemptTimeout)
	err := w.store.DiscoverWork(step, w.hostID, o.Batch*4)
	cancel()
	if err != nil {
		return errors.Join(result, err)
	}
	{
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, receiptErr := w.store.PurgeExpiredReceipts(purge, min(o.Batch*4, 1000))
		result = errors.Join(result, receiptErr)
		cancel()
	}
	if transit := w.transit.Load(); transit != nil {
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, purgeErr := transit.PurgeExpired(purge, min(o.Batch*4, 1000))
		result = errors.Join(result, purgeErr)
		cancel()
	}
	{
		// After the transit purge: an attachment goes once its invocation's own
		// content has gone, or when it expired unused.
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, attachmentErr := w.store.PurgeAttachments(purge, nil, min(o.Batch*4, 1000))
		result = errors.Join(result, attachmentErr)
		cancel()
	}
	for range o.Batch {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
		job, err := w.store.ClaimWork(attempt, w.hostID, o.WorkLease)
		if errors.Is(err, controlplane.ErrNoWork) {
			cancel()
			break
		}
		if err != nil {
			cancel()
			return errors.Join(result, err)
		}
		if w.afterWorkClaim != nil {
			w.afterWorkClaim(job)
		}
		err = w.executeWork(attempt, job, o.DeliveryLease)
		w.countJob(job.Kind, err)
		w.logJob(job, err)
		if err == nil && w.afterWork != nil {
			w.afterWork(job)
		}
		cancel()
		finish, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err == nil {
			err = w.store.CompleteWork(finish, job)
		} else {
			err = errors.Join(err, w.store.RetryWork(finish, job, o.backoff(job.Failures)))
		}
		finishCancel()
		result = errors.Join(result, err)
	}
	return result
}

func (w *Placements) executeWork(ctx context.Context, j controlplane.WorkerJob, deliveryLease time.Duration) error {
	switch j.Kind {
	case "provision":
		return w.provision(ctx, j)
	case "lifecycle":
		return w.lifecycleOperation(ctx, j)
	case "delivery":
		var err error
		if transit := w.transit.Load(); transit != nil {
			err = transit.DispatchMailbox(ctx, j.ID, deliveryLease, w)
		} else {
			err = w.store.DispatchMailbox(ctx, j.ID, deliveryLease, w)
		}
		if errors.Is(err, controlplane.ErrNoDelivery) {
			return nil
		}
		return err
	case "closure":
		return w.store.ReconcileRequestClosure(ctx, j.ID, w)
	case "deletion":
		if err := w.store.ReconcileRevocation(ctx, j.ID, w); err != nil {
			return err
		}
		return w.RemoveDeletedStore(ctx, j.ID)
	case "expiration":
		err := w.store.RequestExpiration(ctx, j.ID)
		if errors.Is(err, controlplane.ErrTransition) {
			return nil
		}
		if err != nil && !errors.Is(err, controlplane.ErrClosurePending) {
			return err
		}
		return w.store.ReconcileRequestClosure(ctx, j.ID, w)
	default:
		return errors.New("unknown worker job kind")
	}
}
