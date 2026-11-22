//go:build linux

package worker

import (
	"context"
	"errors"
	"time"
)

type MaintenanceOptions struct {
	Interval       time.Duration
	AttemptTimeout time.Duration
	// Nil keeps the explicit maintenance-only API. The service command enables
	// business dispatch with validated defaults in its configuration.
	Dispatch *DispatchOptions
	// Wake, when set with Dispatch, starts a dispatch pass before Interval
	// ends: the database notifies new work for this host (P-01). A lost
	// notification only delays work until the next pass.
	Wake <-chan struct{}
	// Archives, when set, makes each pass capture the volume archives that
	// are due, after dispatch (REC-02). Nil takes none.
	Archives *Archives
	// Report must return promptly. The service command emits only a fixed event,
	// never raw SQL/runtime errors, credentials or message data.
	Report func(error)
}

// RunMaintenance immediately reconciles and then periodically discovers/resumes
// credential replacements without inbound work. Errors retain durable jobs;
// each attempt is bounded and other queued jobs are still attempted. This loop
// can also process the durable business queue, then capture the volume
// archives that are due. End-to-end success still requires service capacity
// and a guest able to complete its work during residency.
//
// Between these passes, every Interval, the business queue gets passes of
// its own: at once after a pass that claimed a full batch, and when Wake
// says that work arrived (P-01). They report only their errors.
func (w *Placements) RunMaintenance(ctx context.Context, opts MaintenanceOptions) error {
	if opts.Interval <= 0 || opts.AttemptTimeout <= 0 {
		return errors.New("positive maintenance interval and attempt timeout required")
	}
	if opts.Dispatch != nil && !opts.Dispatch.valid() {
		return errors.New("invalid dispatch options")
	}
	if opts.Archives != nil && !opts.Archives.valid() {
		return errors.New("invalid archive options")
	}
	full := func(ctx context.Context) bool {
		err := w.refreshCredentials(ctx, opts.AttemptTimeout)
		// The API refuses new agents and imports while a file system is
		// past the storage pressure threshold (OPS-03).
		err = errors.Join(err, w.recordStoragePressure(ctx, opts.AttemptTimeout))
		busy := false
		if opts.Dispatch != nil && ctx.Err() == nil {
			var dispatchErr error
			busy, dispatchErr = w.dispatchPass(ctx, *opts.Dispatch, opts.AttemptTimeout)
			err = errors.Join(err, dispatchErr)
		}
		if w.provisioning != nil && opts.Archives == nil && ctx.Err() == nil {
			attempt, cancel := context.WithTimeout(ctx, opts.AttemptTimeout)
			err = errors.Join(err, w.GrowthPass(attempt, nil))
			cancel()
		}
		if opts.Archives != nil && ctx.Err() == nil {
			// Each capture reports itself; only a failed selection joins err.
			attempt, cancel := context.WithTimeout(ctx, opts.Archives.Timeout)
			err = errors.Join(err, w.GrowthPass(attempt, opts.Archives.Store))
			cancel()
			err = errors.Join(err, w.ArchivePass(ctx, opts.Archives))
		}
		if opts.Report != nil {
			opts.Report(err)
		}
		return busy
	}
	var dispatch func(context.Context) bool
	if opts.Dispatch != nil {
		dispatch = func(ctx context.Context) bool {
			busy, err := w.dispatchPass(ctx, *opts.Dispatch, opts.AttemptTimeout)
			if err != nil && opts.Report != nil {
				opts.Report(err)
			}
			return busy
		}
	}
	return maintenanceLoop(ctx, opts.Interval, opts.Wake, full, dispatch)
}

// maintenanceLoop runs full at once, then Interval after each full pass
// ends. Meanwhile it runs dispatch, when set: at once while the last pass
// reported more work, and at each wake. A wake that arrives during a pass
// gives one more pass after it: wakes are merged, never lost.
func maintenanceLoop(ctx context.Context, interval time.Duration, wake <-chan struct{}, full, dispatch func(context.Context) bool) error {
	if dispatch == nil {
		wake = nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		busy := full(ctx) && dispatch != nil
		next := time.Now().Add(interval)
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !time.Now().Before(next) {
				break // the next full pass is due
			}
			if !busy {
				timer := time.NewTimer(time.Until(next))
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
					continue
				case <-wake:
					timer.Stop()
				}
			}
			busy = dispatch(ctx)
		}
	}
}
