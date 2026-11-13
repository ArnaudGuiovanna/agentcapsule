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
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := w.refreshCredentials(ctx, opts.AttemptTimeout)
		if opts.Dispatch != nil && ctx.Err() == nil {
			err = errors.Join(err, w.DispatchPass(ctx, *opts.Dispatch, opts.AttemptTimeout))
		}
		if opts.Archives != nil && ctx.Err() == nil {
			// Each capture reports itself; only a failed selection joins err.
			err = errors.Join(err, w.ArchivePass(ctx, opts.Archives))
		}
		if opts.Report != nil {
			opts.Report(err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(opts.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
