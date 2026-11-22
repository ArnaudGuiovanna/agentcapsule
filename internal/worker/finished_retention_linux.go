//go:build linux

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// finishedPurgeEvery spaces the purges of finished records: their retention
// is counted in days.
const finishedPurgeEvery = 10 * time.Minute

// finishedRetention is the configuration's finished_retention: a duration
// from 45 days to 10 years, 90 days when absent. It must exceed the horizon
// of the host's own archives by two weeks: a restore from the oldest archive
// still finds every event it lost (ADR 003, 008).
func (c ServiceConfig) finishedRetention() (time.Duration, error) {
	invalid := errors.New("invalid finished_retention")
	retention := controlplane.DefaultFinishedRetention
	if c.FinishedRetention != "" {
		var err error
		if retention, err = time.ParseDuration(c.FinishedRetention); err != nil {
			return 0, invalid
		}
	}
	if retention < controlplane.MinFinishedRetention || retention > controlplane.MaxFinishedRetention {
		return 0, invalid
	}
	a, err := c.archives()
	if err != nil {
		return 0, invalid
	}
	if a != nil && retention < time.Duration(a.Keep)*a.Every+14*24*time.Hour {
		return 0, errors.New("finished_retention shorter than the archives' horizon")
	}
	return retention, nil
}

// purgeFinished deletes, at most every finishedPurgeEvery, a batch of this
// host's finished records past their retention (P-04). A full batch is
// followed by another at the next pass.
func (w *Placements) purgeFinished(ctx context.Context, o DispatchOptions, timeout time.Duration) error {
	last := time.Unix(0, w.finishedPurgedAt.Load())
	if time.Since(last) < finishedPurgeEvery {
		return nil
	}
	retention := o.Retention
	if retention == 0 {
		retention = controlplane.DefaultFinishedRetention
	}
	limit := min(o.Batch*4, 1000)
	purge, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	n, err := w.store.PurgeFinished(purge, w.hostID, nil, retention, limit)
	if err == nil && n.Requests < int64(limit) && n.Lifecycle < int64(limit) && n.Invocations < int64(limit) {
		w.finishedPurgedAt.Store(time.Now().UnixNano())
	}
	return err
}
