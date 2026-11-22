//go:build linux

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// modelCallRetention is the configuration's model_call_retention: a
// duration from 35 days to 10 years, 90 days when absent.
func (c ServiceConfig) modelCallRetention() (time.Duration, error) {
	retention := controlplane.DefaultModelCallRetention
	if c.ModelCallRetention != "" {
		var err error
		if retention, err = time.ParseDuration(c.ModelCallRetention); err != nil {
			return 0, errors.New("invalid model_call_retention")
		}
	}
	if retention < controlplane.MinModelCallRetention || retention > controlplane.MaxModelCallRetention {
		return 0, errors.New("invalid model_call_retention")
	}
	return retention, nil
}

// purgeModelCalls deletes, at most every finishedPurgeEvery, a batch of the
// installation's finished model calls past their retention, and the budget
// windows that started before it. A full batch is followed by another at
// the next pass. Several workers purge side by side: each skips the rows
// another holds.
func (w *Placements) purgeModelCalls(ctx context.Context, o DispatchOptions, timeout time.Duration) error {
	last := time.Unix(0, w.modelCallsPurgedAt.Load())
	if time.Since(last) < finishedPurgeEvery {
		return nil
	}
	retention := o.ModelCallRetention
	if retention == 0 {
		retention = controlplane.DefaultModelCallRetention
	}
	limit := min(o.Batch*4, 1000)
	purge, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	n, err := w.store.PurgeModelCalls(purge, nil, retention, limit)
	if err == nil && n.Calls < int64(limit) && n.Windows < int64(limit) {
		w.modelCallsPurgedAt.Store(time.Now().UnixNano())
	}
	return err
}
