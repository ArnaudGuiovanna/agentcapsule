//go:build linux

package worker

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// EnableDeletionTelemetry registers, read at each scrape from PostgreSQL, the
// number of this host's agents whose deletion is requested and not finished,
// and the age of the oldest (ADR 018). Until a deletion finishes, the agent's
// volume key exists and its archives still open. With a key authority, a
// deletion finishes once the key and the volume are destroyed; without one,
// once the execution is sealed. No agent identifier is a label. Call it once
// per registry.
func (w *Placements) EnableDeletionTelemetry(registry *telemetry.Registry) error {
	if registry == nil {
		return controlplane.ErrInput
	}
	unfinished := registry.Gauge("agentcapsule_worker_deletions_unfinished",
		"Agents of this host whose deletion is requested and not finished: their volume key is not destroyed yet.")
	oldest := registry.Gauge("agentcapsule_worker_deletion_oldest_seconds",
		"Age of the oldest unfinished deletion of this host's agents; 0 when none.")
	sealOnly := w.provisioning == nil
	registry.Collect(func(ctx context.Context) error {
		n, age, err := w.store.UnfinishedDeletions(ctx, w.hostID, sealOnly)
		if err != nil {
			return err
		}
		unfinished.Set(float64(n))
		oldest.Set(age.Seconds())
		return nil
	})
	return nil
}
