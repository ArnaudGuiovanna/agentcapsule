//go:build linux

package worker

import (
	"context"
	"errors"
	"net"
	"slices"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

var (
	jobKinds     = []string{"provision", "lifecycle", "delivery", "closure", "deletion", "expiration"}
	retryReasons = []string{"wake_budget", "slim_unavailable", "capacity", "error"}
)

// RetryReason classifies why work waits for its next attempt, for metrics
// and events: the organization's wake budget, an absent SLIM bridge or node,
// the host's VM capacity, or any other error.
func RetryReason(err error) string {
	var bridge *slimlink.BridgeError
	var socket *net.OpError
	switch {
	case errors.Is(err, controlplane.ErrWakeBudget):
		return "wake_budget"
	case errors.As(err, &bridge), errors.As(err, &socket) && socket.Net == "unix":
		return "slim_unavailable"
	case errors.Is(err, runtime.ErrCapacity):
		return "capacity"
	}
	return "error"
}

type workerTelemetry struct {
	jobs         *telemetry.Counter
	waits        *telemetry.Counter
	starts       *telemetry.Counter
	startSeconds *telemetry.Histogram
}

// EnableTelemetry registers the worker's metrics (OPS-02): jobs by kind and
// outcome, why work waits, VM boots and their duration, and, read at each
// scrape, the host's queue by kind, its running VMs against its capacity, and
// how full the runtime root's file system is. No agent or organization
// identifier is a label.
func (w *Placements) EnableTelemetry(registry *telemetry.Registry, root string, maxActive int) error {
	kind := telemetry.Label{Name: "kind", Values: jobKinds}
	m := &workerTelemetry{
		jobs: registry.Counter("agentcapsule_worker_jobs_total", "Durable jobs processed, by kind and outcome (done, retried).",
			kind, telemetry.Label{Name: "outcome", Values: []string{"done", "retried"}}),
		waits: registry.Counter("agentcapsule_worker_job_retries_total", "Jobs put back to wait, by kind and reason.",
			kind, telemetry.Label{Name: "reason", Values: retryReasons}),
		starts: registry.Counter("agentcapsule_worker_vm_starts_total", "VM boots for work, by outcome (started, failed).",
			telemetry.Label{Name: "outcome", Values: []string{"started", "failed"}}),
		startSeconds: registry.Histogram("agentcapsule_worker_vm_start_seconds", "Duration of successful VM boots.",
			[]float64{0.5, 1, 2, 5, 10, 20, 30, 60, 120}),
	}
	jobs := registry.Gauge("agentcapsule_worker_jobs", "Jobs of this host, by kind.", kind)
	due := registry.Gauge("agentcapsule_worker_jobs_due", "Jobs due and not held by a worker, by kind.", kind)
	failing := registry.Gauge("agentcapsule_worker_jobs_failing", "Jobs that failed three times or more, by kind.", kind)
	oldest := registry.Gauge("agentcapsule_worker_job_oldest_due_seconds", "How long the oldest due job has waited past its time, by kind.", kind)
	running := registry.Gauge("agentcapsule_worker_vms_running", "VMs of this host published as running.")
	registry.Gauge("agentcapsule_worker_vm_capacity", "VMs this host may run at once (max_active).").Set(float64(maxActive))
	disk := registry.Gauge("agentcapsule_worker_root_disk_used_ratio", "Used share of the file system holding the runtime root (0 to 1).")
	registry.Collect(func(ctx context.Context) error {
		stats, err := w.store.WorkQueue(ctx, w.hostID)
		if err != nil {
			return err
		}
		for _, g := range []*telemetry.Gauge{jobs, due, failing, oldest} {
			g.Reset()
		}
		for _, k := range jobKinds {
			jobs.Set(0, k)
			due.Set(0, k)
			failing.Set(0, k)
			oldest.Set(0, k)
		}
		for _, s := range stats {
			jobs.Set(float64(s.Jobs), s.Kind)
			due.Set(float64(s.Due), s.Kind)
			failing.Set(float64(s.Failing), s.Kind)
			oldest.Set(s.OldestDue.Seconds(), s.Kind)
		}
		n, err := w.store.RunningPlacements(ctx, w.hostID)
		if err != nil {
			return err
		}
		running.Set(float64(n))
		var fs syscall.Statfs_t
		if err = syscall.Statfs(root, &fs); err != nil {
			return err
		}
		if fs.Blocks > 0 {
			disk.Set(1 - float64(fs.Bavail)/float64(fs.Blocks))
		}
		return nil
	})
	if !w.metrics.CompareAndSwap(nil, m) {
		return controlplane.ErrConflict
	}
	return nil
}

func (w *Placements) countJob(kind string, err error) {
	m := w.metrics.Load()
	if m == nil {
		return
	}
	if err == nil {
		m.jobs.Inc(kind, "done")
		return
	}
	m.jobs.Inc(kind, "retried")
	m.waits.Inc(kind, RetryReason(err))
}

func (w *Placements) countStart(started time.Time, err error) {
	m := w.metrics.Load()
	if m == nil {
		return
	}
	if err != nil {
		m.starts.Inc("failed")
		return
	}
	m.starts.Inc("started")
	m.startSeconds.Since(started)
}

// JobKinds and RetryReasons are the vocabularies of the worker's job events.
func JobKinds() []string     { return slices.Clone(jobKinds) }
func RetryReasons() []string { return slices.Clone(retryReasons) }

type jobEvents struct{ progress, problems *telemetry.Logger }

// EnableJobEvents writes one event per job processed: job_done to progress,
// job_retried with its reason to problems. Each carries the job's kind and,
// when an API request started the work, that request's X-Request-ID (OPS-02),
// so that a person's report leads from the API's log to the worker's.
func (w *Placements) EnableJobEvents(progress, problems *telemetry.Logger) error {
	if progress == nil || problems == nil || !w.jobEvents.CompareAndSwap(nil, &jobEvents{progress, problems}) {
		return controlplane.ErrConflict
	}
	return nil
}

func (w *Placements) logJob(j controlplane.WorkerJob, err error) {
	e := w.jobEvents.Load()
	if e == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fields := []telemetry.Field{telemetry.Code("kind", j.Kind)}
	if origin, lookup := w.store.JobOrigin(ctx, j); lookup == nil && origin != "" {
		fields = append(fields, telemetry.RequestID(origin))
	}
	if err == nil {
		e.progress.Event("job_done", fields...)
		return
	}
	e.problems.Event("job_retried", append(fields, telemetry.Code("reason", RetryReason(err)))...)
}
