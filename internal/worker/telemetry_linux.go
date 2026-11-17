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
	jobKinds     = []string{"provision", "lifecycle", "delivery", "closure", "deletion", "expiration", "resume"}
	retryReasons = []string{"wake_budget", "agent_failed", "slim_unavailable", "capacity", "organization_quota", "storage_pressure", "error"}
	// A guest fails at boot or crashes; an agent that spends its restart
	// budget is FAILED for the kind of its last failure (ADR 012).
	guestFailureKinds   = []string{controlplane.GuestBootFailed, controlplane.GuestCrashed}
	agentFailureReasons = []string{"boot_failed", "crashed"}
	// A delivery dies when its attempts are spent or its deadline passes,
	// the deadline winning when both hold (ADR 007).
	deadKinds   = []string{"reply", "status", "instruction"}
	deadReasons = []string{"attempts_exhausted", "expired"}
)

// RetryReason classifies why work waits for its next attempt, for metrics
// and events: the organization's wake budget, a FAILED agent, an absent SLIM
// bridge or node, the host's VM capacity, the organization's quotas on its
// VMs, the host's storage pressure, or any other error.
func RetryReason(err error) string {
	var bridge *slimlink.BridgeError
	var socket *net.OpError
	switch {
	case errors.Is(err, controlplane.ErrWakeBudget):
		return "wake_budget"
	case errors.Is(err, controlplane.ErrAgentFailed):
		return "agent_failed"
	case errors.As(err, &bridge), errors.As(err, &socket) && socket.Net == "unix":
		return "slim_unavailable"
	case errors.Is(err, runtime.ErrCapacity):
		return "capacity"
	case errors.Is(err, controlplane.ErrOrganizationQuota):
		return "organization_quota"
	case errors.Is(err, controlplane.ErrStoragePressure):
		return "storage_pressure"
	}
	return "error"
}

type workerTelemetry struct {
	jobs         *telemetry.Counter
	waits        *telemetry.Counter
	dead         *telemetry.Counter
	starts       *telemetry.Counter
	startSeconds *telemetry.Histogram
	// guestFailures counts failed boots and crashes of guests;
	// agentsFailed, the agents that spent their restart budget.
	guestFailures *telemetry.Counter
	agentsFailed  *telemetry.Counter
}

// EnableTelemetry registers the worker's metrics (OPS-02): jobs by kind and
// outcome, why work waits, VM boots and their duration, and, read at each
// scrape, the host's queue by kind, its running VMs against its capacity, how
// full the runtime root's file system is, and PostgreSQL's WAL archiving. No
// agent or organization identifier is a label.
func (w *Placements) EnableTelemetry(registry *telemetry.Registry, root string, maxActive int) error {
	kind := telemetry.Label{Name: "kind", Values: jobKinds}
	m := &workerTelemetry{
		jobs: registry.Counter("agentcapsule_worker_jobs_total", "Durable jobs processed, by kind and outcome (done, retried).",
			kind, telemetry.Label{Name: "outcome", Values: []string{"done", "retried"}}),
		waits: registry.Counter("agentcapsule_worker_job_retries_total", "Jobs put back to wait, by kind and reason.",
			kind, telemetry.Label{Name: "reason", Values: retryReasons}),
		dead: registry.Counter("agentcapsule_worker_deliveries_dead_total", "Deliveries that died, by kind (reply, status, instruction) and reason (attempts_exhausted, expired).",
			telemetry.Label{Name: "kind", Values: deadKinds}, telemetry.Label{Name: "reason", Values: deadReasons}),
		starts: registry.Counter("agentcapsule_worker_vm_starts_total", "VM boots for work, by outcome (started, failed).",
			telemetry.Label{Name: "outcome", Values: []string{"started", "failed"}}),
		startSeconds: registry.Histogram("agentcapsule_worker_vm_start_seconds", "Duration of successful VM boots.",
			[]float64{0.5, 1, 2, 5, 10, 20, 30, 60, 120}),
		guestFailures: registry.Counter("agentcapsule_worker_guest_failures_total", "Guests that failed to boot (boot) or went away without a stop (crash).",
			telemetry.Label{Name: "kind", Values: guestFailureKinds}),
		agentsFailed: registry.Counter("agentcapsule_worker_agents_failed_total", "Agents that spent their restart budget and are FAILED."),
	}
	// Served at zero from the start, so that increase() sees the first death
	// and the first FAILED agent.
	for _, k := range deadKinds {
		for _, r := range deadReasons {
			m.dead.Add(0, k, r)
		}
	}
	for _, k := range guestFailureKinds {
		m.guestFailures.Add(0, k)
	}
	m.agentsFailed.Add(0)
	jobs := registry.Gauge("agentcapsule_worker_jobs", "Jobs of this host, by kind.", kind)
	due := registry.Gauge("agentcapsule_worker_jobs_due", "Jobs due and not held by a worker, by kind.", kind)
	failing := registry.Gauge("agentcapsule_worker_jobs_failing", "Jobs that failed three times or more, by kind.", kind)
	oldest := registry.Gauge("agentcapsule_worker_job_oldest_due_seconds", "How long the oldest due job has waited past its time, by kind.", kind)
	running := registry.Gauge("agentcapsule_worker_vms_running", "VMs of this host published as running.")
	registry.Gauge("agentcapsule_worker_vm_capacity", "VMs this host may run at once (max_active).").Set(float64(maxActive))
	disk := registry.Gauge("agentcapsule_worker_root_disk_used_ratio", "Used share of the file system holding the runtime root (0 to 1).")
	waiting := registry.Gauge("agentcapsule_worker_invocations_waiting", "Invocations accepted for this host's agents and not yet delivered.")
	waited := registry.Gauge("agentcapsule_worker_invocation_oldest_waiting_seconds", "How long the oldest invocation not yet delivered has waited since it was accepted.")
	failedAgents := registry.Gauge("agentcapsule_worker_agents_failed", "Live agents of this host that are FAILED: they boot again only when woken or cleared.")
	queued := registry.Gauge("agentcapsule_worker_agents_queued", "Agents of this host waiting for a VM slot (QUEUED).")
	queuedOldest := registry.Gauge("agentcapsule_worker_capacity_oldest_wait_seconds", "How long the oldest agent waiting for a VM slot has waited.")
	quotaWaits := registry.Gauge("agentcapsule_worker_agents_waiting_for_quota", "Agents of this host whose work waits for their organization's quotas (QUEUED).")
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
		backlog, oldestInvocation, err := w.store.InvocationBacklog(ctx, w.hostID)
		if err != nil {
			return err
		}
		waiting.Set(float64(backlog))
		waited.Set(oldestInvocation.Seconds())
		if n, err = w.store.FailedAgents(ctx, w.hostID); err != nil {
			return err
		}
		failedAgents.Set(float64(n))
		waiting, longest, err := w.store.CapacityQueue(ctx, w.hostID)
		if err != nil {
			return err
		}
		queued.Set(float64(waiting))
		queuedOldest.Set(longest.Seconds())
		if waiting, err = w.store.QuotaWaits(ctx, w.hostID); err != nil {
			return err
		}
		quotaWaits.Set(float64(waiting))
		var fs syscall.Statfs_t
		if err = syscall.Statfs(root, &fs); err != nil {
			return err
		}
		if fs.Blocks > 0 {
			disk.Set(1 - float64(fs.Bavail)/float64(fs.Blocks))
		}
		return nil
	})
	// The authorities' replication metrics are the authority service's
	// (ADR 006): it owns the link to the standby.
	w.enableArchivingTelemetry(registry)
	if !w.metrics.CompareAndSwap(nil, m) {
		return controlplane.ErrConflict
	}
	return nil
}

// enableArchivingTelemetry exposes PostgreSQL's WAL archiving, read at each
// scrape (REC-03, ADR 004): whether it is on, archive_timeout, the age of the
// last archive, whether a completed segment waits, and whether the latest
// attempt failed. Its own collection, so that a failure to read it does not
// stop the queue's metrics.
func (w *Placements) enableArchivingTelemetry(registry *telemetry.Registry) {
	enabled := registry.Gauge("agentcapsule_postgres_wal_archiving_enabled", "1 when PostgreSQL archives its WAL: archive_mode on, and an archive command or library set.")
	timeout := registry.Gauge("agentcapsule_postgres_wal_archive_timeout_seconds", "PostgreSQL's archive_timeout; 0 when off.")
	age := registry.Gauge("agentcapsule_postgres_wal_archive_age_seconds", "Seconds since PostgreSQL last archived a WAL file, or since its archiver statistics began if none since.")
	pending := registry.Gauge("agentcapsule_postgres_wal_archive_pending", "1 when a completed WAL segment waits for archiving.")
	failing := registry.Gauge("agentcapsule_postgres_wal_archive_failing", "1 when PostgreSQL's latest WAL archive attempt failed.")
	flag := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	registry.Collect(func(ctx context.Context) error {
		a, err := w.store.WALArchiving(ctx)
		if err != nil {
			return err
		}
		enabled.Set(flag(a.Enabled))
		timeout.Set(a.Timeout.Seconds())
		age.Set(a.Age.Seconds())
		pending.Set(flag(a.Pending))
		failing.Set(flag(a.Failing))
		return nil
	})
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

// DeliveryDead counts and logs a delivery that died (ADR 007 §4): the
// operator learns that deliveries died, by kind and reason, not whose. The
// event delivery_dead carries the request ID of the API request that started
// the work, if any, as job_retried does.
func (w *Placements) DeliveryDead(ctx context.Context, d controlplane.DeadDelivery) {
	if m := w.metrics.Load(); m != nil {
		m.dead.Inc(d.Kind, d.Reason)
	}
	e := w.jobEvents.Load()
	if e == nil {
		return
	}
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	fields := []telemetry.Field{telemetry.Code("kind", d.Kind)}
	if origin, err := w.store.JobOrigin(lookup, controlplane.WorkerJob{Kind: "delivery", ID: d.ID}); err == nil && origin != "" {
		fields = append(fields, telemetry.RequestID(origin))
	}
	e.problems.Event("delivery_dead", append(fields, telemetry.Code("reason", d.Reason))...)
}

var _ controlplane.DeathObserver = (*Placements)(nil)

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

// countGuestFailure counts a guest's failure and, when it spent its agent's
// restart budget, the FAILED agent, with the event agent_failed. The event
// names the reason, not the agent.
func (w *Placements) countGuestFailure(kind string, failed bool) {
	if m := w.metrics.Load(); m != nil {
		m.guestFailures.Inc(kind)
		if failed {
			m.agentsFailed.Inc()
		}
	}
	if e := w.jobEvents.Load(); e != nil && failed {
		reason := "boot_failed"
		if kind == controlplane.GuestCrashed {
			reason = "crashed"
		}
		e.problems.Event("agent_failed", telemetry.Code("reason", reason))
	}
}

// JobKinds and RetryReasons are the vocabularies of the worker's job events,
// DeadDeliveryKinds and DeadDeliveryReasons those of delivery_dead,
// AgentFailureReasons that of agent_failed.
func JobKinds() []string            { return slices.Clone(jobKinds) }
func RetryReasons() []string        { return slices.Clone(retryReasons) }
func DeadDeliveryKinds() []string   { return slices.Clone(deadKinds) }
func DeadDeliveryReasons() []string { return slices.Clone(deadReasons) }
func AgentFailureReasons() []string { return slices.Clone(agentFailureReasons) }

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

// logJob writes the job's event; origin is the request ID jobOrigin read.
func (w *Placements) logJob(j controlplane.WorkerJob, origin string, err error) {
	e := w.jobEvents.Load()
	if e == nil {
		return
	}
	fields := []telemetry.Field{telemetry.Code("kind", j.Kind)}
	if origin != "" {
		fields = append(fields, telemetry.RequestID(origin))
	}
	if err == nil {
		e.progress.Event("job_done", fields...)
		return
	}
	e.problems.Event("job_retried", append(fields, telemetry.Code("reason", RetryReason(err)))...)
}
