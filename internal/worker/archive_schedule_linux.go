//go:build linux

package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// Archives makes the maintenance loop archive the encrypted volume of each
// agent of its host, about once a day (REC-02, ADR 004). See ArchivePass.
type Archives struct {
	// Store is the host's private archive root, outside the runtime and both
	// authorities.
	Store *volumearchive.Store
	// Every bounds the age of each agent's newest archive. From Every minus
	// SleepWindow on, a sleeping agent is captured; at Every, a running agent
	// is stopped for its capture (controlplane.ArchivePolicy).
	Every, SleepWindow time.Duration
	// Keep is the number of archives kept per agent, at least one.
	Keep int
	// PerPass bounds the captures of one maintenance pass.
	PerPass int
	// Timeout bounds one capture, the copy of the volume included.
	Timeout time.Duration
	// Report receives the outcome of each capture and must return promptly.
	// The service command turns it into fixed events.
	Report func(ArchiveReport)

	// retries holds the agents whose last capture failed, until they may be
	// tried again. Only the maintenance loop uses it.
	retries map[string]archiveRetry
	metrics atomic.Pointer[archiveMetrics]
	// now replaces the database clock in tests; nil in service.
	now func() time.Time
}

// ArchiveReport is the outcome of one capture.
type ArchiveReport struct {
	// Running is true when the agent's VM ran: the capture stopped it, and
	// it wakes again on its next delivery.
	Running bool
	// Err is nil once the archive is published and recorded. Otherwise the
	// agent is tried again at a later pass, after a delay.
	Err      error
	Size     int64
	Duration time.Duration
	// Removed counts the older archives deleted by retention after the
	// capture; RetentionErr stops that deletion until the next capture.
	Removed      int
	RetentionErr error
}

// VM is the state of the agent's VM before the capture: asleep or running.
func (r ArchiveReport) VM() string {
	if r.Running {
		return "running"
	}
	return "asleep"
}

type archiveRetry struct {
	until    time.Time
	failures int
}

type archiveMetrics struct{ captures *telemetry.Counter }

var (
	archiveVMs          = []string{"asleep", "running"}
	archiveRetryReasons = []string{"placement", "busy", "disk_full", "authority", "timeout", "retention", "error"}
)

// ArchiveVMs and ArchiveRetryReasons are the vocabularies of the archive events.
func ArchiveVMs() []string          { return slices.Clone(archiveVMs) }
func ArchiveRetryReasons() []string { return slices.Clone(archiveRetryReasons) }

// ArchiveRetryReason classifies why a capture failed: the agent was not
// cleanly stopped or changed state (placement), its volume or the host was
// busy, the archive disk is full, an authority refused, the capture took too
// long, or any other error.
func ArchiveRetryReason(err error) string {
	switch {
	case errors.Is(err, controlplane.ErrPlacement), errors.Is(err, controlplane.ErrStoreEnrollment),
		errors.Is(err, runtime.ErrGeneration), errors.Is(err, runtime.ErrHostFenced):
		return "placement"
	case errors.Is(err, runtime.ErrVolumeBusy), errors.Is(err, runtime.ErrAdmissionBusy), errors.Is(err, controlplane.ErrPlacementBusy):
		return "busy"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "disk_full"
	case errors.Is(err, restoreauthority.ErrStale), errors.Is(err, restoreauthority.ErrSealed), errors.Is(err, restoreauthority.ErrRevoked),
		errors.Is(err, restoreauthority.ErrConflict), errors.Is(err, restoreauthority.ErrUnavailable),
		errors.Is(err, keyauthority.ErrUnavailable), errors.Is(err, keyauthority.ErrRevoked):
		return "authority"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "error"
}

func (a *Archives) valid() bool {
	return a != nil && a.Store != nil && a.Every >= time.Second && a.SleepWindow >= 0 && a.SleepWindow < a.Every &&
		a.Keep >= 1 && a.Keep <= 365 && a.PerPass >= 1 && a.PerPass <= 16 && a.Timeout > 0
}

func (a *Archives) policy() controlplane.ArchivePolicy {
	return controlplane.ArchivePolicy{Every: a.Every, SleepWindow: a.SleepWindow}
}

// retryDelay is Every/48 after a first failure (30 minutes for a day), then
// doubles, up to Every/4: a failing agent neither holds up the others nor,
// when it runs, is stopped at every pass.
func (a *Archives) retryDelay(failures int) time.Duration {
	d, limit := a.Every/48, a.Every/4
	for i := 1; i < failures && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// waiting drops expired retry entries and returns the agents still waiting.
func (a *Archives) waiting(now time.Time) map[string]bool {
	held := map[string]bool{}
	for id, r := range a.retries {
		switch {
		case now.Before(r.until):
			held[id] = true
		case now.Sub(r.until) > a.Every:
			delete(a.retries, id) // long gone: deleted, or no longer failing
		}
	}
	return held
}

// pick returns up to PerPass candidates, in order, that are not waiting.
func (a *Archives) pick(candidates []controlplane.VolumeArchiveCandidate, held map[string]bool) []controlplane.VolumeArchiveCandidate {
	picked := make([]controlplane.VolumeArchiveCandidate, 0, a.PerPass)
	for _, c := range candidates {
		if len(picked) == a.PerPass {
			break
		}
		if !held[c.AgentID] {
			picked = append(picked, c)
		}
	}
	return picked
}

// hold puts aside, without counting a failure, an agent found not due under
// its barrier: a wake or another capture came first. A VM whose state
// disagrees with the database then costs no barrier at every pass.
func (a *Archives) hold(agentID string, now time.Time) {
	if a.retries == nil {
		a.retries = map[string]archiveRetry{}
	}
	r := a.retries[agentID]
	r.until = now.Add(a.retryDelay(1))
	a.retries[agentID] = r
}

func (a *Archives) record(agentID string, err error, now time.Time) {
	if err == nil {
		delete(a.retries, agentID)
		return
	}
	if a.retries == nil {
		a.retries = map[string]archiveRetry{}
	}
	r := a.retries[agentID]
	r.failures++
	r.until = now.Add(a.retryDelay(r.failures))
	a.retries[agentID] = r
}

// EnableArchiveTelemetry registers the archive metrics (OPS-02): captures by
// the state of the VM and outcome, and, read at each scrape from PostgreSQL,
// the number of agents archived and the age of the oldest among their newest
// archives. No agent identifier is a label.
func (w *Placements) EnableArchiveTelemetry(registry *telemetry.Registry, a *Archives) error {
	if registry == nil || a == nil {
		return controlplane.ErrInput
	}
	m := &archiveMetrics{captures: registry.Counter("agentcapsule_worker_volume_archives_total",
		"Volume archive captures, by the state of the VM before the capture (asleep, running) and outcome (captured, retried).",
		telemetry.Label{Name: "vm", Values: archiveVMs}, telemetry.Label{Name: "outcome", Values: []string{"captured", "retried"}})}
	agents := registry.Gauge("agentcapsule_worker_volume_archive_agents", "Live agents of this host whose volume the worker archives.")
	oldest := registry.Gauge("agentcapsule_worker_volume_archive_oldest_seconds",
		"Age of the oldest among the newest volume archives of this host's agents; an agent never archived counts from its initialization.")
	registry.Collect(func(ctx context.Context) error {
		n, age, err := w.store.VolumeArchiveFreshness(ctx, w.hostID)
		if err != nil {
			return err
		}
		agents.Set(float64(n))
		oldest.Set(age.Seconds())
		return nil
	})
	if !a.metrics.CompareAndSwap(nil, m) {
		return controlplane.ErrConflict
	}
	return nil
}

// ArchivePass captures at most PerPass agents of this host that are due:
// sleeping agents first, then running agents whose newest archive reached
// Every, which it stops. A capture holds the agent's barrier, which is the
// host's exclusive admission: deliveries on the host wait for it, so a pass
// does little. A failed capture leaves no archive and is tried again after a
// delay. Only an error of the selection itself is returned; each capture is
// reported through Report and the metrics.
func (w *Placements) ArchivePass(ctx context.Context, a *Archives) error {
	if !a.valid() {
		return errors.New("invalid archive options")
	}
	var now *time.Time
	if a.now != nil {
		t := a.now()
		now = &t
	}
	held := a.waiting(time.Now())
	candidates, err := w.store.DueVolumeArchives(ctx, w.hostID, now, a.policy(), min(a.PerPass+len(held), 1024))
	if err != nil {
		return err
	}
	for _, c := range a.pick(candidates, held) {
		if ctx.Err() != nil {
			return nil
		}
		r, attempted := w.archiveAgent(ctx, a, c, now)
		if !attempted {
			a.hold(c.AgentID, time.Now())
			continue
		}
		if ctx.Err() != nil && r.Err != nil {
			return nil // stopping: neither a failure nor a reason to wait
		}
		a.record(c.AgentID, r.Err, time.Now())
		if m := a.metrics.Load(); m != nil {
			outcome := "captured"
			if r.Err != nil {
				outcome = "retried"
			}
			m.captures.Inc(r.VM(), outcome)
		}
		if a.Report != nil {
			a.Report(r)
		}
	}
	return nil
}

func newArchiveID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "arc_" + hex.EncodeToString(b), nil
}

// archiveAgent captures one agent. It returns false when nothing was
// attempted: the agent was no longer due once under its barrier.
func (w *Placements) archiveAgent(ctx context.Context, a *Archives, c controlplane.VolumeArchiveCandidate, now *time.Time) (ArchiveReport, bool) {
	started := time.Now()
	r := ArchiveReport{Running: c.Running}
	id, err := newArchiveID()
	if err != nil {
		r.Err = err
		return r, true
	}
	began := false
	step, cancel := context.WithTimeout(ctx, a.Timeout)
	manifest, err := w.captureArchive(step, c.AgentID, id, a.Store, archiveHooks{
		begin: func(ctx context.Context, running bool) error {
			if err := w.settleArchives(ctx, c.AgentID, a.Store); err != nil {
				return err
			}
			r.Running = running
			if err := w.store.BeginVolumeArchive(ctx, w.hostID, c.AgentID, id, running, now, a.policy()); err != nil {
				return err
			}
			began = true
			return nil
		},
		published: func(ctx context.Context, m restoreauthority.Archive) error {
			return w.store.CompleteVolumeArchive(ctx, id, m.Size, false)
		},
	})
	cancel()
	if !began && errors.Is(err, controlplane.ErrArchiveNotDue) {
		return r, false // another capture, a wake or a deletion came first
	}
	cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelCleanup()
	if err != nil && began {
		// A capture that published nothing is forgotten. A published one
		// stays pending, and the agent's next capture records it.
		if _, missing := a.Store.Manifest(id); errors.Is(missing, fs.ErrNotExist) {
			_ = w.store.AbandonVolumeArchive(cleanup, id)
		}
	}
	if err == nil {
		r.Size = manifest.Size
		// The archive just published is the agent's newest: retention keeps
		// at least it, so it never deletes an agent's only archive.
		r.Removed, r.RetentionErr = w.pruneArchives(cleanup, a, c.AgentID)
	}
	// What a crash or an interrupted removal left behind; a capture still
	// writing touches its file, and none of this host's runs an hour idle.
	_ = a.Store.Sweep(time.Hour)
	r.Err, r.Duration = err, time.Since(started)
	return r, true
}

// settleArchives runs under the agent's barrier, before a new capture. It
// settles the captures that a crash interrupted: a published archive is
// recorded, as of the start of its capture; a capture that published nothing
// is forgotten. An unreadable archive stays pending and is not counted.
func (w *Placements) settleArchives(ctx context.Context, agentID string, archives *volumearchive.Store) error {
	pending, err := w.store.PendingVolumeArchives(ctx, agentID, w.hostID)
	if err != nil {
		return err
	}
	for _, id := range pending {
		m, err := archives.Manifest(id)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			err = w.store.AbandonVolumeArchive(ctx, id)
		case errors.Is(err, volumearchive.ErrArchive), err == nil && m.Binding.Store != agentID:
			continue
		case err == nil:
			err = w.store.CompleteVolumeArchive(ctx, id, m.Size, true)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// pruneArchives deletes the agent's archives beyond the Keep newest, then
// records each removal. An interrupted removal is finished at the next
// capture: removing a missing archive succeeds.
func (w *Placements) pruneArchives(ctx context.Context, a *Archives, agentID string) (int, error) {
	expired, err := w.store.ExpiredVolumeArchives(ctx, agentID, w.hostID, a.Keep)
	if err != nil {
		return 0, err
	}
	for i, id := range expired {
		if err = a.Store.Remove(id); err == nil {
			err = w.store.RemovedVolumeArchive(ctx, id)
		}
		if err != nil {
			return i, err
		}
	}
	return len(expired), nil
}
