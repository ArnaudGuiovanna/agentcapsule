package authoritylog

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// ErrBehind means that the replica lacks records that the primary's log no
// longer holds: the replica was set back or replaced. It needs a new snapshot.
var ErrBehind = errors.New("replica is behind the primary's log")

// ErrDiverged means that the primary's log and the replica disagree: one of
// them was set back, or replaced.
var ErrDiverged = errors.New("primary and replica histories differ")

// The kinds of a replication error, a closed vocabulary for metrics.
const (
	ErrorNone        = "none"
	ErrorUnreachable = "unreachable"
	ErrorTimeout     = "timeout"
	ErrorProtocol    = "protocol"
	ErrorBehind      = "replica_behind"
	ErrorDiverged    = "diverged"
	ErrorLocal       = "local"
)

// ErrorKinds lists every error kind.
func ErrorKinds() []string {
	kinds := []string{ErrorNone, ErrorUnreachable, ErrorTimeout, ErrorProtocol, ErrorBehind, ErrorDiverged, ErrorLocal}
	for _, k := range RefusalKinds() {
		kinds = append(kinds, "refused_"+k)
	}
	return kinds
}

// ErrorKind classifies a replication error.
func ErrorKind(err error) string {
	var refusal *Refusal
	var netErr net.Error
	switch {
	case err == nil:
		return ErrorNone
	case errors.As(err, &refusal):
		return "refused_" + refusal.Kind
	case errors.Is(err, ErrBehind):
		return ErrorBehind
	case errors.Is(err, ErrDiverged):
		return ErrorDiverged
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return ErrorTimeout
	case errors.Is(err, ErrProtocol), errors.Is(err, ErrRecord):
		return ErrorProtocol
	case errors.As(err, &netErr):
		if netErr.Timeout() {
			return ErrorTimeout
		}
		return ErrorUnreachable
	}
	return ErrorLocal
}

// Metrics is the primary's view of the stream. A nil *Metrics records nothing.
type Metrics struct {
	enabled, committed, acknowledged, lag, lagSeconds, lastError *telemetry.Gauge
	errors                                                       *telemetry.Counter
	writes                                                       *telemetry.Histogram

	mu                   sync.Mutex
	committedSeq, ackSeq uint64
	pending              map[uint64]time.Time
}

// NewMetrics registers the primary's replication metrics.
func NewMetrics(r *telemetry.Registry) *Metrics {
	kind := telemetry.Label{Name: "kind", Values: ErrorKinds()}
	m := &Metrics{
		enabled: r.Gauge("agentcapsule_authority_replication_enabled", "1 when the authorities replicate synchronously to a standby; 0 in standalone mode, without disaster protection."),
		committed: r.Gauge("agentcapsule_authority_replication_committed_sequence",
			"Sequence number of the last authority record this process committed locally."),
		acknowledged: r.Gauge("agentcapsule_authority_replication_acknowledged_sequence",
			"Sequence number of the last authority record the replica acknowledged to this process."),
		lag: r.Gauge("agentcapsule_authority_replication_lag_records",
			"Authority records committed locally and not yet acknowledged by the replica."),
		lagSeconds: r.Gauge("agentcapsule_authority_replication_lag_seconds",
			"Age of the oldest authority record committed locally and not yet acknowledged; 0 when none."),
		lastError: r.Gauge("agentcapsule_authority_replication_last_error",
			"1 for the kind of the last replication attempt's error; kind none when it succeeded.", kind),
		errors: r.Counter("agentcapsule_authority_replication_errors_total", "Failed replication attempts, by kind.", kind),
		writes: r.Histogram("agentcapsule_authority_replication_write_seconds",
			"Time from an authority record's local commit to the replica's acknowledgment.",
			[]float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 5, 30}),
		pending: map[uint64]time.Time{},
	}
	m.setError(ErrorNone)
	r.Collect(func(context.Context) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		oldest := time.Time{}
		for _, t := range m.pending {
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
		age := 0.0
		if !oldest.IsZero() {
			age = time.Since(oldest).Seconds()
		}
		m.lagSeconds.Set(age)
		return nil
	})
	return m
}

func (m *Metrics) setError(kind string) {
	m.lastError.Reset()
	for _, k := range ErrorKinds() {
		v := 0.0
		if k == kind {
			v = 1
		}
		m.lastError.Set(v, k)
	}
}

// Enabled records the mode: synchronous replication, or standalone.
func (m *Metrics) Enabled(on bool) {
	if m == nil {
		return
	}
	v := 0.0
	if on {
		v = 1
	}
	m.enabled.Set(v)
}

// Committed records a local commit of record seq, not yet acknowledged.
func (m *Metrics) Committed(seq uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq > m.committedSeq {
		m.committedSeq = seq
	}
	if seq > m.ackSeq {
		m.pending[seq] = time.Now()
	}
	m.update()
}

// Acknowledged records the replica's position.
func (m *Metrics) Acknowledged(seq uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq > m.ackSeq {
		m.ackSeq = seq
	}
	if seq > m.committedSeq {
		m.committedSeq = seq
	}
	for s, t := range m.pending {
		if s <= seq {
			m.writes.Since(t)
			delete(m.pending, s)
		}
	}
	m.setError(ErrorNone)
	m.update()
}

func (m *Metrics) update() {
	m.committed.Set(float64(m.committedSeq))
	m.acknowledged.Set(float64(m.ackSeq))
	m.lag.Set(float64(m.committedSeq - m.ackSeq))
}

// Failed records a failed replication attempt.
func (m *Metrics) Failed(err error) {
	if m == nil || err == nil {
		return
	}
	kind := ErrorKind(err)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors.Inc(kind)
	m.setError(kind)
}

// ReplicaMetrics is the replica's view of the stream. A nil value records
// nothing.
type ReplicaMetrics struct {
	applied, epoch, lastApply *telemetry.Gauge
	refusals                  *telemetry.Counter
}

// NewReplicaMetrics registers the replica's metrics.
func NewReplicaMetrics(r *telemetry.Registry) *ReplicaMetrics {
	return &ReplicaMetrics{
		applied:   r.Gauge("agentcapsule_authority_replica_applied_sequence", "Sequence number of the last authority record the replica applied durably."),
		epoch:     r.Gauge("agentcapsule_authority_replica_epoch", "Epoch of the stream the replica accepts."),
		lastApply: r.Gauge("agentcapsule_authority_replica_last_apply_timestamp_seconds", "When the replica last applied a record; its start time before."),
		refusals: r.Counter("agentcapsule_authority_replica_refusals_total", "Requests the replica refused, by kind.",
			telemetry.Label{Name: "kind", Values: RefusalKinds()}),
	}
}

// Position records the replica's position; applied tells whether it moved.
func (m *ReplicaMetrics) Position(p Position, applied bool) {
	if m == nil {
		return
	}
	m.applied.Set(float64(p.Seq))
	m.epoch.Set(float64(p.Epoch))
	if applied {
		m.lastApply.Set(float64(time.Now().UnixNano()) / 1e9)
	}
}

// Started records the replica's start.
func (m *ReplicaMetrics) Started(p Position) {
	if m == nil {
		return
	}
	m.Position(p, false)
	m.lastApply.Set(float64(time.Now().UnixNano()) / 1e9)
}

// Refused records a refusal.
func (m *ReplicaMetrics) Refused(kind string) {
	if m == nil {
		return
	}
	m.refusals.Inc(kind)
}
