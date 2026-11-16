//go:build linux && cgo

package authorityservice

import (
	"sync"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Metrics is the service's own view, beside the replication metrics of
// authoritylog.Metrics. A nil *Metrics records nothing.
type Metrics struct {
	holds   *telemetry.Gauge
	expired *telemetry.Counter
	refused *telemetry.Counter
	// receipt are the daily receipt keys' (receipt_keys_linux.go).
	receipt receiptMetrics

	mu     sync.Mutex
	active map[string]int
}

// NewMetrics registers the service's metrics.
func NewMetrics(r *telemetry.Registry) *Metrics {
	kind := telemetry.Label{Name: "kind", Values: HoldKinds()}
	m := &Metrics{
		holds: r.Gauge("agentcapsule_authority_service_holds", "Holds the authority service grants now, by kind.", kind),
		expired: r.Counter("agentcapsule_authority_service_hold_expired_total",
			"Holds the authority service ended at their cap, closing their connection, by kind.", kind),
		refused: r.Counter("agentcapsule_authority_service_refused_peers_total",
			"Connections the authority service closed at accept because of their peer's account, by socket.",
			telemetry.Label{Name: "socket", Values: []string{RoleWorker, RoleAPI}}),
		active:  map[string]int{},
		receipt: newReceiptMetrics(r),
	}
	for _, k := range HoldKinds() {
		m.holds.Set(0, k)
	}
	return m
}

// Holding counts a hold of this kind that starts (delta 1) or ends (-1).
func (m *Metrics) Holding(kind string, delta int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[kind] = max(m.active[kind]+delta, 0)
	m.holds.Set(float64(m.active[kind]), kind)
}

// Expired counts a hold ended at its cap.
func (m *Metrics) Expired(kind string) {
	if m != nil {
		m.expired.Inc(kind)
	}
}

// Refused counts a peer refused at accept on a socket.
func (m *Metrics) Refused(socket string) {
	if m != nil {
		m.refused.Inc(socket)
	}
}
