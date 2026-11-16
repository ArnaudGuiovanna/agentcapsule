package api

import (
	"context"
	"net/http"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// accessRevocation reads one access revocation (ADR 006 wave 5): its kind
// and its state, pending until the standby holds its record, then
// confirmed. An organization's administrators and auditors read the
// organization's; the platform operator reads the platform's own.
func (s *Server) accessRevocation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.AccessRevocation(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

// confirmBatch bounds the pending revocations one pass asks about.
const confirmBatch = 100

// ConfirmRevocations asks the authority service about the pending access
// revocations every interval, until ctx ends, and confirms those the
// standby now holds (ADR 006 §7). The API runs it while it reaches the
// authority service.
func (s *Server) ConfirmRevocations(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		_, _ = s.store.ConfirmAccessRevocations(ctx, confirmBatch)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// observeRevocations exposes the pending access revocations: how many, and
// for how long the oldest has waited.
func (s *Server) observeRevocations(registry *telemetry.Registry) {
	pending := registry.Gauge("agentcapsule_api_access_revocations_pending",
		"Access revocations recorded but not confirmed: the standby does not hold their record yet (ADR 006 wave 5).")
	oldest := registry.Gauge("agentcapsule_api_access_revocation_oldest_pending_seconds",
		"Seconds since the oldest pending access revocation was recorded; 0 when none is pending.")
	registry.Collect(func(ctx context.Context) error {
		count, since, err := s.store.PendingAccessRevocations(ctx)
		if err != nil {
			return err
		}
		pending.Set(float64(count))
		age := 0.0
		if !since.IsZero() {
			age = max(time.Since(since).Seconds(), 0)
		}
		oldest.Set(age)
		return nil
	})
}
