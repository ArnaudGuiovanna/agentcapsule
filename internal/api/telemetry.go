package api

import (
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// problemCodes lists every code the API answers with (application/problem+json);
// TestEveryProblemCodeIsDeclared keeps it complete.
var problemCodes = []string{"agent_already_exists", "agent_unavailable", "attachment_quota_exceeded", "attachment_too_large",
	"attachment_unavailable", "attachments_purged", "audit_export_too_large", "authentication_required", "authority_not_reconciled", "authority_unavailable", "closure_pending", "expired", "forbidden",
	"harness_unavailable", "idempotency_key_in_progress", "idempotency_key_required", "idempotency_key_reused", "idempotency_receipt_unreadable", "incomplete_body", "input_purged", "invalid_json",
	"invalid_path", "invalid_request", "invalid_transition", "json_required", "media_type_required", "method_not_allowed", "not_found",
	"organization_name_taken", "organization_quota_exceeded", "outcome_unknown", "pool_exhausted", "provider_address_not_allowed", "queue_full", "quota_below_agent", "request_too_large", "requester_revoked", "source_credential_name_taken", "storage_capacity_unavailable",
	"storage_pressure", "temporarily_unavailable"}

var (
	httpMethods   = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	statusClasses = []string{"1xx", "2xx", "3xx", "4xx", "5xx"}
)

// invalidRoute labels a request refused before routing (an unclean path).
const invalidRoute = "invalid_path"

type apiTelemetry struct {
	requests *telemetry.Counter
	latency  *telemetry.Histogram
	log      *telemetry.Logger
}

// EnableTelemetry counts and times every request by route pattern (never the
// IDs in the path), method and status class, and writes one event per request
// to events: its X-Request-ID, route, method, status, problem code and
// duration (OPS-02). Call it once every route is registered.
func (s *Server) EnableTelemetry(registry *telemetry.Registry, events io.Writer) {
	routes := append(slices.Clone(s.routes), invalidRoute)
	route := telemetry.Label{Name: "route", Values: routes}
	s.telemetry = &apiTelemetry{
		requests: registry.Counter("agentcapsule_api_requests_total", "API requests by route pattern, method and status class.",
			route, telemetry.Label{Name: "method", Values: httpMethods}, telemetry.Label{Name: "status_class", Values: statusClasses}),
		latency: registry.Histogram("agentcapsule_api_request_duration_seconds", "API request latency by route pattern.",
			[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}, route),
		log: telemetry.NewLogger(events, map[string][]string{"event": {"http_request", "audit_refusal_unrecorded"}, "route": routes, "method": httpMethods,
			"problem": problemCodes}),
	}
	s.observeRevocations(registry)
}

func (t *apiTelemetry) record(route, method string, w *statusRecorder, requestID string, elapsed time.Duration) {
	class := strconv.Itoa(w.status/100) + "xx"
	t.requests.Inc(route, method, class)
	t.latency.Observe(elapsed.Seconds(), route)
	fields := []telemetry.Field{telemetry.RequestID(requestID), telemetry.Code("route", route), telemetry.Code("method", method),
		telemetry.Int("status", int64(w.status))}
	if w.problem != "" {
		fields = append(fields, telemetry.Code("problem", w.problem))
	}
	t.log.Event("http_request", append(fields, telemetry.Seconds("duration", elapsed))...)
}

// refusalUnrecorded reports a refused administrative attempt that its
// organization's trail could not record (TEN-009): the answer went out, the
// record did not.
func (t *apiTelemetry) refusalUnrecorded() {
	t.log.Event("audit_refusal_unrecorded")
}

// statusRecorder keeps the status and problem code a handler answered with.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	wrote   bool
	problem string
}

func (w *statusRecorder) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
