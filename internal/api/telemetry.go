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
	"attachment_unavailable", "authentication_required", "closure_pending", "expired", "forbidden", "harness_unavailable",
	"idempotency_key_in_progress", "idempotency_key_required", "idempotency_key_reused", "incomplete_body", "invalid_json",
	"invalid_path", "invalid_request", "invalid_transition", "json_required", "media_type_required", "method_not_allowed",
	"not_found", "queue_full", "request_too_large", "storage_capacity_unavailable", "temporarily_unavailable"}

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
		log: telemetry.NewLogger(events, map[string][]string{"event": {"http_request"}, "route": routes, "method": httpMethods,
			"problem": problemCodes}),
	}
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
