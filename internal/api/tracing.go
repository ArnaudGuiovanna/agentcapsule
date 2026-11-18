package api

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// apiTracing records the API's spans (OPR-3): one per request, the root of
// the trace whose ID is the request's X-Request-ID, and one per invocation's
// admission.
type apiTracing struct {
	tracer  *telemetry.Tracer
	request *telemetry.SpanType
	admit   *telemetry.SpanType
	// wildcards are each route's path wildcards whose values the request's
	// span carries as pseudonyms.
	wildcards map[string][]string
}

var wildcard = regexp.MustCompile(`\{([a-z_]+)\}`)

// secretWildcards name path values that are bearer secrets: never in a span,
// not even as a pseudonym.
var secretWildcards = []string{"token"}

// EnableTracing records a span per request and per admission of an
// invocation, written by tracer. A request's span carries its route pattern,
// method, status and problem code, and the pseudonyms of its organization,
// its principal and the identifiers in its path; never a path, a header or a
// body. Call it once every route is registered.
func (s *Server) EnableTracing(tracer *telemetry.Tracer) {
	routes := append(slices.Clone(s.routes), invalidRoute)
	t := &apiTracing{tracer: tracer, wildcards: map[string][]string{}}
	ids := []string{"agentcapsule.organization", "agentcapsule.principal"}
	for _, route := range routes {
		for _, m := range wildcard.FindAllStringSubmatch(route, -1) {
			if slices.Contains(secretWildcards, m[1]) {
				continue
			}
			t.wildcards[route] = append(t.wildcards[route], m[1])
			if key := "agentcapsule.path." + m[1]; !slices.Contains(ids, key) {
				ids = append(ids, key)
			}
		}
	}
	t.request = telemetry.NewSpanType("api.request", telemetry.SpanServer, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "http.route", Values: routes}, {Name: "http.request.method", Values: httpMethods},
			{Name: "agentcapsule.problem", Values: problemCodes}},
		Ints: []string{"http.response.status_code"}, IDs: ids})
	t.admit = telemetry.NewSpanType("invocation.admit", telemetry.SpanInternal, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.outcome", Values: []string{"accepted", "replayed", "refused"}},
			{Name: "agentcapsule.problem", Values: problemCodes}},
		IDs: []string{"agentcapsule.agent", "agentcapsule.invocation"}})
	s.tracing = t
}

// start begins the request's span; nil without tracing.
func (t *apiTracing) start(ctx context.Context, requestID string) (context.Context, *telemetry.Span) {
	if t == nil {
		return ctx, nil
	}
	return t.request.StartRequest(ctx, t.tracer, requestID)
}

// finish ends the request's span. served is the request the mux routed, with
// its path values, or nil when it was refused before routing.
func (t *apiTracing) finish(span *telemetry.Span, route, method string, served *http.Request, w *statusRecorder) {
	if span == nil {
		return
	}
	span.Code("http.route", route)
	span.Code("http.request.method", method)
	span.Int("http.response.status_code", int64(w.status))
	if w.problem != "" {
		span.Code("agentcapsule.problem", w.problem)
	}
	if served != nil {
		for _, name := range t.wildcards[route] {
			span.ID("agentcapsule.path."+name, served.PathValue(name))
		}
	}
	if w.status >= 500 {
		span.Fail()
	}
	span.End()
}

// identify adds the authenticated principal and its organization to the
// request's span, as pseudonyms.
func identify(ctx context.Context, p controlplane.Principal) {
	span := telemetry.SpanFrom(ctx)
	span.ID("agentcapsule.organization", p.TenantID)
	span.ID("agentcapsule.principal", p.ID)
}

// admission begins the span of an invocation's admission to agent.
func (t *apiTracing) admission(ctx context.Context, agent string) (context.Context, *telemetry.Span) {
	if t == nil {
		return ctx, nil
	}
	ctx, span := t.admit.Start(ctx)
	span.ID("agentcapsule.agent", agent)
	return ctx, span
}

// admitted ends an admission's span once its answer is written.
func admitted(span *telemetry.Span, w http.ResponseWriter, out controlplane.APIReceipt, err error) {
	if span == nil {
		return
	}
	recorder, _ := w.(*statusRecorder)
	switch {
	case err != nil:
		span.Code("agentcapsule.outcome", "refused")
		if recorder != nil && recorder.problem != "" {
			span.Code("agentcapsule.problem", recorder.problem)
		}
		if recorder != nil && recorder.status >= 500 {
			span.Fail()
		}
	case out.Replayed:
		span.Code("agentcapsule.outcome", "replayed")
	default:
		span.Code("agentcapsule.outcome", "accepted")
	}
	if err == nil {
		var created struct {
			ID          string `json:"id"`
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(out.Body, &created) == nil {
			span.ID("agentcapsule.invocation", cmp.Or(created.ID, created.OperationID))
		}
	}
	span.End()
}
