//go:build linux

package worker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The worker's spans (OPR-3, docs/observability.md#traces). Every
// identifier is a pseudonym; the codes come from these lists.
var (
	outcomeDone  = []string{"done", "retried"}
	platformCall = []string{"validate", "submit", "reply", "search", "post_owner", "read_attachment", "complete_invocation",
		"llm_complete", "llm_forward", "describe_agent", "request_status", "llm_embed", "llm_transcribe", "llm_ocr", "output_stream"}
	// platformOutcomes are "ok" and the codes platformError answers with.
	platformOutcomes = []string{"ok", "unavailable", "invalid", "unauthorized", "not_found", "mandate", "conflict", "expired", "transition",
		"commit_unknown", "quota_exceeded", "rate_limited", "rejected", "outcome_unknown", "dialect", "unsupported",
		// An output stream's closed reasons (ADR 022).
		"done", "terminal", "reset", "revoked", "truncated", "idle"}

	jobSpan = telemetry.NewSpanType("worker.job", telemetry.SpanConsumer, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.job.kind", Values: jobKinds}, {Name: "agentcapsule.outcome", Values: outcomeDone},
			{Name: "agentcapsule.retry_reason", Values: retryReasons}},
		Ints: []string{"agentcapsule.job.failures"}, IDs: []string{"agentcapsule.job", "agentcapsule.agent"}})
	deliverSpan = telemetry.NewSpanType("worker.deliver", telemetry.SpanInternal, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.delivery.kind", Values: []string{"invocation", "agent_message"}},
			{Name: "agentcapsule.delivery.transport", Values: []string{"vsock", "slim"}}, {Name: "agentcapsule.outcome", Values: []string{"delivered", "failed"}},
			{Name: "agentcapsule.retry_reason", Values: retryReasons}},
		IDs: []string{"agentcapsule.agent"}})
	wakeSpan = telemetry.NewSpanType("worker.wake", telemetry.SpanInternal, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.outcome", Values: []string{"running", "booted", "capacity", "organization_quota", "failed"}},
			{Name: "agentcapsule.wake.evicted", Values: []string{"yes", "no"}}},
		IDs: []string{"agentcapsule.agent"}})
	bootSpan = telemetry.NewSpanType("worker.boot", telemetry.SpanInternal, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.boot.purpose", Values: []string{"work", "fence"}},
			{Name: "agentcapsule.outcome", Values: []string{"started", "failed", "guest_failed", "capacity", "organization_quota"}}},
		IDs: []string{"agentcapsule.agent"}})
	platformSpan = telemetry.NewSpanType("platform.call", telemetry.SpanServer, telemetry.SpanAttributes{
		Codes: []telemetry.Label{{Name: "agentcapsule.platform.call", Values: platformCall}, {Name: "agentcapsule.outcome", Values: platformOutcomes},
			{Name: "agentcapsule.trace.origin", Values: []string{"delivery", "work", "none"}}},
		IDs: []string{"agentcapsule.agent"}})
)

// workerTracing is the worker's tracer and the deliveries in progress: a
// guest's platform calls during a delivery to it are children of that
// delivery's span.
type workerTracing struct {
	tracer *telemetry.Tracer
	mu     sync.Mutex
	turns  map[string]*telemetry.Span
}

// EnableTracing records the worker's spans with tracer (OPR-3): each job,
// joining the trace of the API request that started its work; each
// delivery, wake and boot; each platform call of a guest; and, through the
// context, the calls to the authority service and to model providers.
func (w *Placements) EnableTracing(tracer *telemetry.Tracer) error {
	if tracer == nil || !w.tracing.CompareAndSwap(nil, &workerTracing{tracer: tracer, turns: map[string]*telemetry.Span{}}) {
		return controlplane.ErrConflict
	}
	return nil
}

// jobOrigin is the X-Request-ID of the API request that started a job's
// work, or "", when events or traces need it.
func (w *Placements) jobOrigin(ctx context.Context, j controlplane.WorkerJob) string {
	if w.jobEvents.Load() == nil && w.tracing.Load() == nil {
		return ""
	}
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	origin, err := w.store.JobOrigin(lookup, j)
	if err != nil {
		return ""
	}
	return origin
}

// startJob begins a job's span in the trace of origin.
func (w *Placements) startJob(ctx context.Context, j controlplane.WorkerJob, origin string) (context.Context, *telemetry.Span) {
	t := w.tracing.Load()
	if t == nil {
		return ctx, nil
	}
	ctx, span := jobSpan.Start(telemetry.ContinueTrace(ctx, t.tracer, origin))
	span.Code("agentcapsule.job.kind", j.Kind)
	span.ID("agentcapsule.job", j.ID)
	span.ID("agentcapsule.agent", j.AgentID)
	span.Int("agentcapsule.job.failures", int64(j.Failures))
	return ctx, span
}

func endJob(span *telemetry.Span, err error) {
	if err == nil {
		span.Code("agentcapsule.outcome", "done")
	} else {
		span.Code("agentcapsule.outcome", "retried")
		span.Code("agentcapsule.retry_reason", RetryReason(err))
		span.Fail()
	}
	span.End()
}

// turn records that a delivery to agent is in progress, until the returned
// function runs.
func (w *Placements) turn(agent string, span *telemetry.Span) func() {
	t := w.tracing.Load()
	if t == nil || span == nil {
		return func() {}
	}
	t.mu.Lock()
	t.turns[agent] = span
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		if t.turns[agent] == span {
			delete(t.turns, agent)
		}
		t.mu.Unlock()
	}
}

func endDelivery(span *telemetry.Span, slim bool, err error) {
	transport := "vsock"
	if slim {
		transport = "slim"
	}
	span.Code("agentcapsule.delivery.transport", transport)
	if err != nil {
		span.Code("agentcapsule.outcome", "failed")
		span.Code("agentcapsule.retry_reason", RetryReason(err))
		span.Fail()
	} else {
		span.Code("agentcapsule.outcome", "delivered")
	}
	span.End()
}

func endWake(span *telemetry.Span, outcome string, evicted bool, err error) {
	switch {
	case errors.Is(err, runtime.ErrCapacity):
		outcome = "capacity"
	case errors.Is(err, controlplane.ErrOrganizationQuota):
		outcome = "organization_quota"
	case err != nil:
		outcome = "failed"
		span.Fail()
	}
	span.Code("agentcapsule.outcome", outcome)
	if evicted {
		span.Code("agentcapsule.wake.evicted", "yes")
	} else {
		span.Code("agentcapsule.wake.evicted", "no")
	}
	span.End()
}

func endBoot(span *telemetry.Span, fence bool, err error) {
	purpose := "work"
	if fence {
		purpose = "fence"
	}
	span.Code("agentcapsule.boot.purpose", purpose)
	switch {
	case err == nil:
		span.Code("agentcapsule.outcome", "started")
	case errors.Is(err, runtime.ErrBootFailed):
		span.Code("agentcapsule.outcome", "guest_failed")
		span.Fail()
	case errors.Is(err, runtime.ErrCapacity):
		span.Code("agentcapsule.outcome", "capacity")
	case errors.Is(err, controlplane.ErrOrganizationQuota):
		span.Code("agentcapsule.outcome", "organization_quota")
	default:
		span.Code("agentcapsule.outcome", "failed")
		span.Fail()
	}
	span.End()
}

// trace begins the span of a guest's platform call. It is a child of the
// delivery to the agent in progress, if any; otherwise, when the call names
// its work (an invocation, a request between agents, a mandate), it joins
// the trace of the API request that started that work, read from
// PostgreSQL; otherwise it begins its own trace. The returned function ends
// it with the call's outcome.
func (a platformAPI) trace(ctx context.Context, call, kind, id string) (context.Context, func(error)) {
	var t *workerTracing
	if a.traces != nil {
		t = a.traces()
	}
	if t == nil {
		return ctx, func(error) {}
	}
	t.mu.Lock()
	delivery := t.turns[a.caller.AgentID]
	t.mu.Unlock()
	origin := "none"
	switch {
	case delivery != nil:
		ctx, origin = telemetry.WithParent(ctx, delivery), "delivery"
	case kind != "" && id != "" && a.store != nil:
		lookup, cancel := context.WithTimeout(ctx, time.Second)
		request, err := a.store.TraceOrigin(lookup, kind, id)
		cancel()
		ctx = telemetry.ContinueTrace(ctx, t.tracer, request)
		if err == nil && request != "" {
			origin = "work"
		}
	default:
		ctx = telemetry.WithTracer(ctx, t.tracer)
	}
	ctx, span := platformSpan.Start(ctx)
	span.Code("agentcapsule.platform.call", call)
	span.Code("agentcapsule.trace.origin", origin)
	span.ID("agentcapsule.agent", a.caller.AgentID)
	return ctx, func(err error) {
		outcome := "ok"
		if err != nil {
			// The code the guest receives; some calls hand it already mapped.
			var e *capsuleprotocol.PlatformError
			if errors.As(err, &e) || errors.As(platformError(err), &e) {
				outcome = e.Code
			}
			span.Fail()
		}
		span.Code("agentcapsule.outcome", outcome)
		span.End()
	}
}
