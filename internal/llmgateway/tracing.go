package llmgateway

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// callSpan is one logical model call (OPR-3): the provider's kind, the
// gateway's entry (complete, forward), its mode (unary, stream), the outcome,
// the upstream attempts and the tokens the provider reported. Never a prompt,
// an event, a model name, an address or a credential.
var callSpan = telemetry.NewSpanType("llm.call", telemetry.SpanClient, telemetry.SpanAttributes{
	Codes: []telemetry.Label{{Name: "agentcapsule.llm.provider", Values: []string{"openai_compatible", "anthropic"}},
		{Name: "agentcapsule.llm.entry", Values: []string{"complete", "forward", "embed", "transcribe", "ocr"}},
		{Name: "agentcapsule.llm.mode", Values: []string{"unary", "stream"}},
		{Name: "agentcapsule.outcome", Values: []string{"ok", "invalid", "unavailable", "rate_limited", "rejected", "address_refused",
			"outcome_unknown", "dialect", "canceled", "unsupported", "stream_cut"}}},
	Ints: []string{"agentcapsule.llm.attempts", "agentcapsule.llm.input_tokens", "agentcapsule.llm.output_tokens"}})

func startCall(ctx context.Context, entry string, route Route) (context.Context, *telemetry.Span) {
	ctx, span := callSpan.Start(ctx)
	span.Code("agentcapsule.llm.entry", entry)
	span.Code("agentcapsule.llm.provider", route.Kind)
	span.Code("agentcapsule.llm.mode", "unary")
	return ctx, span
}

func endCall(span *telemetry.Span, usage Usage, err error) {
	if span == nil {
		return
	}
	outcome := "ok"
	switch {
	case err == nil:
		span.Int("agentcapsule.llm.input_tokens", usage.InputTokens)
		span.Int("agentcapsule.llm.output_tokens", usage.OutputTokens)
	case errors.Is(err, ErrAddressRefused):
		outcome = "address_refused"
	case errors.Is(err, ErrRejected):
		outcome = "rejected"
	case errors.Is(err, ErrRateLimited):
		outcome = "rate_limited"
	case errors.Is(err, errStreamCut):
		outcome = "stream_cut"
	case errors.Is(err, ErrUnavailable):
		outcome = "unavailable"
	case errors.Is(err, ErrOutcomeUnknown):
		outcome = "outcome_unknown"
	case errors.Is(err, ErrDialect):
		outcome = "dialect"
	case errors.Is(err, ErrUnsupported):
		outcome = "unsupported"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		outcome = "canceled"
	default:
		outcome = "invalid"
	}
	if err != nil {
		span.Fail()
	}
	span.Code("agentcapsule.outcome", outcome)
	span.End()
}
