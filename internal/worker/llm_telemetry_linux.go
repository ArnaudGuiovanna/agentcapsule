//go:build linux

package worker

import (
	"context"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

var (
	llmProviders = []string{"openai_compatible", "anthropic"}
	llmOutcomes  = []string{"settled", "released", "unknown"}
	llmRefusals  = []string{"budget_tokens", "budget_cost", "unpriced", "alias_access", "unsupported"}
	llmUnits     = []string{"tokens", "cost"}
	llmPeriods   = []string{"day", "month"}
	llmScopes    = []string{"organization", "agent", "alias", "agent_alias"}
)

// LLMTelemetry tells the operator about metered model calls (LLM-05, OPS-02):
// settled tokens and estimated cost by provider kind, outcomes, refusals and
// soft budgets by closed codes, and the calls whose outcome waits for their
// organization. No organization, agent, alias or model is a label or a field:
// each organization reads its own per agent and per alias figures from
// GET /v1/llm/usage.
type LLMTelemetry struct {
	calls, tokens, cost, refusals, soft *telemetry.Counter
	firstEvent                          *telemetry.Histogram
	problems                            *telemetry.Logger
	// Seconds of audio and OCR pages of settled calls (ADR 023 §12).
	audioSeconds, pages *telemetry.Counter
}

// NewLLMTelemetry registers the metrics. unresolved counts, at each scrape,
// the installation's calls of unknown outcome (Store.LLMUnresolvedCalls).
func NewLLMTelemetry(registry *telemetry.Registry, problems *telemetry.Logger, unresolved func(context.Context) (int64, error)) *LLMTelemetry {
	provider := telemetry.Label{Name: "provider", Values: llmProviders}
	m := &LLMTelemetry{
		calls: registry.Counter("agentcapsule_llm_calls_total", "Model calls that reached the provider or might have, by provider kind and outcome (settled, released, unknown).",
			provider, telemetry.Label{Name: "outcome", Values: llmOutcomes}),
		tokens: registry.Counter("agentcapsule_llm_tokens_total", "Tokens of settled model calls, as the provider reported them, by provider kind and direction (input, output).",
			provider, telemetry.Label{Name: "direction", Values: []string{"input", "output"}}),
		cost: registry.Counter("agentcapsule_llm_estimated_cost_micro_total", "Estimated cost of settled model calls, in micro-units of each organization's own currency, by provider kind.",
			provider),
		refusals: registry.Counter("agentcapsule_llm_refusals_total", "Model calls refused before any reservation, by reason (budget_tokens, budget_cost, unpriced, alias_access, unsupported).",
			telemetry.Label{Name: "reason", Values: llmRefusals}),
		soft: registry.Counter("agentcapsule_llm_budget_soft_exceeded_total", "Model calls that went past a soft budget, by its unit (tokens, cost); a call past two counts twice.",
			telemetry.Label{Name: "unit", Values: llmUnits}),
		firstEvent: registry.Histogram("agentcapsule_llm_stream_first_event_seconds", "Time from a model stream's provider request to its first event.",
			[]float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}),
		problems: problems,
		audioSeconds: registry.Counter("agentcapsule_llm_audio_seconds_total", "Seconds of audio of settled transcriptions, as the provider reported them, by provider kind.",
			provider),
		pages: registry.Counter("agentcapsule_llm_ocr_pages_total", "Pages of settled OCR calls, as the provider reported them, by provider kind.", provider),
	}
	// Served from zero, so that increase() sees the first one.
	for _, r := range llmRefusals {
		m.refusals.Add(0, r)
	}
	for _, u := range llmUnits {
		m.soft.Add(0, u)
	}
	gauge := registry.Gauge("agentcapsule_llm_unresolved_calls", "Model calls of unknown outcome that wait for their organization to settle or release them, across the installation.")
	registry.Collect(func(ctx context.Context) error {
		n, err := unresolved(ctx)
		if err != nil {
			return err
		}
		gauge.Set(float64(n))
		return nil
	})
	return m
}

// ObserveLLM counts one call. A soft budget passed and a refusal are also
// logged to problems (standard error), with codes only.
func (m *LLMTelemetry) ObserveLLM(e controlplane.LLMCallEvent) {
	for _, hit := range e.SoftBudgets {
		m.soft.Inc(hit.Unit)
		m.problems.Event("llm_budget_soft_exceeded", telemetry.Code("unit", hit.Unit), telemetry.Code("period", hit.Period), telemetry.Code("scope", hit.Scope))
	}
	if e.Outcome == "refused" {
		m.refusals.Inc(e.Reason)
		fields := []telemetry.Field{telemetry.Code("reason", e.Reason)}
		if e.Period != "" {
			fields = append(fields, telemetry.Code("period", e.Period), telemetry.Code("scope", e.Scope))
		}
		m.problems.Event("llm_call_refused", fields...)
		return
	}
	m.calls.Inc(e.Provider, e.Outcome)
	if e.Outcome == "settled" {
		m.tokens.Add(float64(e.InputTokens), e.Provider, "input")
		m.tokens.Add(float64(e.OutputTokens), e.Provider, "output")
		m.cost.Add(float64(e.CostMicro), e.Provider)
		m.audioSeconds.Add(float64(e.AudioSeconds), e.Provider)
		m.pages.Add(float64(e.Pages), e.Provider)
	}
}

// ObserveFirstEvent times a stream's first provider event.
func (m *LLMTelemetry) ObserveFirstEvent(d time.Duration) { m.firstEvent.Observe(d.Seconds()) }

var _ controlplane.LLMStreamObserver = (*LLMTelemetry)(nil)

// LLMEvents and LLMEventCodes are the vocabulary of the model gateway's
// events, for the worker's loggers.
func LLMEvents() []string { return []string{"llm_budget_soft_exceeded", "llm_call_refused"} }

func LLMEventCodes() map[string][]string {
	return map[string][]string{"reason": slices.Clone(llmRefusals), "unit": slices.Clone(llmUnits), "period": slices.Clone(llmPeriods), "scope": slices.Clone(llmScopes)}
}
