//go:build linux

package worker

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The operator sees model calls as technical counts: tokens and estimated
// cost by provider kind, outcomes, refusals and soft caps by closed codes, and
// how many calls wait for reconciliation. No organization, agent or alias.
func TestModelCallMetricsAndEventsCarryNoTenant(t *testing.T) {
	registry := telemetry.NewRegistry()
	var logs bytes.Buffer
	vocabulary := map[string][]string{"event": LLMEvents()}
	for k, v := range LLMEventCodes() {
		vocabulary[k] = v
	}
	m := NewLLMTelemetry(registry, telemetry.NewLogger(&logs, vocabulary), func(context.Context) (int64, error) { return 4, nil })
	soft := []controlplane.LLMBudgetHit{{Unit: "cost", Period: "day", Scope: "organization"}}
	m.ObserveLLM(llmservice.CallEvent{Provider: "anthropic", Outcome: "settled", InputTokens: 120, OutputTokens: 30, CostMicro: 210, SoftBudgets: soft})
	m.ObserveLLM(llmservice.CallEvent{Provider: "openai_compatible", Outcome: "unknown"})
	m.ObserveLLM(llmservice.CallEvent{Provider: "openai_compatible", Outcome: "refused", Reason: "budget_cost", Period: "month", Scope: "agent"})
	m.ObserveLLM(llmservice.CallEvent{Provider: "openai_compatible", Outcome: "refused", Reason: "alias_access"})
	m.ObserveLLM(llmservice.CallEvent{Provider: "org_acme/fast", Outcome: "settled", InputTokens: 1})
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`agentcapsule_llm_tokens_total{provider="anthropic",direction="input"} 120`,
		`agentcapsule_llm_tokens_total{provider="anthropic",direction="output"} 30`,
		`agentcapsule_llm_estimated_cost_micro_total{provider="anthropic"} 210`,
		`agentcapsule_llm_calls_total{provider="openai_compatible",outcome="unknown"} 1`,
		`agentcapsule_llm_calls_total{provider="other",outcome="settled"} 1`,
		`agentcapsule_llm_refusals_total{reason="budget_cost"} 1`,
		`agentcapsule_llm_refusals_total{reason="alias_access"} 1`,
		`agentcapsule_llm_refusals_total{reason="unpriced"} 0`,
		`agentcapsule_llm_budget_soft_exceeded_total{unit="cost"} 1`,
		`agentcapsule_llm_budget_soft_exceeded_total{unit="tokens"} 0`,
		`agentcapsule_llm_unresolved_calls 4`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Fatal("missing", want, "\n", body)
		}
	}
	if strings.Contains(body, "acme") || strings.Contains(logs.String(), "acme") {
		t.Fatal("a tenant value reached the operator")
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 3 ||
		!strings.Contains(lines[0], `"event":"llm_budget_soft_exceeded","unit":"cost","period":"day","scope":"organization"`) ||
		!strings.Contains(lines[1], `"event":"llm_call_refused","reason":"budget_cost","period":"month","scope":"agent"`) ||
		!strings.Contains(lines[2], `"event":"llm_call_refused","reason":"alias_access"}`) {
		t.Fatal("events", logs.String())
	}
}
