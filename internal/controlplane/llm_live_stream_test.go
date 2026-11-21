//go:build llmlive

package controlplane

// Metered model streams end to end against a real provider (ADR 022), with
// the variables of llm_live_test.go. The Anthropic API is the same server's,
// as in internal/llmgateway/live_stream_test.go.

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// withAnthropic adds the alias "local-anthropic": the server's Anthropic API
// through the lab's counting proxy.
func (l *liveLab) withAnthropic(t *testing.T) {
	t.Helper()
	base := os.Getenv("AGENTCAPSULE_TEST_LLM_ANTHROPIC_BASE_URL")
	if base == "" {
		base = strings.TrimSuffix(strings.TrimRight(os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), "/"), "/v1")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	var proxy string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT base_url FROM llm_providers WHERE tenant_id=$1`, l.owner.TenantID).Scan(&proxy); err != nil {
		t.Fatal(err)
	}
	p, _ := url.Parse(proxy)
	mode, secret := "none", os.Getenv("AGENTCAPSULE_TEST_LLM_SECRET")
	if secret != "" {
		mode = "secret"
	}
	r, err := l.a.CreateLLMProvider(t.Context(), l.owner, "live-anthropic", CreateLLMProviderInput{AuthMode: mode, Name: "local-anthropic-server", Kind: "anthropic",
		BaseURL: p.Scheme + "://" + p.Host + strings.TrimRight(u.Path, "/"), Secret: secret})
	var v LLMProvider
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create provider", err)
	}
	if _, err = l.a.CreateLLMAlias(t.Context(), l.owner, "alias-local-anthropic", CreateLLMAliasInput{Alias: "local-anthropic", ProviderID: v.ID,
		UpstreamModel: os.Getenv("AGENTCAPSULE_TEST_LLM_MODEL"), InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
		t.Fatal(err)
	}
}

func liveStreamBody(dialect string) []byte {
	b, _ := json.Marshal(map[string]any{"model": "alias", "max_tokens": 16, "temperature": 0, "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "Say hello in one short sentence."}}})
	return b
}

// A capsule's model stream, in both dialects and as text, is relayed as it
// comes and settled at the usage the provider reported; its key is never
// sent again.
func TestLiveModelStreamIsSettledAtTheProviderReportedUsage(t *testing.T) {
	l := newLiveLab(t)
	l.withAnthropic(t)
	svc := l.service(t, 2*time.Minute)
	var settled llmgateway.Usage
	for _, c := range []struct{ key, alias, dialect string }{{"s-openai", "local", "openai"}, {"s-anthropic", "local-anthropic", "anthropic"}} {
		events := 0
		end, err := svc.ForwardStreamFromVM(t.Context(), l.caller, c.key, c.alias, c.dialect, liveStreamBody(c.dialect), nil, func(llmgateway.Event) error { events++; return nil })
		if err != nil || end.Outcome != LLMStreamCompleted || events < 3 || end.Usage.InputTokens <= 0 || end.Usage.OutputTokens <= 0 {
			t.Fatal(c.dialect, end, err, events)
		}
		if l.usageState(t, c.key) != "settled" {
			t.Fatal(c.dialect, "a completed stream was not settled")
		}
		settled.InputTokens += end.Usage.InputTokens
		settled.OutputTokens += end.Usage.OutputTokens
		t.Logf("%s: %d events, usage %+v settled", c.dialect, events, end.Usage)
	}
	var text []string
	end, err := svc.CompleteStreamFromVM(t.Context(), l.caller, "s-text", "local", liveRequest(16), nil, func(s string) error { text = append(text, s); return nil })
	if err != nil || end.Outcome != LLMStreamCompleted || len(text) == 0 || end.FinishReason == "" || l.usageState(t, "s-text") != "settled" {
		t.Fatal("text stream", end, err)
	}
	settled.InputTokens += end.Usage.InputTokens
	settled.OutputTokens += end.Usage.OutputTokens
	rep, err := l.a.LLMUsage(t.Context(), l.owner, "day")
	if err != nil || rep.Totals.Calls != 3 || rep.Totals.SettledInput != settled.InputTokens || rep.Totals.SettledOutput != settled.OutputTokens ||
		rep.Totals.PendingTokens != 0 || rep.Totals.UnknownTokens != 0 {
		t.Fatalf("usage does not match the provider's count: %+v vs %+v (%v)", rep.Totals, settled, err)
	}
	before := l.sent.Load()
	if _, err = svc.ForwardStreamFromVM(t.Context(), l.caller, "s-openai", "local", "openai", liveStreamBody("openai"), nil, func(llmgateway.Event) error { return nil }); !errors.Is(err, ErrLLMAlreadyProcessed) {
		t.Fatal("a settled stream's key was replayed", err)
	}
	if l.sent.Load() != before || before != 3 {
		t.Fatal("a replayed key reached the provider", before, l.sent.Load())
	}
}

// A stream cut after its first event, here by a guest that leaves, is never
// sent again; its reservation stays counted as unknown until the
// organization settles it.
func TestLiveModelStreamCutStaysUnknownAndReconcilable(t *testing.T) {
	l := newLiveLab(t)
	l.withAnthropic(t)
	svc := l.service(t, 2*time.Minute)
	for _, c := range []struct{ key, alias, dialect string }{{"cut-openai", "local", "openai"}, {"cut-anthropic", "local-anthropic", "anthropic"}} {
		events := 0
		end, err := svc.ForwardStreamFromVM(t.Context(), l.caller, c.key, c.alias, c.dialect, liveStreamBody(c.dialect), nil, func(llmgateway.Event) error {
			if events++; events == 2 {
				return errors.New("the guest left")
			}
			return nil
		})
		if err != nil || end.Outcome != LLMStreamOutcomeUnknown || events != 2 {
			t.Fatal(c.dialect, end, err, events)
		}
		if l.usageState(t, c.key) != "unknown" {
			t.Fatal(c.dialect, "a cut stream is not unknown")
		}
		before := l.sent.Load()
		if _, err = svc.ForwardStreamFromVM(t.Context(), l.caller, c.key, c.alias, c.dialect, liveStreamBody(c.dialect), nil, func(llmgateway.Event) error { return nil }); !errors.Is(err, ErrLLMAlreadyProcessed) || l.sent.Load() != before {
			t.Fatal(c.dialect, "a cut stream's key was sent again", err)
		}
	}
	calls, err := l.a.ListLLMUnresolved(t.Context(), l.owner, "", 10)
	if err != nil || len(calls) != 2 {
		t.Fatal("unresolved", calls, err)
	}
	rep, err := l.a.LLMUsage(t.Context(), l.owner, "day")
	if err != nil || rep.Totals.UnknownTokens <= 0 {
		t.Fatal("a cut stream is no longer counted", rep.Totals, err)
	}
	if r, err := l.a.SettleLLMOutcome(t.Context(), l.owner, calls[0].ID, "settle-1", SettleLLMOutcomeInput{InputTokens: 40, OutputTokens: 2}); err != nil || r.Status != 200 {
		t.Fatal("reconcile", err)
	}
	if r, err := l.a.ReleaseLLMOutcome(t.Context(), l.owner, calls[1].ID, "release-1"); err != nil || r.Status != 200 {
		t.Fatal("reconcile", err)
	}
	if calls, err = l.a.ListLLMUnresolved(t.Context(), l.owner, "", 10); err != nil || len(calls) != 0 {
		t.Fatal("still unresolved", calls, err)
	}
}
