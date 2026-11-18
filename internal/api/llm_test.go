package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func TestLLMProviderEndpointsNeverReturnTheCredential(t *testing.T) {
	l, cutoff, owner := apiAgentsLab(t)
	secret := "sk-http-0123456789abcdef"
	body := `{"name":"main","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"` + secret + `"}`
	r := call(t, l.server, "POST", "/v1/llm/providers", owner, "p1", body)
	var p controlplane.LLMProvider
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &p) != nil || strings.Contains(r.Body.String(), secret) {
		t.Fatal("create", r.Code, r.Body.String())
	}
	if again := call(t, l.server, "POST", "/v1/llm/providers", owner, "p1", body); again.Header().Get("Idempotency-Replayed") != "true" || strings.Contains(again.Body.String(), secret) {
		t.Fatal("replay", again.Code, again.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases", owner, "a1", `{"alias":"fast","provider_id":"`+p.ID+`","upstream_model":"gpt-x"}`); r.Code != 201 {
		t.Fatal("alias", r.Code, r.Body.String())
	}
	for _, path := range []string{"/v1/llm/providers", "/v1/llm/aliases"} {
		if r = call(t, l.server, "GET", path, owner, "", ""); r.Code != 200 || strings.Contains(r.Body.String(), secret) {
			t.Fatal("list", path, r.Code)
		}
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers/"+p.ID+"/rotate", owner, "r1", `{"secret":"sk-rotated-1234567890"}`); r.Code != 200 || strings.Contains(r.Body.String(), "sk-rotated") { // gitleaks:allow test fixture
		t.Fatal("rotate", r.Code, r.Body.String())
	}
	// A credential without the scope is refused.
	narrow := l.sign(t, cutoff, "owner", "alice", "org:read")
	if r = call(t, l.server, "GET", "/v1/llm/providers", narrow, "", ""); r.Code != 403 {
		t.Fatal("scope-less list", r.Code)
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers/"+p.ID+"/disable", owner, "d1", `{}`); r.Code != 200 {
		t.Fatal("disable", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers", owner, "p2", `{"name":"x","kind":"openai_compatible","base_url":"http://evil.example.org","secret":"`+secret+`"}`); r.Code != 400 {
		t.Fatal("plain http accepted", r.Code)
	}
	// An internal address written in the URL has its own code.
	if r = call(t, l.server, "POST", "/v1/llm/providers", owner, "p3", `{"name":"x","kind":"openai_compatible","base_url":"https://10.0.0.7/v1","secret":"`+secret+`"}`); r.Code != 400 ||
		!strings.Contains(r.Body.String(), `"code":"provider_address_not_allowed"`) {
		t.Fatal("internal address", r.Code, r.Body.String())
	}
}

// The routes of ADR 011: an alias's access, prices and grants; cost budgets;
// and the reconciliation of calls of unknown outcome.
func TestHTTPAliasAccessCostBudgetsAndReconciliation(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	agent := apiTenantAgent(t, l, owner, "alpha")
	r := call(t, l.server, "POST", "/v1/llm/providers", owner, "p1", `{"name":"main","kind":"anthropic","base_url":"https://llm.example.org","secret":"sk-http-0123456789abcdef"}`)
	var p controlplane.LLMProvider
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &p) != nil {
		t.Fatal("provider", r.Code, r.Body.String())
	}
	var alias controlplane.LLMAlias
	r = call(t, l.server, "POST", "/v1/llm/aliases", owner, "a1", `{"alias":"fast","provider_id":"`+p.ID+`","upstream_model":"m","access":"listed"}`)
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &alias) != nil || alias.Access != "listed" || alias.Priced {
		t.Fatal("listed alias", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases/fast/prices", owner, "pr", `{"input_micro_per_mtok":1000000,"output_micro_per_mtok":3000000}`); r.Code != 200 ||
		json.Unmarshal(r.Body.Bytes(), &alias) != nil || !alias.Priced || alias.OutputMicroPerMTok != 3000000 {
		t.Fatal("prices", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases/fast/prices", owner, "pr2", `{"input_micro_per_mtok":1}`); r.Code != 400 {
		t.Fatal("one price", r.Code)
	}
	var g controlplane.LLMAliasGrant
	if r = call(t, l.server, "POST", "/v1/llm/aliases/fast/grants", owner, "g1", `{"agent_id":"`+agent+`"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &g) != nil {
		t.Fatal("grant", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", "/v1/llm/aliases/fast/grants", owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), g.ID) {
		t.Fatal("grants", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases/fast/grants/"+g.ID+"/revoke", owner, "g2", `{}`); r.Code != 200 || !strings.Contains(r.Body.String(), `"revoked"`) {
		t.Fatal("revoke", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases/fast/access", owner, "ac", `{"access":"organization"}`); r.Code != 200 || !strings.Contains(r.Body.String(), `"organization"`) {
		t.Fatal("access", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/budgets", owner, "b1", `{"period":"day","limit_cost_micro":1000,"mode":"hard"}`); r.Code != 201 || !strings.Contains(r.Body.String(), `"limit_cost_micro":1000`) {
		t.Fatal("cost budget", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/budgets", owner, "b2", `{"period":"day","limit_tokens":10,"limit_cost_micro":1000,"mode":"hard"}`); r.Code != 400 {
		t.Fatal("two limits", r.Code)
	}
	// A call of unknown outcome, then its reconciliation.
	res, err := l.server.accounts.ReserveLLM(t.Context(), l.org.ID, agent, "fast", "k1", 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.server.accounts.MarkLLMUnknown(t.Context(), l.org.ID, res.ID); err != nil {
		t.Fatal(err)
	}
	if r = call(t, l.server, "GET", "/v1/llm/calls/unresolved", owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), res.ID) || !strings.Contains(r.Body.String(), `"reserved_cost_micro":700`) {
		t.Fatal("unresolved", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", "/v1/llm/budgets", owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"used":700`) {
		t.Fatal("budget consumption", r.Code, r.Body.String())
	}
	reader := l.sign(t, at, "narrow", "alice", "org:read usage:read")
	if r = call(t, l.server, "POST", "/v1/llm/calls/"+res.ID+"/settle", reader, "s0", `{"input_tokens":10,"output_tokens":5}`); r.Code != 403 {
		t.Fatal("settled without quota:manage", r.Code)
	}
	if r = call(t, l.server, "POST", "/v1/llm/calls/"+res.ID+"/settle", owner, "s1", `{"input_tokens":10,"output_tokens":5}`); r.Code != 200 ||
		!strings.Contains(r.Body.String(), `"state":"settled"`) || !strings.Contains(r.Body.String(), `"estimated_cost_micro":25`) {
		t.Fatal("settle", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/calls/"+res.ID+"/release", owner, "r1", `{}`); r.Code != 409 {
		t.Fatal("released after settlement", r.Code)
	}
	if r = call(t, l.server, "GET", "/v1/llm/usage?period=month", owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"totals":{"calls":1,"settled_input_tokens":10`) {
		t.Fatal("usage", r.Code, r.Body.String())
	}
}
