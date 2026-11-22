package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// policyLab is an agent placed on a VM, with the aliases "fast"
// (openai_compatible, chat), "embed" (the same provider, embeddings) and
// "claude" (anthropic), on a fake provider. The provider records each body,
// answers with the usage the test sets (usage: "" for none, "cap" for an
// output as long as the request's cap, 10,000 tokens when it has none), and
// holds each call while a gate is set.
type policyLab struct {
	*tenantLab
	owner     Principal
	caller    VMCaller
	svc       *LLMService
	seen      *firstEvents
	providers map[string]string // kind -> provider id
	calls     atomic.Int32
	last      atomic.Value // string: the last body
	usage     atomic.Value // string
	gate      atomic.Pointer[chan struct{}]
	arrived   chan struct{}
}

func newPolicyLab(t *testing.T) *policyLab {
	t.Helper()
	l, c, owner := agentLab(t)
	p := &policyLab{tenantLab: l, owner: owner, seen: &firstEvents{}, providers: map[string]string{}, arrived: make(chan struct{}, 64)}
	p.usage.Store(`,"usage":{"prompt_tokens":5,"completion_tokens":2,"input_tokens":5,"output_tokens":2}`)
	p.last.Store("")
	srv := httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(p.open) // before srv.Close, which waits for a held call
	for _, v := range []struct{ key, kind, base string }{{"pp-openai", "openai_compatible", srv.URL + "/v1"}, {"pp-anthropic", "anthropic", srv.URL}} {
		r, err := l.a.CreateLLMProvider(t.Context(), owner, v.key, CreateLLMProviderInput{Name: v.key, Kind: v.kind, BaseURL: "https://llm.example.org", Secret: providerSecret})
		var made LLMProvider
		if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &made) != nil {
			t.Fatal("create provider", err)
		}
		if _, err = l.s.pool.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1 WHERE id=$2`, v.base, made.ID); err != nil {
			t.Fatal(err)
		}
		p.providers[v.kind] = made.ID
	}
	for _, a := range []CreateLLMAliasInput{
		{Alias: "fast", ProviderID: p.providers["openai_compatible"]},
		{Alias: "embed", ProviderID: p.providers["openai_compatible"], Operations: []string{"embed"}},
		{Alias: "claude", ProviderID: p.providers["anthropic"]},
	} {
		a.UpstreamModel, a.InputMicroPerMTok, a.OutputMicroPerMTok = "up-"+a.Alias, price(1_000_000), price(1_000_000)
		if _, err := l.a.CreateLLMAlias(t.Context(), owner, "alias-"+a.Alias, a); err != nil {
			t.Fatal(a.Alias, err)
		}
	}
	agent := activateTenantAgent(t, l, c, owner, "policy-agent")
	if err := l.s.RegisterPlacement(t.Context(), agent, "local"); err != nil {
		t.Log("placement already registered:", err)
	}
	pl, err := l.s.ClaimPlacement(t.Context(), agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", pl.Generation)
	if err = l.s.ConfirmPlacement(t.Context(), agent, "local", "worker", pl.Generation, vm); err != nil {
		t.Fatal(err)
	}
	p.caller = VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: pl.Generation}
	g := llmgateway.NewForTests(llmgateway.Config{Timeout: 20 * time.Second, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true})
	if p.svc, err = NewLLMService(l.a, g); err != nil {
		t.Fatal(err)
	}
	p.svc.Observe(p.seen)
	return p
}

func (p *policyLab) serve(w http.ResponseWriter, r *http.Request) {
	p.calls.Add(1)
	b, _ := io.ReadAll(r.Body)
	p.last.Store(string(b))
	if gate := p.gate.Load(); gate != nil {
		p.arrived <- struct{}{}
		<-*gate
	}
	if strings.HasSuffix(r.URL.Path, "/embeddings") {
		_, _ = io.WriteString(w, `{"data":[{"index":0,"embedding":[0.5,0.25]}],"usage":{"prompt_tokens":3}}`)
		return
	}
	usage := p.usage.Load().(string)
	if usage == "cap" {
		var req struct {
			MaxTokens           *int64 `json:"max_tokens"`
			MaxCompletionTokens *int64 `json:"max_completion_tokens"`
		}
		_ = json.Unmarshal(b, &req)
		out := int64(10_000) // what the model writes when nothing bounds it
		for _, n := range []*int64{req.MaxTokens, req.MaxCompletionTokens} {
			if n != nil {
				out = min(out, *n)
			}
		}
		usage = fmt.Sprintf(`,"usage":{"prompt_tokens":10,"completion_tokens":%d,"input_tokens":10,"output_tokens":%d}`, out, out)
	}
	if r.URL.Path == "/v1/messages" {
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]`+usage+`}`)
		return
	}
	_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]`+usage+`}`)
}

// hold makes every call wait at the provider until open.
func (p *policyLab) hold() { gate := make(chan struct{}); p.gate.Store(&gate) }

func (p *policyLab) open() {
	if gate := p.gate.Swap(nil); gate != nil {
		close(*gate)
	}
}

func (p *policyLab) forward(t *testing.T, key, alias, dialect, body string) (ForwardResult, error) {
	t.Helper()
	return p.svc.ForwardFromVM(t.Context(), p.caller, key, alias, dialect, []byte(body), nil)
}

type usageRow struct {
	State                     string
	Reserved                  int64
	SettledInput, SettledOutp *int64
}

func (p *policyLab) row(t *testing.T, key string) (usageRow, bool) {
	t.Helper()
	var u usageRow
	err := p.s.pool.QueryRow(t.Context(), `SELECT state,reserved_tokens,input_tokens,output_tokens FROM llm_usage WHERE agent_id=$1 AND request_key=$2`, p.caller.AgentID, key).
		Scan(&u.State, &u.Reserved, &u.SettledInput, &u.SettledOutp)
	if err != nil {
		return usageRow{}, false
	}
	return u, true
}

func (p *policyLab) refusals(reason string) int {
	p.seen.mu.Lock()
	defer p.seen.mu.Unlock()
	n := 0
	for _, e := range p.seen.events {
		if e.Outcome == "refused" && e.Reason == reason {
			n++
		}
	}
	return n
}

func (p *policyLab) setPolicy(t *testing.T, alias, key string, in SetLLMAliasRequestPolicyInput) LLMAlias {
	t.Helper()
	r, err := p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, alias, key, in)
	var v LLMAlias
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("request policy", err)
	}
	return v
}

// A provider-executed tool or a cost-changing option is refused before any
// reservation, in both dialects, unary and stream, until the organization
// names it in the alias's request policy (S-11). The policy is validated,
// audited, listed, and applies from the next reservation. An agent that may
// not call a listed alias learns nothing of its policy.
func TestTheRequestPolicyRefusesServerToolsBeforeAnyReservation(t *testing.T) {
	p := newPolicyLab(t)
	search := `{"messages":[{"role":"user","content":"look it up"}],"tools":[{"type":"web_search_preview"}],"max_tokens":16}`
	refused := []struct{ alias, dialect, body string }{
		{"fast", "openai", search},
		{"fast", "openai", `{"messages":[{"role":"user","content":"hi"}],"service_tier":"priority","max_tokens":16}`},
		{"fast", "openai", `{"messages":[{"role":"user","content":"hi"}],"web_search_options":{},"max_tokens":16}`},
		{"claude", "anthropic", `{"max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`},
		{"claude", "anthropic", `{"max_tokens":16,"messages":[{"role":"user","content":"hi"}],"mcp_servers":[{"type":"url","url":"https://mcp.example","name":"m"}]}`},
		{"claude", "anthropic", `{"max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`},
	}
	for i, c := range refused {
		if _, err := p.forward(t, fmt.Sprintf("deny-%d", i), c.alias, c.dialect, c.body); !errors.Is(err, llmgateway.ErrFeatureDenied) {
			t.Fatal(c.body, err)
		}
		stream := strings.Replace(c.body, "{", `{"stream":true,`, 1)
		if _, err := p.svc.ForwardStreamFromVM(t.Context(), p.caller, fmt.Sprintf("deny-s-%d", i), c.alias, c.dialect, []byte(stream), nil, func(llmgateway.Event) error { return nil }); !errors.Is(err, llmgateway.ErrFeatureDenied) {
			t.Fatal("stream", c.body, err)
		}
		if _, found := p.row(t, fmt.Sprintf("deny-%d", i)); found {
			t.Fatal("a refused request reserved", c.body)
		}
	}
	if p.calls.Load() != 0 || p.refusals("feature_denied") != 2*len(refused) {
		t.Fatal("refused requests reached the provider or were not observed", p.calls.Load(), p.refusals("feature_denied"))
	}
	// The organization allows web search, and nothing else, on fast.
	v := p.setPolicy(t, "fast", "rp-1", SetLLMAliasRequestPolicyInput{AllowedToolTypes: []string{"web_search_preview"}})
	if !slices.Equal(v.AllowedToolTypes, []string{"web_search_preview"}) || v.AllowedFields == nil || len(v.AllowedFields) != 0 || v.OutputCapField != "max_tokens" || v.MaxOutputTokens != nil {
		t.Fatal("policy", v)
	}
	if _, err := p.forward(t, "allowed-1", "fast", "openai", search); err != nil || p.calls.Load() != 1 || !strings.Contains(p.last.Load().(string), "web_search_preview") {
		t.Fatal("an allowed server tool was refused", err)
	}
	if _, err := p.forward(t, "deny-again", "fast", "openai", refused[1].body); !errors.Is(err, llmgateway.ErrFeatureDenied) {
		t.Fatal("an option the policy does not name", err)
	}
	// Audited once; a replayed key and an unchanged policy change nothing.
	again, err := p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, "fast", "rp-1", SetLLMAliasRequestPolicyInput{AllowedToolTypes: []string{"web_search_preview"}})
	if err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	p.setPolicy(t, "fast", "rp-2", SetLLMAliasRequestPolicyInput{AllowedToolTypes: []string{"web_search_preview"}})
	var audited int
	if err = p.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_audit WHERE tenant_id=$1 AND action='alias.request_policy_set' AND alias='fast' AND actor_principal_id=$2`,
		p.owner.TenantID, p.owner.ID).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("audit", audited, err)
	}
	// Names are sorted; a bad one, a repeated one, one the gateway rules on,
	// too many, or a cap out of bounds is refused.
	v = p.setPolicy(t, "fast", "rp-3", SetLLMAliasRequestPolicyInput{AllowedFields: []string{"top_k", "service_tier"}, MaxOutputTokens: price(8000), OutputCapField: "max_completion_tokens"})
	if !slices.Equal(v.AllowedFields, []string{"service_tier", "top_k"}) || len(v.AllowedToolTypes) != 0 || *v.MaxOutputTokens != 8000 || v.OutputCapField != "max_completion_tokens" {
		t.Fatal("policy", v)
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("f%d", i)
	}
	for _, bad := range []SetLLMAliasRequestPolicyInput{
		{AllowedFields: []string{"Store"}}, {AllowedFields: []string{"model"}}, {AllowedFields: []string{"max_tokens"}}, {AllowedFields: []string{"stream"}},
		{AllowedFields: []string{"store", "store"}}, {AllowedToolTypes: []string{"web search"}}, {AllowedFields: many}, {AllowedFields: []string{""}},
		{MaxOutputTokens: price(0)}, {MaxOutputTokens: price(1_000_001)}, {OutputCapField: "max_output_tokens"},
	} {
		if _, err = p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, "fast", newID("k"), bad); !errors.Is(err, ErrInput) {
			t.Fatal("accepted", bad, err)
		}
	}
	if _, err = p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, "claude", "rp-4", SetLLMAliasRequestPolicyInput{OutputCapField: "max_completion_tokens"}); !errors.Is(err, ErrInput) {
		t.Fatal("an anthropic alias reads max_tokens only", err)
	}
	// The list shows it; an alias can be created with one.
	items, err := p.a.ListLLMAliases(t.Context(), p.owner, "", 50)
	if err != nil || len(items) != 3 || !slices.Equal(items[2].AllowedFields, []string{"service_tier", "top_k"}) {
		t.Fatal("list", items, err)
	}
	r, err := p.a.CreateLLMAlias(t.Context(), p.owner, "alias-tiered", CreateLLMAliasInput{Alias: "tiered", ProviderID: p.providers["openai_compatible"], UpstreamModel: "m",
		AllowedFields: []string{"store"}, AllowedToolTypes: []string{"file_search"}, MaxOutputTokens: price(500)})
	var created LLMAlias
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &created) != nil || !slices.Equal(created.AllowedFields, []string{"store"}) || *created.MaxOutputTokens != 500 {
		t.Fatal("create with a policy", err, created)
	}
	if _, err = p.a.CreateLLMAlias(t.Context(), p.owner, "alias-bad", CreateLLMAliasInput{Alias: "bad", ProviderID: p.providers["anthropic"], UpstreamModel: "m",
		OutputCapField: "max_completion_tokens"}); !errors.Is(err, ErrInput) {
		t.Fatal("an anthropic alias with max_completion_tokens", err)
	}
	if _, err = p.a.DisableLLMAlias(t.Context(), p.owner, "tiered", "dis-tiered"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, "tiered", "rp-5", SetLLMAliasRequestPolicyInput{}); !errors.Is(err, ErrTransition) {
		t.Fatal("a disabled alias took a policy", err)
	}
	// A listed alias not granted to the agent: the refusal is alias_access,
	// whatever the request asks.
	if _, err = p.a.SetLLMAliasAccess(t.Context(), p.owner, "claude", "listed", SetLLMAliasAccessInput{Access: "listed"}); err != nil {
		t.Fatal(err)
	}
	if _, err = p.forward(t, "not-granted", "claude", "anthropic", refused[3].body); !errors.Is(err, ErrLLMAliasDenied) || errors.Is(err, llmgateway.ErrFeatureDenied) {
		t.Fatal("an alias not granted revealed its policy", err)
	}
}

// A call that declares no output cap is held to its alias's maximum output,
// else the platform's default: the cap reaches the provider in the field the
// alias names and is what the reservation counts, with the media the provider
// fetches by reference (S-13).
func TestAnUncappedCallIsHeldToItsAliasMaximumAndReservesIt(t *testing.T) {
	p := newPolicyLab(t)
	body := `{"messages":[{"role":"user","content":"hi"}]}`
	estimate := llmgateway.EstimateTokens([]byte(body))
	sent := func() map[string]json.RawMessage {
		var v map[string]json.RawMessage
		if err := json.Unmarshal([]byte(p.last.Load().(string)), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := p.forward(t, "cap-default", "fast", "openai", body); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "cap-default"); u.Reserved != estimate+llmgateway.DefaultForwardOutput || string(sent()["max_tokens"]) != "4096" {
		t.Fatal("default cap", u, p.last.Load())
	}
	p.setPolicy(t, "fast", "rp-cap", SetLLMAliasRequestPolicyInput{MaxOutputTokens: price(300), OutputCapField: "max_completion_tokens"})
	if _, err := p.forward(t, "cap-alias", "fast", "openai", body); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "cap-alias"); u.Reserved != estimate+300 || string(sent()["max_completion_tokens"]) != "300" || sent()["max_tokens"] != nil {
		t.Fatal("alias cap", u, p.last.Load())
	}
	// A declared cap is the request's own.
	if _, err := p.forward(t, "cap-own", "fast", "openai", `{"messages":[{"role":"user","content":"hi"}],"max_tokens":40}`); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "cap-own"); u.Reserved != llmgateway.EstimateTokens([]byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":40}`))+40 {
		t.Fatal("declared cap", u)
	}
	// An image by URL: the body is small, the reservation is not.
	image := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://img.example/x.png"}}]}],"max_tokens":10}`
	if _, err := p.forward(t, "image", "fast", "openai", image); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "image"); u.Reserved != llmgateway.EstimateTokens([]byte(image))+llmgateway.ImageInputTokens+10 {
		t.Fatal("image by reference", u)
	}
	// The text route takes the alias's cap too.
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hello"}}}
	if _, err := p.svc.CallFromVM(t.Context(), p.caller, "text-cap", "fast", q, nil); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "text-cap"); u.Reserved != llmgateway.EstimateTokens([]byte("hello"))+messageOverhead+300 || string(sent()["max_completion_tokens"]) != "300" {
		t.Fatal("text route cap", u, p.last.Load())
	}
}

// Concurrent uncapped calls against a hard budget: each is admitted only if
// every reservation in the window still fits, and none settles above its
// reservation, since the provider is held to the reserved cap. The window
// never passes the limit (S-13). Before the cap was injected, each call
// reserved 4,096 output tokens and the provider wrote 10,000.
func TestAHardBudgetHoldsUnderConcurrentUncappedCalls(t *testing.T) {
	p := newPolicyLab(t)
	p.usage.Store("cap")
	p.svc.LimitCallsPerAgent(32)
	body := `{"messages":[{"role":"user","content":"write at length"}]}`
	each := llmgateway.EstimateTokens([]byte(body)) + llmgateway.DefaultForwardOutput
	limit := 4*each + each/2
	if r, err := p.a.CreateLLMBudget(t.Context(), p.owner, "hard", CreateLLMBudgetInput{Period: "day", LimitTokens: limit, Mode: "hard"}); err != nil || r.Status != 201 {
		t.Fatal("budget", err)
	}
	p.hold()
	const calls = 12
	var refused, failed atomic.Int32
	var wg sync.WaitGroup
	for i := range calls {
		wg.Go(func() {
			_, err := p.forward(t, fmt.Sprintf("burst-%d", i), "fast", "openai", body)
			switch {
			case errors.Is(err, ErrBudgetExceeded):
				refused.Add(1)
			case err != nil:
				failed.Add(1)
				t.Error(err)
			}
		})
	}
	arrived := int32(0)
	for deadline := time.Now().Add(30 * time.Second); arrived+refused.Load()+failed.Load() < calls; {
		select {
		case <-p.arrived:
			arrived++
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("calls neither admitted nor refused", arrived, refused.Load())
		}
	}
	p.open()
	wg.Wait()
	if arrived != 4 || refused.Load() != calls-4 {
		t.Fatal("admitted", arrived, "refused", refused.Load())
	}
	rep, err := p.a.LLMUsage(t.Context(), p.owner, "day")
	if err != nil || rep.Totals.PendingTokens != 0 || rep.Totals.SettledInput+rep.Totals.SettledOutput > limit {
		t.Fatal("the window passed its hard limit", rep.Totals, limit, err)
	}
}

// An agent has at most its limit of model calls in flight, every route
// counted; the next is refused before any reservation, and observed. A
// replay of a running key is still an unknown outcome (S-13).
func TestTheCallsInFlightOfAnAgentAreBounded(t *testing.T) {
	p := newPolicyLab(t)
	p.svc.LimitCallsPerAgent(2)
	p.hold()
	body := `{"messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	done := make(chan error, 2)
	go func() { _, err := p.forward(t, "run-1", "fast", "openai", body); done <- err }()
	go func() {
		_, err := p.svc.EmbedFromVM(t.Context(), p.caller, "run-2", "embed", llmgateway.EmbedRequest{Input: []string{"x"}}, nil)
		done <- err
	}()
	<-p.arrived
	<-p.arrived
	if _, err := p.forward(t, "run-3", "fast", "openai", body); !errors.Is(err, ErrLLMConcurrency) {
		t.Fatal("a third call in flight", err)
	}
	if _, err := p.svc.ForwardStreamFromVM(t.Context(), p.caller, "run-4", "fast", "openai", []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), nil,
		func(llmgateway.Event) error { return nil }); !errors.Is(err, ErrLLMConcurrency) {
		t.Fatal("a stream beyond the limit", err)
	}
	if _, found := p.row(t, "run-3"); found {
		t.Fatal("a call beyond the limit reserved")
	}
	if _, err := p.forward(t, "run-1", "fast", "openai", body); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("a replay of a running key", err)
	}
	if p.refusals("concurrency_limited") != 2 || p.calls.Load() != 2 {
		t.Fatal("refusals", p.refusals("concurrency_limited"), p.calls.Load())
	}
	p.open()
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.forward(t, "run-3", "fast", "openai", body); err != nil {
		t.Fatal("a call once the others ended", err)
	}
}

// A unary answer without usage, or with part of it, was produced and billed:
// what it left out settles at the reservation, never at zero (L-06).
func TestAnAnswerWithoutUsageSettlesAtTheReservation(t *testing.T) {
	p := newPolicyLab(t)
	p.usage.Store("")
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hello"}}, MaxTokens: 16}
	res, err := p.svc.CallFromVM(t.Context(), p.caller, "bare-text", "fast", q, nil)
	input := llmgateway.EstimateTokens([]byte("hello")) + messageOverhead
	if err != nil || res.Usage != (llmgateway.Usage{InputTokens: input, OutputTokens: 16}) {
		t.Fatal(res.Usage, err)
	}
	if u, _ := p.row(t, "bare-text"); u.State != "settled" || *u.SettledInput != input || *u.SettledOutp != 16 {
		t.Fatal("text call without usage", u)
	}
	body := `{"max_tokens":20,"messages":[{"role":"user","content":"hi"}]}`
	out, err := p.forward(t, "bare-claude", "claude", "anthropic", body)
	if err != nil || out.Usage != (llmgateway.Usage{InputTokens: llmgateway.EstimateTokens([]byte(body)), OutputTokens: 20}) {
		t.Fatal(out.Usage, err)
	}
	if u, _ := p.row(t, "bare-claude"); u.State != "settled" || *u.SettledOutp != 20 {
		t.Fatal("forward without usage", u)
	}
	p.usage.Store(`,"usage":{"completion_tokens":3}`)
	if _, err = p.forward(t, "half", "fast", "openai", `{"messages":[{"role":"user","content":"hi"}],"max_tokens":9}`); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.row(t, "half"); *u.SettledOutp != 3 || *u.SettledInput != llmgateway.EstimateTokens([]byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":9}`)) {
		t.Fatal("partial usage", u)
	}
	rep, err := p.a.LLMUsage(t.Context(), p.owner, "day")
	if err != nil || rep.Totals.SettledOutput != 16+20+3 {
		t.Fatal(rep.Totals, err)
	}
}

// An embedding whose key is replayed while it runs answers outcome_unknown
// without reaching the provider, and leaves the reservation to the running
// call, as for chat: the organization cannot resolve it under the running
// call, which then settles it (L-07).
func TestAMediaKeyInFlightIsNeitherSentAgainNorMadeUnknown(t *testing.T) {
	p := newPolicyLab(t)
	p.hold()
	words := llmgateway.EmbedRequest{Input: []string{"net present value"}}
	done := make(chan error, 1)
	go func() { _, err := p.svc.EmbedFromVM(t.Context(), p.caller, "vec", "embed", words, nil); done <- err }()
	<-p.arrived
	if _, err := p.svc.EmbedFromVM(t.Context(), p.caller, "vec", "embed", words, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("replay of a running embedding", err)
	}
	u, _ := p.row(t, "vec")
	if u.State != "reserved" || p.calls.Load() != 1 {
		t.Fatal("a replay touched a running embedding's reservation:", u.State, p.calls.Load())
	}
	var id string
	if err := p.s.pool.QueryRow(t.Context(), `SELECT id FROM llm_usage WHERE agent_id=$1 AND request_key='vec'`, p.caller.AgentID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.a.ReleaseLLMOutcome(t.Context(), p.owner, id, "too-early"); !errors.Is(err, ErrTransition) {
		t.Fatal("the organization released a running embedding", err)
	}
	p.open()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if u, _ = p.row(t, "vec"); u.State != "settled" || *u.SettledInput != 3 {
		t.Fatal("the running embedding's settlement", u)
	}
}

// Migration 65 on an installation that already has aliases and audit rows:
// every alias allows nothing beyond the plain fields and keeps the default
// output cap, and the audit takes the new action. The schema refuses what the
// API refuses.
func TestLLMRequestPolicyMigrationKeepsExistingAliases(t *testing.T) {
	p := newPolicyLab(t)
	if _, err := p.s.pool.Exec(t.Context(), `
        ALTER TABLE llm_audit DROP CONSTRAINT llm_audit_action_check,
          ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled',
            'budget.created','budget.disabled','alias.access_set','alias.prices_set','alias.grant_created','alias.grant_revoked','usage.settled','usage.released',
            'alias.operations_set'));
        ALTER TABLE llm_model_aliases DROP COLUMN allowed_fields, DROP COLUMN allowed_tool_types, DROP COLUMN max_output_tokens, DROP COLUMN output_cap_field`); err != nil {
		t.Fatal("revert", err)
	}
	if _, err := p.s.pool.Exec(t.Context(), llmRequestPolicySQL); err != nil {
		t.Fatal("migrate", err)
	}
	items, err := p.a.ListLLMAliases(t.Context(), p.owner, "", 10)
	if err != nil || len(items) != 3 {
		t.Fatal(items, err)
	}
	for _, a := range items {
		if a.AllowedFields == nil || len(a.AllowedFields) != 0 || len(a.AllowedToolTypes) != 0 || a.MaxOutputTokens != nil || a.OutputCapField != "max_tokens" {
			t.Fatal("alias after migration", a)
		}
	}
	p.setPolicy(t, "fast", "after-migration", SetLLMAliasRequestPolicyInput{AllowedFields: []string{"store"}})
	for _, bad := range []string{
		`UPDATE llm_model_aliases SET allowed_fields='{Store}' WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET allowed_tool_types=ARRAY[NULL]::text[] WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET max_output_tokens=0 WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET output_cap_field='max' WHERE alias='fast'`,
	} {
		if _, err = p.s.pool.Exec(t.Context(), bad); err == nil {
			t.Fatal("the schema accepted", bad)
		}
	}
}

// A provider disabled, or a credential rotated, between the route's
// resolution and its reservation is never used: the disabled provider
// refuses the call before any reservation, and a rotated credential is
// resolved again (L-08).
func TestARouteChangedBeforeItsReservationIsNeverUsed(t *testing.T) {
	p := newPolicyLab(t)
	amounts := llmAmounts{Operation: LLMChat, Input: 5, Output: 5}
	rotated := "sk-rotated-0123456789-abcdef" // gitleaks:allow test fixture, not a credential
	once := sync.Once{}
	hold, err := p.svc.admit(t.Context(), p.owner.TenantID, p.caller.AgentID, "claude", "rot-1", func(LLMRoute) (llmAmounts, error) {
		once.Do(func() {
			if _, err := p.a.RotateLLMProviderSecret(t.Context(), p.owner, p.providers["anthropic"], "rotate", rotated); err != nil {
				t.Error(err)
			}
		})
		return amounts, nil
	})
	if err != nil || hold.route.Secret != rotated || hold.route.Generation != 2 {
		t.Fatal("a route rotated before its reservation", err, hold.route.Generation)
	}
	hold.release()
	hold, err = p.svc.admit(t.Context(), p.owner.TenantID, p.caller.AgentID, "fast", "dis-1", func(LLMRoute) (llmAmounts, error) {
		if _, err := p.a.DisableLLMProvider(t.Context(), p.owner, p.providers["openai_compatible"], "disable"); err != nil {
			t.Error(err)
		}
		return amounts, nil
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("a provider disabled before the reservation was used", err)
	}
	if _, found := p.row(t, "dis-1"); found {
		t.Fatal("a disabled provider's call reserved")
	}
	// The key was given back with the refusal.
	if _, err = p.svc.admit(t.Context(), p.owner.TenantID, p.caller.AgentID, "fast", "dis-1", func(LLMRoute) (llmAmounts, error) { return amounts, nil }); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
