//go:build llmlive

package controlplane

// End-to-end metered model calls against a real OpenAI-compatible provider,
// normally a local Ollama (see internal/llmgateway/live_test.go for the
// variables). PostgreSQL is required as for every other store test. A counting
// reverse proxy sits between the gateway and the provider so the tests can
// prove which refusals happen before anything is sent.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

type liveLab struct {
	*tenantLab
	owner  Principal
	caller VMCaller
	sent   *atomic.Int32
}

func newLiveLab(t *testing.T) *liveLab {
	t.Helper()
	base, model := os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_LLM_MODEL")
	if base == "" || model == "" {
		t.Fatal("-tags llmlive needs AGENTCAPSULE_TEST_LLM_BASE_URL and AGENTCAPSULE_TEST_LLM_MODEL")
	}
	upstream, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	sent := &atomic.Int32{}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: upstream.Scheme, Host: upstream.Host})
	// A call the gateway cuts on purpose is not a proxy failure worth logging.
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	l, c, owner := agentLab(t)
	r, err := l.a.CreateLLMProvider(t.Context(), owner, "live", CreateLLMProviderInput{Name: "local-model-server", Kind: "openai_compatible",
		BaseURL: srv.URL + strings.TrimRight(upstream.Path, "/"), Secret: providerSecret})
	var p LLMProvider
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &p) != nil {
		t.Fatal("create provider", err)
	}
	for _, a := range []CreateLLMAliasInput{
		{Alias: "local", ProviderID: p.ID, UpstreamModel: model, InputMicroPerMTok: 1_000_000, OutputMicroPerMTok: 3_000_000},
		{Alias: "ghost", ProviderID: p.ID, UpstreamModel: "agentcapsule-no-such-model"},
	} {
		if _, err = l.a.CreateLLMAlias(t.Context(), owner, "alias-"+a.Alias, a); err != nil {
			t.Fatal(err)
		}
	}
	agent := activateTenantAgent(t, l, c, owner, "live-agent")
	if err = l.s.RegisterPlacement(t.Context(), agent, "local"); err != nil {
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
	return &liveLab{tenantLab: l, owner: owner, caller: VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: pl.Generation}, sent: sent}
}

func (l *liveLab) service(t *testing.T, timeout time.Duration) *LLMService {
	t.Helper()
	svc, err := NewLLMService(l.a, llmgateway.New(llmgateway.Config{Timeout: timeout, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (l *liveLab) usageState(t *testing.T, key string) string {
	t.Helper()
	var state string
	if err := l.s.pool.QueryRow(t.Context(), `SELECT state FROM llm_usage WHERE agent_id=$1 AND request_key=$2`, l.caller.AgentID, key).Scan(&state); err != nil {
		t.Fatal(key, err)
	}
	return state
}

func liveRequest(max int) llmgateway.Request {
	zero := 0.0
	return llmgateway.Request{Messages: []llmgateway.Message{{Role: "system", Content: "Answer in one short sentence."}, {Role: "user", Content: "Say hello."}},
		MaxTokens: max, Temperature: &zero}
}

func TestLiveModelCallIsSettledAtTheProviderReportedUsage(t *testing.T) {
	l := newLiveLab(t)
	svc := l.service(t, 2*time.Minute)
	out, err := svc.CallFromVM(t.Context(), l.caller, "live-1", "local", liveRequest(16), nil)
	if err != nil || out.Text == "" || out.Usage.InputTokens <= 0 || out.Usage.OutputTokens <= 0 {
		t.Fatal("the capsule's model call failed", err, out.Usage)
	}
	if l.usageState(t, "live-1") != "settled" {
		t.Fatal("a completed call was not settled")
	}
	rep, err := l.a.LLMUsage(t.Context(), l.owner, "day")
	if err != nil || len(rep.Lines) != 1 {
		t.Fatal("usage report", err, rep)
	}
	line := rep.Lines[0]
	if line.AgentID != l.caller.AgentID || line.Alias != "local" || line.Calls != 1 ||
		line.SettledInput != out.Usage.InputTokens || line.SettledOutput != out.Usage.OutputTokens || line.PendingTokens != 0 || line.UnknownTokens != 0 {
		t.Fatalf("usage does not match the provider's count: %+v vs %+v", line, out.Usage)
	}
	if want := out.Usage.InputTokens + 3*out.Usage.OutputTokens; line.EstimatedCostMicr != want {
		t.Fatal("cost estimate", line.EstimatedCostMicr, want)
	}
	// A settled key is never sent again.
	before := l.sent.Load()
	if _, err = svc.CallFromVM(t.Context(), l.caller, "live-1", "local", liveRequest(16), nil); !errors.Is(err, ErrLLMAlreadyProcessed) {
		t.Fatal("a settled key was replayed", err)
	}
	if l.sent.Load() != before {
		t.Fatal("a replayed key reached the provider")
	}
	t.Logf("provider usage %+v settled; estimated cost %d micro", out.Usage, line.EstimatedCostMicr)
}

func TestLiveHardBudgetRefusesBeforeTheProvider(t *testing.T) {
	l := newLiveLab(t)
	svc := l.service(t, 2*time.Minute)
	// The reservation for 16 output tokens plus the prompt estimate is above 10.
	if r, err := l.a.CreateLLMBudget(t.Context(), l.owner, "tiny", CreateLLMBudgetInput{Period: "day", LimitTokens: 10, Mode: "hard"}); err != nil || r.Status != 201 {
		t.Fatal("budget", err)
	}
	if _, err := svc.CallFromVM(t.Context(), l.caller, "over", "local", liveRequest(16), nil); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("a hard budget was exceeded", err)
	}
	if n := l.sent.Load(); n != 0 {
		t.Fatal("a refused call reached the provider", n)
	}
}

func TestLiveProviderRefusalReleasesTheReservation(t *testing.T) {
	l := newLiveLab(t)
	svc := l.service(t, time.Minute)
	if _, err := svc.CallFromVM(t.Context(), l.caller, "ghost-1", "ghost", liveRequest(16), nil); !errors.Is(err, llmgateway.ErrRejected) {
		t.Fatal("an unknown upstream model was not refused", err)
	}
	if l.sent.Load() != 1 {
		t.Fatal("a definite refusal was retried or never sent", l.sent.Load())
	}
	if l.usageState(t, "ghost-1") != "released" {
		t.Fatal("a refused call kept its budget")
	}
}

func TestLiveCallCutAfterSendingStaysCountedAsUnknown(t *testing.T) {
	l := newLiveLab(t)
	// Load the model so the cut below happens while it generates.
	if _, err := l.service(t, 2*time.Minute).CallFromVM(t.Context(), l.caller, "warm", "local", liveRequest(16), nil); err != nil {
		t.Fatal("warm-up", err)
	}
	zero := 0.0
	long := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "Count from 1 to 400, separated by commas."}}, MaxTokens: 1024, Temperature: &zero}
	if _, err := l.service(t, 50*time.Millisecond).CallFromVM(t.Context(), l.caller, "cut", "local", long, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("a call cut after sending was not uncertain", err)
	}
	if l.usageState(t, "cut") != "unknown" {
		t.Fatal("an uncertain call was not kept as unknown")
	}
	rep, err := l.a.LLMUsage(t.Context(), l.owner, "day")
	if err != nil || len(rep.Lines) != 1 || rep.Lines[0].UnknownTokens <= 0 {
		t.Fatal("an uncertain call is no longer counted", err, rep)
	}
}
