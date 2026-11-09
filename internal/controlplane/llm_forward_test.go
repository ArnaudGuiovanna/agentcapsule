package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// An agent's native request from the model endpoint in its VM is metered like a
// platform call: placement check, reservation from the request's size and
// output cap, one outcome, usage attributed to its tenant and agent.
func TestNativeModelRequestFromAVMIsMeteredLikeACall(t *testing.T) {
	l, c, owner := agentLab(t)
	p := createProvider(t, l, owner, "fp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "fa", CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "upstream-m"}); err != nil {
		t.Fatal(err)
	}
	answer := `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"ls","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":4}}`
	var provider atomic.Int32
	var model atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider.Add(1)
		var v struct{ Model string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &v)
		model.Store(v.Model)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := NewLLMService(l.a, llmgateway.New(llmgateway.Config{Timeout: time.Second, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	agent := activateTenantAgent(t, l, c, owner, "native-agent")
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
	caller := VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: pl.Generation}
	body := []byte(`{"model":"fast","messages":[{"role":"user","content":"list files"}],"tools":[{"type":"function","function":{"name":"ls"}}],"max_tokens":64}`)

	out, err := svc.ForwardFromVM(t.Context(), caller, "fw-1", "fast", "openai", body, nil)
	if err != nil || string(out.Body) != answer || out.Usage != (llmgateway.Usage{InputTokens: 9, OutputTokens: 4}) || model.Load() != "upstream-m" {
		t.Fatal("native request", string(out.Body), err, model.Load())
	}
	if _, err = svc.ForwardFromVM(t.Context(), caller, "fw-1", "fast", "openai", body, nil); !errors.Is(err, ErrLLMAlreadyProcessed) {
		t.Fatal("a settled key was forwarded twice", err)
	}
	calls := provider.Load()
	// Refused before any reservation: a stream, a malformed body, a stale VM.
	if _, err = svc.ForwardFromVM(t.Context(), caller, "fw-2", "fast", "openai", []byte(`{"messages":[1],"stream":true}`), nil); !errors.Is(err, llmgateway.ErrInvalid) {
		t.Fatal("stream", err)
	}
	stale := caller
	stale.Generation++
	if _, err = svc.ForwardFromVM(t.Context(), stale, "fw-3", "fast", "openai", body, nil); !errors.Is(err, ErrPlacement) {
		t.Fatal("stale VM", err)
	}
	// An alias whose provider speaks another API: released, never sent.
	if _, err = svc.ForwardFromVM(t.Context(), caller, "fw-4", "fast", "anthropic", body, nil); !errors.Is(err, llmgateway.ErrDialect) {
		t.Fatal("dialect", err)
	}
	if _, err = svc.ForwardFromVM(t.Context(), caller, "fw-5", "missing", "openai", body, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("an alias the tenant never defined", err)
	}
	if provider.Load() != calls {
		t.Fatal("a refused request reached the provider")
	}
	// The reservation follows the request's own output cap: a hard budget
	// smaller than it refuses before the provider.
	if r, err := l.a.CreateLLMBudget(t.Context(), owner, "fb", CreateLLMBudgetInput{Period: "day", LimitTokens: 13 + 200, Mode: "hard"}); err != nil || r.Status != 201 {
		t.Fatal("budget", err)
	}
	big := []byte(`{"messages":[{"role":"user","content":"x"}],"max_completion_tokens":500}`)
	if _, err = svc.ForwardFromVM(t.Context(), caller, "fw-6", "fast", "openai", big, nil); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("hard budget", err)
	}
	if provider.Load() != calls {
		t.Fatal("an over-budget request reached the provider")
	}
	rep, err := l.a.LLMUsage(t.Context(), owner, "day")
	if err != nil || len(rep.Lines) != 1 || rep.Lines[0].AgentID != agent || rep.Lines[0].SettledInput != 9 || rep.Lines[0].SettledOutput != 4 || rep.Lines[0].PendingTokens != 0 {
		t.Fatal("usage", rep, err)
	}
}
