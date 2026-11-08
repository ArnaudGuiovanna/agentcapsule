package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

func TestModelCallFromAVMIsBoundToItsTenantAndPlacement(t *testing.T) {
	l, c, owner := agentLab(t)
	p := createProvider(t, l, owner, "vp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "al", CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "m"}); err != nil {
		t.Fatal(err)
	}
	var provider atomic.Int32
	var inAdmission atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inAdmission.Load() {
			t.Error("the provider was called while holding host admission")
		}
		provider.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"from the model"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
	}))
	defer srv.Close()
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := NewLLMService(l.a, llmgateway.New(llmgateway.Config{Timeout: time.Second, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	agent := activateTenantAgent(t, l, c, owner, "vm-agent")
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
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}, MaxTokens: 16}

	// The admission hook stands in for the worker's host lock; the provider call
	// must happen after it has been released.
	guard := func(ctx context.Context, fn func(context.Context) error) error {
		inAdmission.Store(true)
		defer inAdmission.Store(false)
		return fn(ctx)
	}
	out, err := svc.CallFromVM(t.Context(), caller, "vm-1", "fast", q, guard)
	if err != nil || out.Text != "from the model" {
		t.Fatal("running capsule could not call its model", err)
	}
	// The key is scoped to the agent, and a settled key is never called again.
	if _, err = svc.CallFromVM(t.Context(), caller, "vm-1", "fast", q, guard); !errors.Is(err, ErrLLMAlreadyProcessed) {
		t.Fatal("a settled key was called twice", err)
	}
	if _, err = svc.CallFromVM(t.Context(), caller, "vm-2", "missing", q, guard); err == nil {
		t.Fatal("an alias the tenant never defined was served")
	}
	// A stale generation is refused before any reservation or provider call.
	before := provider.Load()
	stale := caller
	stale.Generation++
	if _, err = svc.CallFromVM(t.Context(), stale, "vm-3", "fast", q, guard); !errors.Is(err, ErrPlacement) {
		t.Fatal("a stale VM reached the gateway", err)
	}
	if provider.Load() != before {
		t.Fatal("a refused VM caused a provider call")
	}
	// Usage is attributed to this tenant and agent.
	rep, err := l.a.LLMUsage(t.Context(), owner, "day")
	if err != nil || len(rep.Lines) == 0 || rep.Lines[0].SettledInput != 7 {
		t.Fatal("usage not attributed", rep, err)
	}
}
