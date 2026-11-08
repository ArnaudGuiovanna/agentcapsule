package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

type budgetLab struct {
	*tenantLab
	owner Principal
	agent string
	other string
}

func newBudgetLab(t *testing.T) *budgetLab {
	t.Helper()
	l, c, owner := agentLab(t)
	p := createProvider(t, l, owner, "bp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "al1", CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "m", InputMicroPerMTok: 1_000_000, OutputMicroPerMTok: 3_000_000}); err != nil {
		t.Fatal(err)
	}
	return &budgetLab{tenantLab: l, owner: owner, agent: createTenantAgent(t, c, owner, "a1"), other: createTenantAgent(t, c, owner, "a2")}
}

func (b *budgetLab) budget(t *testing.T, key string, in CreateLLMBudgetInput) LLMBudget {
	t.Helper()
	r, err := b.a.CreateLLMBudget(t.Context(), b.owner, key, in)
	var v LLMBudget
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create budget", err, r.Status)
	}
	return v
}

func (b *budgetLab) reserve(agent, key string, n int64) (LLMReservation, error) {
	return b.a.ReserveLLM(context.Background(), b.owner.TenantID, agent, "fast", key, n)
}

func TestHardBudgetRefusesBeforeTheCallAndReleaseGivesCapacityBack(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "b1", CreateLLMBudgetInput{Period: "day", LimitTokens: 1000, Mode: "hard"})
	r1, err := b.reserve(b.agent, "k1", 600)
	if err != nil || r1.State != "reserved" {
		t.Fatal(err)
	}
	if _, err = b.reserve(b.agent, "k2", 500); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("hard limit exceeded", err)
	}
	// Same key again: the existing reservation, counted once.
	again, err := b.reserve(b.agent, "k1", 600)
	if err != nil || !again.Replayed || again.ID != r1.ID {
		t.Fatal("retry double-counted", err)
	}
	if _, err = b.reserve(b.agent, "k3", 400); err != nil {
		t.Fatal("exact fit refused", err)
	}
	// A call that never left frees its tokens.
	if err = b.a.ReleaseLLM(t.Context(), b.owner.TenantID, r1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = b.reserve(b.agent, "k4", 600); err != nil {
		t.Fatal("released capacity not reusable", err)
	}
}

func TestUnknownOutcomeKeepsCountingUntilSettled(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "b1", CreateLLMBudgetInput{Period: "day", LimitTokens: 1000, Mode: "hard"})
	r, err := b.reserve(b.agent, "k1", 900)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.MarkLLMUnknown(t.Context(), b.owner.TenantID, r.ID); err != nil {
		t.Fatal(err)
	}
	if err = b.a.ReleaseLLM(t.Context(), b.owner.TenantID, r.ID); !errors.Is(err, ErrTransition) {
		t.Fatal("an unknown outcome was released as if free", err)
	}
	if _, err = b.reserve(b.agent, "k2", 200); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("uncertain spend read as zero", err)
	}
	rep, err := b.a.LLMUsage(t.Context(), b.owner, "day")
	if err != nil || len(rep.Lines) != 1 || rep.Lines[0].UnknownTokens != 900 || rep.Lines[0].SettledInput != 0 || !rep.Estimated {
		t.Fatal("usage does not isolate uncertainty", rep, err)
	}
	// A late report resolves it to the real amount.
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, 100, 50); err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, 100, 50); err != nil {
		t.Fatal("identical settlement not idempotent", err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, 1, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("settlement rewritten", err)
	}
	if _, err = b.reserve(b.agent, "k2", 200); err != nil {
		t.Fatal("capacity not returned after settlement", err)
	}
	rep, _ = b.a.LLMUsage(t.Context(), b.owner, "day")
	l := rep.Lines[0]
	// 100 in at 1.0/Mtok + 50 out at 3.0/Mtok = 250 micro-units after rounding up.
	if l.SettledInput != 100 || l.SettledOutput != 50 || l.UnknownTokens != 0 || l.PendingTokens != 200 || l.EstimatedCostMicr != 250 {
		t.Fatal("settled usage wrong", l)
	}
}

func TestConcurrentReservationsNeverOvershootAHardBudget(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "b1", CreateLLMBudgetInput{Period: "day", LimitTokens: 1000, Mode: "hard"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			agent := b.agent
			if i%2 == 1 {
				agent = b.other
			}
			_, err := b.reserve(agent, fmt.Sprintf("c%d", i), 100)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrBudgetExceeded):
				refused++
			default:
				t.Error("unexpected", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 10 || refused != 20 {
		t.Fatal("tenant-wide limit not respected", ok, refused)
	}
}

func TestScopedAndSoftBudgets(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "b1", CreateLLMBudgetInput{AgentID: b.agent, Period: "month", LimitTokens: 100, Mode: "hard"})
	b.budget(t, "b2", CreateLLMBudgetInput{Period: "day", LimitTokens: 150, Mode: "soft"})
	if _, err := b.a.CreateLLMBudget(t.Context(), b.owner, "dup", CreateLLMBudgetInput{AgentID: b.agent, Period: "month", LimitTokens: 5, Mode: "soft"}); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate scope accepted", err)
	}
	if _, err := b.reserve(b.agent, "k1", 101); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("agent budget ignored", err)
	}
	// The other agent is not bound by the first agent's budget; soft only warns.
	r, err := b.reserve(b.other, "k2", 200)
	if err != nil || !r.SoftExceeded {
		t.Fatal("soft budget blocked or silent", err, r.SoftExceeded)
	}
	if _, err = b.a.ReserveLLM(t.Context(), "org-else", b.other, "fast", "x", 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant reservation", err)
	}
	if _, err = b.a.ReserveLLM(t.Context(), b.owner.TenantID, b.other, "nope", "x", 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("unlisted model reserved", err)
	}
	// Disabling a budget lifts its limit at once.
	var first LLMBudget
	items, _ := b.a.ListLLMBudgets(t.Context(), b.owner, "", 10)
	for _, it := range items {
		if it.AgentID != nil {
			first = it
		}
	}
	if _, err = b.a.DisableLLMBudget(t.Context(), b.owner, first.ID, "off"); err != nil {
		t.Fatal(err)
	}
	if _, err = b.reserve(b.agent, "k3", 101); err != nil {
		t.Fatal("disabled budget still enforced", err)
	}
}

func TestMeteredCallSettlesReleasesAndMarksUnknown(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "b1", CreateLLMBudgetInput{Period: "day", LimitTokens: 100000, Mode: "hard"})
	var mode atomic.Int32 // 0 ok, 1 reject, 2 hang
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			w.WriteHeader(401)
		case 2:
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
		default:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"yo"}}],"usage":{"prompt_tokens":11,"completion_tokens":4}}`))
		}
	}))
	defer srv.Close()
	defer close(release)
	// Point the provider at the controlled server (loopback http is allowed).
	if _, err := b.s.pool.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := NewLLMService(b.a, llmgateway.New(llmgateway.Config{Timeout: 200 * time.Millisecond, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hello"}}, MaxTokens: 20}
	tenant := b.owner.TenantID
	out, err := svc.Call(t.Context(), tenant, b.agent, "fast", "m1", q)
	if err != nil || out.Text != "yo" {
		t.Fatal(err)
	}
	if _, err = svc.Call(t.Context(), tenant, b.agent, "fast", "m1", q); !errors.Is(err, ErrLLMAlreadyProcessed) {
		t.Fatal("a settled key was called again", err)
	}
	mode.Store(1)
	if _, err = svc.Call(t.Context(), tenant, b.agent, "fast", "m2", q); !errors.Is(err, llmgateway.ErrRejected) {
		t.Fatal(err)
	}
	mode.Store(2)
	if _, err = svc.Call(t.Context(), tenant, b.agent, "fast", "m3", q); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	rep, err := b.a.LLMUsage(t.Context(), b.owner, "day")
	if err != nil || len(rep.Lines) != 1 {
		t.Fatal(rep, err)
	}
	l := rep.Lines[0]
	if l.Calls != 2 || l.SettledInput != 11 || l.SettledOutput != 4 || l.UnknownTokens == 0 || l.PendingTokens != 0 {
		t.Fatal("ledger does not match the three outcomes", l)
	}
	// The rejected call (m2) was released: only settled and unknown remain.
	var released int
	if err = b.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage WHERE state='released'`).Scan(&released); err != nil || released != 1 {
		t.Fatal("rejected call not released", released, err)
	}
	// A crash between reserve and call leaves 'reserved'; the retry must not call again.
	if _, err = b.a.ReserveLLM(t.Context(), tenant, b.agent, "fast", "m4", 10); err != nil {
		t.Fatal(err)
	}
	mode.Store(0)
	if _, err = svc.Call(t.Context(), tenant, b.agent, "fast", "m4", q); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("orphan reservation replayed upstream", err)
	}
}
