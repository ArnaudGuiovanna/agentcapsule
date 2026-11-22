package llmservice

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

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
	if _, err := b.db.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := New(b.a, llmgateway.NewForTests(llmgateway.Config{Timeout: 200 * time.Millisecond, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
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
	if err = b.db.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage WHERE state='released'`).Scan(&released); err != nil || released != 1 {
		t.Fatal("rejected call not released", released, err)
	}
	// A crash between reserve and call leaves 'reserved'; the retry must not call again.
	if _, err = b.a.ReserveLLM(t.Context(), tenant, b.agent, "fast", "m4", 10, 0); err != nil {
		t.Fatal(err)
	}
	mode.Store(0)
	if _, err = svc.Call(t.Context(), tenant, b.agent, "fast", "m4", q); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("orphan reservation replayed upstream", err)
	}
}
