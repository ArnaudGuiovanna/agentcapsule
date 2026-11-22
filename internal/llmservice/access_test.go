package llmservice

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// A metered call to a listed alias by an agent without a grant is refused
// before any reservation and never reaches the provider.
func TestDeniedAliasNeverReachesTheProvider(t *testing.T) {
	b := newBudgetLab(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	defer srv.Close()
	if _, err := b.db.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := New(b.a, llmgateway.NewForTests(llmgateway.Config{Timeout: time.Second, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	seen := &recordingObserver{}
	svc.Observe(seen)
	b.access(t, "fast", "listed", "listed")
	b.grant(t, "fast", "g", CreateLLMAliasGrantInput{AgentID: b.agent})
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}, MaxTokens: 8}
	if _, err = svc.Call(t.Context(), b.owner.TenantID, b.other, "fast", "x1", q); !errors.Is(err, ErrLLMAliasDenied) {
		t.Fatal("denied agent", err)
	}
	if calls.Load() != 0 || b.usageRows(t) != 0 {
		t.Fatal("a denied call reached the provider or reserved budget")
	}
	if _, err = svc.Call(t.Context(), b.owner.TenantID, b.agent, "fast", "x2", q); err != nil || calls.Load() != 1 {
		t.Fatal("granted agent", err)
	}
	events := seen.all()
	if len(events) != 2 || events[0].Outcome != "refused" || events[0].Reason != "alias_access" || events[1].Outcome != "settled" ||
		events[1].Provider != "openai_compatible" || events[1].InputTokens != 3 || events[1].OutputTokens != 2 {
		t.Fatal("observed", events)
	}
}

type recordingObserver struct {
	mu     sync.Mutex
	events []CallEvent
}

func (o *recordingObserver) ObserveLLM(e CallEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (o *recordingObserver) all() []CallEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]CallEvent(nil), o.events...)
}
