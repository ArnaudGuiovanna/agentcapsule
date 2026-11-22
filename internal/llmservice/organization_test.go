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

// A disabled organization's agents call no model (organization_suspension.go),
// also while its VMs still run until the worker puts them to sleep: the call
// is refused before any route, reservation or provider request, as one the
// agent may not make.
func TestDisabledOrganizationCallsNoModel(t *testing.T) {
	b := newBudgetLab(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"yo"}}],"usage":{"prompt_tokens":11,"completion_tokens":4}}`))
	}))
	defer srv.Close()
	if _, err := b.db.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL); err != nil {
		t.Fatal(err)
	}
	svc, err := New(b.a, llmgateway.NewForTests(llmgateway.Config{Timeout: time.Second, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hello"}}, MaxTokens: 20}
	if _, err = svc.Call(t.Context(), b.owner.TenantID, b.agent, "fast", "before", q); err != nil || calls.Load() != 1 {
		t.Fatal("a call of an active organization", err, calls.Load())
	}
	if _, err = b.db.Exec(t.Context(), `UPDATE organizations SET status='disabled',policy_version=policy_version+1 WHERE id=$1`, b.owner.TenantID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Call(t.Context(), b.owner.TenantID, b.agent, "fast", "after", q)
	if !errors.Is(err, ErrOrganizationDisabled) || !errors.Is(err, ErrForbidden) {
		t.Fatal("a call of a disabled organization's agent", err)
	}
	if calls.Load() != 1 {
		t.Fatal("the provider was called for a disabled organization")
	}
	var reserved int
	if err = b.db.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage WHERE tenant_id=$1 AND request_key='after'`, b.owner.TenantID).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("a disabled organization's call reserved budget", reserved, err)
	}
}
