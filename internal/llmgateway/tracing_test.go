package llmgateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

type spanSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *spanSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// A model call is a client span (OPR-3): the provider's kind, the entry, the
// outcome, the attempts and the tokens. The prompt, the answer, the model,
// the provider's address and its key never reach it.
func TestModelCallsAreSpansWithoutContent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"the planted answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
	}))
	defer srv.Close()
	var sink spanSink
	tracer, err := telemetry.NewTracer(&sink, "agentcapsule-worker", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithTracer(context.Background(), tracer)
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL + "/v1/", UpstreamModel: "planted-model", Secret: "sk-planted-secret", Key: "t/p"}
	q := Request{Messages: []Message{{Role: "user", Content: "the planted prompt"}}, MaxTokens: 50}
	if _, err = fast(Config{}).Complete(ctx, route, q); err != nil {
		t.Fatal(err)
	}
	if _, err = fast(Config{}).Complete(ctx, Route{Kind: "anthropic", Secret: "sk-planted-secret"}, q); err == nil {
		t.Fatal("an incomplete route is invalid")
	}
	tracer.Close()
	out := sink.b.String()
	for _, planted := range []string{"planted", srv.URL, strings.TrimPrefix(srv.URL, "http://")} {
		if strings.Contains(out, planted) {
			t.Fatalf("%q reached a span", planted)
		}
	}
	for _, want := range []string{`"name":"llm.call","kind":3`, `{"key":"agentcapsule.llm.entry","value":{"stringValue":"complete"}}`,
		`{"key":"agentcapsule.llm.provider","value":{"stringValue":"openai_compatible"}}`, `{"key":"agentcapsule.llm.attempts","value":{"intValue":"2"}}`,
		`{"key":"agentcapsule.llm.input_tokens","value":{"intValue":"7"}}`, `{"key":"agentcapsule.llm.output_tokens","value":{"intValue":"3"}}`,
		`{"key":"agentcapsule.outcome","value":{"stringValue":"ok"}}`, `{"key":"agentcapsule.outcome","value":{"stringValue":"invalid"}}`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in\n%s", want, out)
		}
	}
}
