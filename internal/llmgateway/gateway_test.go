package llmgateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fast(c Config) *Gateway {
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return New(c)
}

var ask = Request{Messages: []Message{{Role: "system", Content: "be brief"}, {Role: "user", Content: "hi"}}, MaxTokens: 50}

func TestOpenAIAdapterWireFormatAndUsage(t *testing.T) {
	var gotAuth, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotPath, gotBody = r.Header.Get("Authorization"), r.URL.Path, string(b)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
	}))
	defer srv.Close()
	out, err := fast(Config{}).Complete(t.Context(), Route{Kind: "openai_compatible", BaseURL: srv.URL + "/v1/", UpstreamModel: "m1", Secret: "sk-secret", Key: "t/p"}, ask)
	if err != nil || out.Text != "hello" || out.Usage.InputTokens != 7 || out.Usage.OutputTokens != 3 || out.FinishReason != "stop" {
		t.Fatal(out, err)
	}
	if gotAuth != "Bearer sk-secret" || gotPath != "/v1/chat/completions" || !strings.Contains(gotBody, `"model":"m1"`) || !strings.Contains(gotBody, `"max_tokens":50`) {
		t.Fatal(gotAuth, gotPath, gotBody)
	}
}

func TestAnthropicAdapterWireFormat(t *testing.T) {
	var key, version, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		key, version, path, body = r.Header.Get("x-api-key"), r.Header.Get("anthropic-version"), r.URL.Path, string(b)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"bonjour"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`))
	}))
	defer srv.Close()
	out, err := fast(Config{}).Complete(t.Context(), Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "c1", Secret: "sk-ant", Key: "t/a"}, ask)
	if err != nil || out.Text != "bonjour" || out.Usage.InputTokens != 5 || out.FinishReason != "end_turn" {
		t.Fatal(out, err)
	}
	if key != "sk-ant" || version == "" || path != "/v1/messages" || !strings.Contains(body, `"system":"be brief"`) || strings.Contains(body, `"role":"system"`) {
		t.Fatal(key, version, path, body)
	}
}

func TestRetriesOnlyBeforeAcceptanceAndNeverOnDefiniteRefusal(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "k1"}
	if out, err := fast(Config{MaxAttempts: 2}).Complete(t.Context(), route, ask); err != nil || out.Text != "ok" || calls.Load() != 2 {
		t.Fatal("503 not retried", err, calls.Load())
	}
	var rejected atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rejected.Add(1); w.WriteHeader(401) }))
	defer bad.Close()
	route.BaseURL = bad.URL
	if _, err := fast(Config{MaxAttempts: 3}).Complete(t.Context(), route, ask); !errors.Is(err, ErrRejected) || rejected.Load() != 1 {
		t.Fatal("401 retried or mistyped", err, rejected.Load())
	}
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
	defer limited.Close()
	route.BaseURL = limited.URL
	if _, err := fast(Config{MaxAttempts: 2}).Complete(t.Context(), route, ask); !errors.Is(err, ErrRateLimited) {
		t.Fatal("429 mistyped", err)
	}
}

func TestTimeoutAfterSendIsUnknownNotRetried(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "k2"}
	_, err := fast(Config{Timeout: 50 * time.Millisecond, MaxAttempts: 3}).Complete(t.Context(), route, ask)
	if !errors.Is(err, ErrOutcomeUnknown) || calls.Load() != 1 {
		t.Fatal("timeout must be unknown and not retried", err, calls.Load())
	}
}

func TestBreakerOpensThenProbesOnce(t *testing.T) {
	var calls atomic.Int32
	healthy := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !healthy.Load() {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"back"}}]}`))
	}))
	defer srv.Close()
	now := time.Unix(1000, 0)
	g := fast(Config{MaxAttempts: 1, FailureLimit: 2, OpenFor: time.Minute, Now: func() time.Time { return now }})
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "k3"}
	for i := 0; i < 2; i++ {
		if _, err := g.Complete(t.Context(), route, ask); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	before := calls.Load()
	if _, err := g.Complete(t.Context(), route, ask); !errors.Is(err, ErrUnavailable) || calls.Load() != before {
		t.Fatal("open breaker still called the provider")
	}
	// Another bucket is unaffected.
	other := route
	other.Key = "k4"
	healthy.Store(true)
	if _, err := g.Complete(t.Context(), other, ask); err != nil {
		t.Fatal("breaker leaked across keys", err)
	}
	now = now.Add(2 * time.Minute)
	if out, err := g.Complete(t.Context(), route, ask); err != nil || out.Text != "back" {
		t.Fatal("probe did not close the breaker", err)
	}
}

func TestInvalidInputIsRejectedBeforeAnyCall(t *testing.T) {
	g := fast(Config{})
	ok := Route{Kind: "openai_compatible", BaseURL: "http://127.0.0.1:1", UpstreamModel: "m", Secret: "s", Key: "k"}
	for _, q := range []Request{{}, {Messages: []Message{{Role: "tool", Content: "x"}}}, {Messages: []Message{{Role: "user", Content: ""}}}} {
		if _, err := g.Complete(t.Context(), ok, q); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted", q, err)
		}
	}
	bad := ok
	bad.Kind = "other"
	if _, err := g.Complete(t.Context(), bad, ask); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown kind accepted", err)
	}
	if _, err := g.Complete(t.Context(), Route{Kind: "anthropic", BaseURL: "http://x", UpstreamModel: "m", Secret: "s"}, Request{Messages: []Message{{Role: "system", Content: "only"}}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("system-only anthropic request accepted", err)
	}
}
