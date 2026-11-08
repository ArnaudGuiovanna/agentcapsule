//go:build llmlive

package llmgateway

// Live provider checks. They run only with -tags llmlive against a real
// OpenAI-compatible endpoint, normally a local Ollama, named by
// AGENTCAPSULE_TEST_LLM_BASE_URL and AGENTCAPSULE_TEST_LLM_MODEL. They never run
// in the default campaigns and need no paid credential. Model output is not
// asserted beyond being present: only the gateway's contract is.

import (
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func liveRoute(t *testing.T) Route {
	t.Helper()
	base, model := os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_LLM_MODEL")
	if base == "" || model == "" {
		t.Fatal("-tags llmlive needs AGENTCAPSULE_TEST_LLM_BASE_URL and AGENTCAPSULE_TEST_LLM_MODEL")
	}
	secret := os.Getenv("AGENTCAPSULE_TEST_LLM_SECRET")
	if secret == "" {
		secret = "local-model-server" // a local Ollama ignores it; the gateway requires one
	}
	return Route{Kind: "openai_compatible", BaseURL: base, UpstreamModel: model, Secret: secret, Key: "live/" + model}
}

type countingTransport struct{ n atomic.Int32 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func zero() *float64 { v := 0.0; return &v }

func short() Request {
	return Request{Messages: []Message{{Role: "system", Content: "Answer in one short sentence."}, {Role: "user", Content: "Say hello."}},
		MaxTokens: 16, Temperature: zero()}
}

func TestLiveProviderCompletesAndReportsUsage(t *testing.T) {
	g := New(Config{Timeout: 2 * time.Minute, MaxAttempts: 1})
	out, err := g.Complete(t.Context(), liveRoute(t), short())
	if err != nil {
		t.Fatal("live call failed", err)
	}
	if out.Text == "" || out.Usage.InputTokens <= 0 || out.Usage.OutputTokens <= 0 {
		t.Fatalf("empty answer or usage: %q %+v", out.Text, out.Usage)
	}
	if out.Usage.OutputTokens > 16 {
		t.Fatal("the provider ignored max_tokens", out.Usage.OutputTokens)
	}
	if out.FinishReason != "stop" && out.FinishReason != "length" {
		t.Fatal("unexpected finish reason", out.FinishReason)
	}
	t.Logf("model answered %d bytes, usage %+v, finish %s", len(out.Text), out.Usage, out.FinishReason)
}

func TestLiveUnknownModelIsRejectedWithoutOpeningTheBreaker(t *testing.T) {
	g := New(Config{Timeout: time.Minute, MaxAttempts: 3, FailureLimit: 1})
	good := liveRoute(t)
	bad := good
	bad.UpstreamModel = "agentcapsule-no-such-model"
	if _, err := g.Complete(t.Context(), bad, short()); !errors.Is(err, ErrRejected) {
		t.Fatal("an unknown model was not a definite refusal", err)
	}
	// Same breaker bucket, failure limit 1: a refusal proves the provider is up.
	if _, err := g.Complete(t.Context(), good, short()); err != nil {
		t.Fatal("a refusal opened the breaker", err)
	}
}

func TestLiveTimeoutAfterSendIsOutcomeUnknownAndNotRetried(t *testing.T) {
	route := liveRoute(t)
	// Load the model first so the slow call below is slow because it generates.
	if _, err := New(Config{Timeout: 2 * time.Minute, MaxAttempts: 1}).Complete(t.Context(), route, short()); err != nil {
		t.Fatal("warm-up failed", err)
	}
	transport := &countingTransport{}
	g := New(Config{HTTP: &http.Client{Transport: transport}, Timeout: 50 * time.Millisecond, MaxAttempts: 3})
	long := Request{Messages: []Message{{Role: "user", Content: "Count from 1 to 400, separated by commas."}}, MaxTokens: 1024, Temperature: zero()}
	if _, err := g.Complete(t.Context(), route, long); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("a call cut after sending was not reported as uncertain", err)
	}
	if n := transport.n.Load(); n != 1 {
		t.Fatal("a possibly billed call was retried", n)
	}
}
