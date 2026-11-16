//go:build linux

package worker

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// The gateway the worker builds from its configuration refuses a provider on
// an internal address unless the operator's allowlist names it. No setting
// of the configuration reaches the tests' loopback option.
func TestLLMConfigAllowsOnlyTheOperatorsInternalProviders(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	route := llmgateway.Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "sk-provider-key", Key: "t/p"}
	ask := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}}
	call := func(s ServiceLLM) error {
		t.Helper()
		c, err := s.gatewayConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = llmgateway.New(c).Complete(t.Context(), route, ask)
		return err
	}
	if err := call(ServiceLLM{}); !errors.Is(err, llmgateway.ErrAddressRefused) || calls.Load() != 0 {
		t.Fatal("the default configuration called a provider on loopback:", err)
	}
	if err := call(ServiceLLM{AllowedInternalProviders: []string{"10.0.0.0/8", "127.0.0.1:1"}}); !errors.Is(err, llmgateway.ErrAddressRefused) || calls.Load() != 0 {
		t.Fatal("entries that do not name the provider let it through:", err)
	}
	if err := call(ServiceLLM{AllowedInternalProviders: []string{"127.0.0.1:" + port}}); err != nil || calls.Load() != 1 {
		t.Fatal("the allowed provider was refused:", err)
	}
	c, err := (&ServiceLLM{}).gatewayConfig(true)
	if err != nil || !c.RequireHTTPS {
		t.Fatal("production must require HTTPS", err)
	}
	// An invalid entry stops the worker before it opens anything.
	for _, bad := range [][]string{{"8.8.8.8:443"}, {"0.0.0.0/0"}, {"169.254.169.254:80"}, {"models.internal"}} {
		cfg := ServiceConfig{LLM: &ServiceLLM{ReceiptKey: "/nonexistent/receipt.key", AllowedInternalProviders: bad}}
		if _, err := cfg.OpenLLM(nil, true); !errors.Is(err, llmgateway.ErrAllowlist) {
			t.Fatal(bad, "accepted:", err)
		}
	}
}
