package llmgateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The agent's own request reaches the provider with its tools and options
// intact; only the model and the credential are the platform's.
func TestForwardKeepsTheAgentRequestAndReplacesModelAndCredential(t *testing.T) {
	var got map[string]any
	var auth, path string
	answer := `{"id":"x","choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":4}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	body := `{"model":"fast","messages":[{"role":"user","content":"read it"}],"tools":[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}],"tool_choice":"auto","stream":false,"stream_options":null,"n":1,"temperature":0.1}`
	out, err := fast(Config{}).Forward(t.Context(), Route{Kind: "openai_compatible", BaseURL: srv.URL + "/v1", UpstreamModel: "gpt-up", Secret: "sk-secret", Key: "t/p"}, DialectOpenAI, []byte(body))
	if err != nil || string(out.Body) != answer || out.Usage != (Usage{11, 4}) {
		t.Fatal(string(out.Body), out.Usage, err)
	}
	if auth != "Bearer sk-secret" || path != "/v1/chat/completions" || got["model"] != "gpt-up" || got["tools"] == nil || got["tool_choice"] != "auto" || got["temperature"] != 0.1 {
		t.Fatal(auth, path, got)
	}
	if _, ok := got["stream"]; ok {
		t.Fatal("stream forwarded", got)
	}
	if _, ok := got["stream_options"]; ok {
		t.Fatal("stream options forwarded", got)
	}
}

func TestForwardAnthropicCountsCachedInput(t *testing.T) {
	var key, version, path string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		key, version, path = r.Header.Get("x-api-key"), r.Header.Get("anthropic-version"), r.URL.Path
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"tool_use","id":"t1","name":"bash","input":{"cmd":"ls"}}],"stop_reason":"tool_use","usage":{"input_tokens":3,"cache_creation_input_tokens":5,"cache_read_input_tokens":7,"output_tokens":2}}`))
	}))
	defer srv.Close()
	body := `{"model":"smart","max_tokens":512,"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"list"}],"tools":[{"name":"bash","input_schema":{"type":"object"}}]}`
	out, err := fast(Config{}).Forward(t.Context(), Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "claude-up", Secret: "sk-ant", Key: "t/a"}, DialectAnthropic, []byte(body))
	if err != nil || out.Usage != (Usage{15, 2}) {
		t.Fatal(out.Usage, err)
	}
	if key != "sk-ant" || version == "" || path != "/v1/messages" || got["model"] != "claude-up" || got["system"] == nil || got["tools"] == nil || got["max_tokens"] != float64(512) {
		t.Fatal(key, version, path, got)
	}
}

func TestForwardRefusesWhatCannotBeAccountedOrRouted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	openai := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/o"}
	anthropic := Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/a"}
	g := fast(Config{})
	for _, c := range []struct {
		name    string
		route   Route
		dialect string
		body    string
		want    error
	}{
		{"stream", openai, DialectOpenAI, `{"messages":[{"role":"user","content":"x"}],"stream":true}`, ErrInvalid},
		{"several choices", openai, DialectOpenAI, `{"messages":[{"role":"user","content":"x"}],"n":2}`, ErrInvalid},
		{"no messages", openai, DialectOpenAI, `{"model":"m"}`, ErrInvalid},
		{"not an object", openai, DialectOpenAI, `[1]`, ErrInvalid},
		{"trailing data", openai, DialectOpenAI, `{"messages":[1]} {}`, ErrInvalid},
		{"huge cap", openai, DialectOpenAI, `{"messages":[1],"max_completion_tokens":2000000}`, ErrInvalid},
		{"fractional cap", openai, DialectOpenAI, `{"messages":[1],"max_tokens":1.5}`, ErrInvalid},
		{"anthropic without cap", anthropic, DialectAnthropic, `{"messages":[1]}`, ErrInvalid},
		{"unknown dialect", openai, "gemini", `{"messages":[1]}`, ErrInvalid},
		{"openai to anthropic", anthropic, DialectOpenAI, `{"messages":[1]}`, ErrDialect},
		{"anthropic to openai", openai, DialectAnthropic, `{"messages":[1],"max_tokens":5}`, ErrDialect},
		{"too large", openai, DialectOpenAI, `{"messages":["` + strings.Repeat("a", MaxForwardBytes) + `"]}`, ErrInvalid},
	} {
		if _, err := g.Forward(t.Context(), c.route, c.dialect, []byte(c.body)); !errors.Is(err, c.want) {
			t.Error(c.name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("a refused request reached the provider", calls.Load())
	}
	if max, err := ForwardOutputCap(DialectOpenAI, []byte(`{"messages":[1],"max_completion_tokens":300}`)); err != nil || max != 300 {
		t.Fatal(max, err)
	}
	if max, err := ForwardOutputCap(DialectOpenAI, []byte(`{"messages":[1]}`)); err != nil || max != 0 {
		t.Fatal(max, err)
	}
}

// An answer that cannot be accounted for was still produced (and maybe billed).
func TestForwardUnreadableAnswerIsAnUnknownOutcome(t *testing.T) {
	for _, answer := range []string{`{"choices":[]}`, `not json`, `{"choices":[{}],"usage":{"prompt_tokens":-1}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(answer)) }))
		_, err := fast(Config{}).Forward(t.Context(), Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/u"}, DialectOpenAI, []byte(`{"messages":[1]}`))
		srv.Close()
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal(answer, err)
		}
	}
	big := `{"choices":[{"message":{"content":"` + strings.Repeat("a", MaxForwardBytes) + `"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(big)) }))
	defer srv.Close()
	if _, err := fast(Config{}).Forward(t.Context(), Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/b"}, DialectOpenAI, []byte(`{"messages":[1]}`)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("an answer too large for the VM channel", err)
	}
}

// A refused request is not retried and does not open the breaker, as for Complete.
func TestForwardSharesRetriesAndBreaker(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/r"}
	if _, err := fast(Config{}).Forward(t.Context(), route, DialectOpenAI, []byte(`{"messages":[1]}`)); err != nil || calls.Load() != 2 {
		t.Fatal(err, calls.Load())
	}
	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(400) }))
	defer rejected.Close()
	calls.Store(0)
	route.BaseURL = rejected.URL
	if _, err := fast(Config{}).Forward(t.Context(), route, DialectOpenAI, []byte(`{"messages":[1]}`)); !errors.Is(err, ErrRejected) || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}
