package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func (a *platformFake) ForwardLLM(_ context.Context, key string, in LLMForward) (LLMForwardResult, error) {
	a.calls.Add(1)
	switch key {
	case "dialect":
		return LLMForwardResult{}, &PlatformError{Code: "dialect"}
	case "budget":
		return LLMForwardResult{}, &PlatformError{Code: "quota_exceeded"}
	case "leak":
		return LLMForwardResult{}, errors.New("sk-live-provider-secret")
	}
	return LLMForwardResult{Body: json.RawMessage(`{"echo":` + string(in.Body) + `,"alias":"` + in.Alias + `"}`), InputTokens: 5, OutputTokens: 1}, nil
}

// A native request crosses the channel as the agent wrote it, under the alias it
// named; the platform's answer comes back untouched.
func TestLLMForwardCarriesTheNativeRequestAndTypedOutcomes(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	body := `{"model":"fast","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function"}]}`
	in := LLMForward{Alias: "fast", Dialect: "openai", Body: json.RawMessage(body)}
	r, err := c.ForwardLLM(t.Context(), "k1", in)
	if err != nil || r.InputTokens != 5 || r.OutputTokens != 1 {
		t.Fatal(r, err)
	}
	var echoed struct {
		Echo  json.RawMessage `json:"echo"`
		Alias string          `json:"alias"`
	}
	var compact bytes.Buffer
	_ = json.Compact(&compact, []byte(body))
	if json.Unmarshal(r.Body, &echoed) != nil || string(echoed.Echo) != compact.String() || echoed.Alias != "fast" {
		t.Fatal(string(r.Body))
	}
	for key, code := range map[string]string{"dialect": "dialect", "budget": "quota_exceeded", "leak": "unavailable"} {
		_, err = c.ForwardLLM(t.Context(), key, in)
		var pe *PlatformError
		if !errors.As(err, &pe) || pe.Code != code || strings.Contains(err.Error(), "sk-live") {
			t.Fatal(key, err)
		}
	}
	calls := api.calls.Load()
	for i, bad := range []LLMForward{
		{Alias: "", Dialect: "openai", Body: in.Body},
		{Alias: "a b", Dialect: "openai", Body: in.Body},
		{Alias: "fast", Dialect: "gemini", Body: in.Body},
		{Alias: "fast", Dialect: "openai", Body: json.RawMessage(`[1]`)},
		{Alias: "fast", Dialect: "openai", Body: json.RawMessage(`{"a":`)},
		{Alias: "fast", Dialect: "anthropic", Body: json.RawMessage(`{"m":"` + strings.Repeat("a", MaxLLMForwardBytes) + `"}`)},
	} {
		if _, err = c.ForwardLLM(t.Context(), "bad", bad); err == nil {
			t.Fatal("invalid forward accepted", i)
		}
	}
	// The same checks hold on the host for a client that skips them.
	for i, bad := range []*platformRequest{
		{Key: "x", Forward: &LLMForward{Alias: "fast", Dialect: "gemini", Body: in.Body}},
		{Key: "", Forward: &in},
		{Key: "x", Forward: &in, LLM: &LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "x"}}}},
	} {
		if _, err = c.callWithTimeout(t.Context(), "/v1/llm/forward", bad, 0); err == nil {
			t.Fatal("host accepted an invalid forward", i)
		}
	}
	// A forward cannot ride on another route.
	if _, err = c.call(t.Context(), "/v1/directory/search", &platformRequest{Forward: &in}); err == nil {
		t.Fatal("forward smuggled on another route")
	}
	if api.calls.Load() != calls {
		t.Fatal("an invalid forward reached the adapter")
	}
	// The payload names no tenant, provider or credential the host would use.
	b, _ := json.Marshal(platformRequest{Protocol: Version, Identity: host.Identity, Key: "forged", Forward: &in})
	b = bytes.Replace(b, []byte(`"alias":`), []byte(`"provider_secret":"x","alias":`), 1)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+"/v1/llm/forward", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 || api.calls.Load() != calls {
		t.Fatal("unknown field reached the adapter", resp.StatusCode)
	}
}
