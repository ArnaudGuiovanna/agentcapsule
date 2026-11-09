package agentadapter

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

type forwarder struct {
	mu     sync.Mutex
	calls  []capsuleprotocol.LLMForward
	keys   []string
	answer string
	err    error
}

func (f *forwarder) ForwardLLM(_ context.Context, key string, in capsuleprotocol.LLMForward) (capsuleprotocol.LLMForwardResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	f.keys = append(f.keys, key)
	if f.err != nil {
		return capsuleprotocol.LLMForwardResult{}, f.err
	}
	return capsuleprotocol.LLMForwardResult{Body: json.RawMessage(f.answer), InputTokens: 1, OutputTokens: 1}, nil
}

func endpoint(t *testing.T, f *forwarder, cfg string) *httptest.Server {
	t.Helper()
	c, err := ParseConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(&ModelEndpoint{Config: c, Platform: f})
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, body string) (*http.Response, string) {
	t.Helper()
	r, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var b strings.Builder
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		b.WriteString(sc.Text() + "\n")
	}
	return r, b.String()
}

// events splits a server-sent stream into (event, data) pairs.
func events(stream string) [][2]string {
	var out [][2]string
	event := ""
	for _, line := range strings.Split(stream, "\n") {
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			out = append(out, [2]string{event, strings.TrimPrefix(line, "data: ")})
			event = ""
		}
	}
	return out
}

const minimal = `{"version":1,"command":["/bin/agent"],"models":{"gpt-4o":"fast"}}`

// The agent's SDK talks to the endpoint as to OpenAI: the request reaches the
// platform under the mapped alias with its tools, the answer comes back under
// the model name the agent used.
func TestOpenAIRequestReachesThePlatformUnderItsAlias(t *testing.T) {
	f := &forwarder{answer: `{"id":"c1","object":"chat.completion","model":"upstream-secret-name","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`}
	srv := endpoint(t, f, minimal)
	r, body := post(t, srv.URL+"/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"ls"}}],"stream":false}`)
	if r.StatusCode != 200 || len(f.calls) != 1 {
		t.Fatal(r.StatusCode, body)
	}
	c := f.calls[0]
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(c.Body, &fields)
	if c.Alias != "fast" || c.Dialect != "openai" || fields["tools"] == nil || fields["stream"] != nil || !strings.HasPrefix(f.keys[0], "mdl_") {
		t.Fatal(c.Alias, c.Dialect, string(c.Body), f.keys)
	}
	var answer struct {
		Model   string
		Choices []struct{ Message struct{ Content string } }
	}
	if json.Unmarshal([]byte(body), &answer) != nil || answer.Model != "gpt-4o" || answer.Choices[0].Message.Content != "hi" {
		t.Fatal(body)
	}
	// Each request is a new call: a fresh key.
	post(t, srv.URL+"/chat/completions", `{"model":"fast","messages":[{"role":"user","content":"again"}]}`)
	if len(f.keys) != 2 || f.keys[0] == f.keys[1] || f.calls[1].Alias != "fast" {
		t.Fatal(f.keys, f.calls[1].Alias)
	}
}

// A streaming client receives the complete answer as one stream of chunks,
// tool calls with their positions, then the usage it asked for.
func TestOpenAIStreamReplaysTheAnswer(t *testing.T) {
	f := &forwarder{answer: `{"id":"c2","created":7,"model":"x","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"t1","type":"function","function":{"name":"read","arguments":"{\"p\":1}"}},{"id":"t2","type":"function","function":{"name":"ls","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":9}}`}
	srv := endpoint(t, f, minimal)
	r, stream := post(t, srv.URL+"/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"x"}],"stream":true,"stream_options":{"include_usage":true}}`)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatal(r.StatusCode, stream)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(f.calls[0].Body, &fields)
	if fields["stream"] != nil || fields["stream_options"] != nil {
		t.Fatal("stream asked from the provider", string(f.calls[0].Body))
	}
	ev := events(stream)
	if len(ev) != 4 || ev[3][1] != "[DONE]" {
		t.Fatal(stream)
	}
	var first, finish, usage struct {
		Object  string
		Model   string
		Created int
		Choices []struct {
			Index int
			Delta struct {
				Role      string
				ToolCalls []struct {
					Index    int
					ID       string
					Function struct{ Name, Arguments string }
				} `json:"tool_calls"`
			}
			FinishReason *string `json:"finish_reason"`
		}
		Usage *struct{ PromptTokens, CompletionTokens int } `json:"usage"`
	}
	_ = json.Unmarshal([]byte(ev[0][1]), &first)
	_ = json.Unmarshal([]byte(ev[1][1]), &finish)
	_ = json.Unmarshal([]byte(ev[2][1]), &usage)
	calls := first.Choices[0].Delta.ToolCalls
	if first.Object != "chat.completion.chunk" || first.Model != "gpt-4o" || first.Created != 7 || first.Choices[0].FinishReason != nil ||
		len(calls) != 2 || calls[1].Index != 1 || calls[0].Function.Arguments != `{"p":1}` || first.Choices[0].Delta.Role != "assistant" {
		t.Fatal(ev[0][1])
	}
	if finish.Choices[0].FinishReason == nil || *finish.Choices[0].FinishReason != "tool_calls" {
		t.Fatal(ev[1][1])
	}
	if len(usage.Choices) != 0 || usage.Usage == nil {
		t.Fatal(ev[2][1])
	}
}

// The Messages API stream: message_start, each block whole, message_delta with
// the stop reason and output tokens, message_stop.
func TestAnthropicStreamReplaysEachBlock(t *testing.T) {
	f := &forwarder{answer: `{"id":"m1","type":"message","role":"assistant","model":"x","content":[{"type":"thinking","thinking":"plan","signature":"sig"},{"type":"text","text":"Listing."},{"type":"tool_use","id":"tu","name":"bash","input":{"cmd":"ls -la"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":12,"cache_read_input_tokens":4,"output_tokens":30}}`}
	srv := endpoint(t, f, `{"version":1,"command":["/bin/agent"],"default_model":"smart"}`)
	r, stream := post(t, srv.URL+"/v1/messages", `{"model":"claude-whatever","max_tokens":100,"messages":[{"role":"user","content":"x"}],"stream":true}`)
	if r.StatusCode != 200 || f.calls[0].Alias != "smart" || f.calls[0].Dialect != "anthropic" {
		t.Fatal(r.StatusCode, stream)
	}
	ev := events(stream)
	var names []string
	for _, e := range ev {
		names = append(names, e[0])
	}
	want := "message_start content_block_start content_block_delta content_block_delta content_block_stop content_block_start content_block_delta content_block_stop content_block_start content_block_delta content_block_stop message_delta message_stop"
	if strings.Join(names, " ") != want {
		t.Fatal(strings.Join(names, " "))
	}
	var start struct {
		Message struct {
			Model   string
			Content []any
			Usage   map[string]int
		}
	}
	_ = json.Unmarshal([]byte(ev[0][1]), &start)
	if start.Message.Model != "claude-whatever" || len(start.Message.Content) != 0 || start.Message.Usage["input_tokens"] != 12 || start.Message.Usage["output_tokens"] != 0 {
		t.Fatal(ev[0][1])
	}
	var tool struct {
		Delta struct {
			Type        string
			PartialJSON string `json:"partial_json"`
		}
	}
	_ = json.Unmarshal([]byte(ev[9][1]), &tool)
	if tool.Delta.Type != "input_json_delta" || tool.Delta.PartialJSON != `{"cmd":"ls -la"}` {
		t.Fatal(ev[9][1])
	}
	var sig struct{ Delta map[string]string }
	_ = json.Unmarshal([]byte(ev[3][1]), &sig)
	if sig.Delta["type"] != "signature_delta" || sig.Delta["signature"] != "sig" {
		t.Fatal(ev[3][1])
	}
	var end struct {
		Delta map[string]any
		Usage map[string]int
	}
	_ = json.Unmarshal([]byte(ev[11][1]), &end)
	if end.Delta["stop_reason"] != "tool_use" || end.Usage["output_tokens"] != 30 {
		t.Fatal(ev[11][1])
	}
}

// Platform outcomes become the errors each SDK knows how to handle.
func TestPlatformOutcomesBecomeSDKErrors(t *testing.T) {
	f := &forwarder{}
	srv := endpoint(t, f, minimal)
	for code, status := range map[string]int{"not_found": 404, "dialect": 400, "invalid": 400, "quota_exceeded": 429, "rate_limited": 429,
		"rejected": 400, "outcome_unknown": 504, "unavailable": 503, "unauthorized": 403} {
		f.err = &capsuleprotocol.PlatformError{Code: code}
		r, body := post(t, srv.URL+"/v1/chat/completions", `{"model":"fast","messages":[]}`)
		var openai struct {
			Error struct{ Message, Type string }
		}
		if r.StatusCode != status || json.Unmarshal([]byte(body), &openai) != nil || openai.Error.Message == "" {
			t.Fatal(code, r.StatusCode, body)
		}
		r, body = post(t, srv.URL+"/v1/messages", `{"model":"fast","max_tokens":1,"messages":[]}`)
		var anthropic struct {
			Type  string
			Error struct{ Type, Message string }
		}
		if r.StatusCode != status || json.Unmarshal([]byte(body), &anthropic) != nil || anthropic.Type != "error" || anthropic.Error.Message == "" {
			t.Fatal(code, r.StatusCode, body)
		}
	}
	calls := len(f.calls)
	for _, c := range []struct{ path, body string }{
		{"/v1/chat/completions", `not json`},
		{"/v1/chat/completions", `{"messages":[]}`},
		{"/v1/chat/completions", `{"model":"has space","messages":[]}`},
		{"/v1/chat/completions", `{"model":"fast","x":"` + strings.Repeat("a", capsuleprotocol.MaxLLMForwardBytes) + `"}`},
		{"/v1/embeddings", `{"model":"fast"}`},
	} {
		if r, body := post(t, srv.URL+c.path, c.body); r.StatusCode < 400 {
			t.Fatal(c.path, r.StatusCode, body)
		}
	}
	if len(f.calls) != calls {
		t.Fatal("a refused request reached the platform")
	}
	r, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Data []struct{ ID string } }
	_ = json.NewDecoder(r.Body).Decode(&list)
	r.Body.Close()
	if len(list.Data) != 1 || list.Data[0].ID != "gpt-4o" {
		t.Fatal(list)
	}
}
