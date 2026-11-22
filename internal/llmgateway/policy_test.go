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

// recorder is a provider that keeps the last request's body and answers as
// the dialect's API does.
func recorder(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var calls atomic.Int32
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		if r.URL.Path == "/v1/messages" {
			_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":3,"output_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &body
}

func sentFields(t *testing.T, body *atomic.Value) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body.Load().(string)), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Provider-executed tools and cost-changing options are refused before
// anything is sent, in both dialects and on both entries, unless the alias's
// policy names them (S-11). A plain function or custom tool, and Anthropic's
// client tools without a type, always pass.
func TestServerToolsAndCostOptionsAreRefusedUnlessTheAliasAllowsThem(t *testing.T) {
	srv, calls, _ := recorder(t)
	g := fast(Config{})
	openai := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/o"}
	anthropic := Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "c", Secret: "s", Key: "t/a"}
	msg := `"messages":[{"role":"user","content":"hi"}]`
	denied := []struct {
		name, dialect, body string
		allow               RequestPolicy
	}{
		{"openai web search tool", DialectOpenAI, `{` + msg + `,"tools":[{"type":"web_search_preview"}]}`, RequestPolicy{AllowedToolTypes: []string{"web_search_preview"}}},
		{"openai file search", DialectOpenAI, `{` + msg + `,"tools":[{"type":"function","function":{"name":"f"}},{"type":"file_search"}]}`, RequestPolicy{AllowedToolTypes: []string{"file_search"}}},
		{"openai code interpreter", DialectOpenAI, `{` + msg + `,"tools":[{"type":"code_interpreter"}]}`, RequestPolicy{AllowedToolTypes: []string{"code_interpreter"}}},
		{"openai computer use", DialectOpenAI, `{` + msg + `,"tools":[{"type":"computer_use_preview"}]}`, RequestPolicy{AllowedToolTypes: []string{"computer_use_preview"}}},
		{"openai mcp", DialectOpenAI, `{` + msg + `,"tools":[{"type":"mcp","server_url":"https://mcp.example"}]}`, RequestPolicy{AllowedToolTypes: []string{"mcp"}}},
		{"openai tool without a type", DialectOpenAI, `{` + msg + `,"tools":[{"function":{"name":"f"}}]}`, RequestPolicy{}},
		{"openai web search options", DialectOpenAI, `{` + msg + `,"web_search_options":{}}`, RequestPolicy{AllowedFields: []string{"web_search_options"}}},
		{"openai priority tier", DialectOpenAI, `{` + msg + `,"service_tier":"priority"}`, RequestPolicy{AllowedFields: []string{"service_tier"}}},
		{"openai flex tier", DialectOpenAI, `{` + msg + `,"service_tier":"flex"}`, RequestPolicy{AllowedFields: []string{"service_tier"}}},
		{"openai stored completion", DialectOpenAI, `{` + msg + `,"store":true}`, RequestPolicy{AllowedFields: []string{"store"}}},
		{"openai background", DialectOpenAI, `{` + msg + `,"background":true}`, RequestPolicy{AllowedFields: []string{"background"}}},
		{"openai audio output", DialectOpenAI, `{` + msg + `,"modalities":["text","audio"],"audio":{"voice":"alloy","format":"wav"}}`, RequestPolicy{AllowedFields: []string{"audio", "modalities"}}},
		{"openai prediction", DialectOpenAI, `{` + msg + `,"prediction":{"type":"content","content":"x"}}`, RequestPolicy{AllowedFields: []string{"prediction"}}},
		{"openai vendor option", DialectOpenAI, `{` + msg + `,"top_k":5}`, RequestPolicy{AllowedFields: []string{"top_k"}}},
		{"anthropic web search", DialectAnthropic, `{"max_tokens":9,` + msg + `,"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":5}]}`, RequestPolicy{AllowedToolTypes: []string{"web_search_20250305"}}},
		{"anthropic web fetch", DialectAnthropic, `{"max_tokens":9,` + msg + `,"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`, RequestPolicy{AllowedToolTypes: []string{"web_fetch_20250910"}}},
		{"anthropic code execution", DialectAnthropic, `{"max_tokens":9,` + msg + `,"tools":[{"name":"bash","input_schema":{}},{"type":"code_execution_20250825","name":"code_execution"}]}`, RequestPolicy{AllowedToolTypes: []string{"code_execution_20250825"}}},
		{"anthropic computer use", DialectAnthropic, `{"max_tokens":9,` + msg + `,"tools":[{"type":"computer_20250124","name":"computer","display_width_px":1024,"display_height_px":768}]}`, RequestPolicy{AllowedToolTypes: []string{"computer_20250124"}}},
		{"anthropic mcp connector", DialectAnthropic, `{"max_tokens":9,` + msg + `,"mcp_servers":[{"type":"url","url":"https://mcp.example","name":"x"}]}`, RequestPolicy{AllowedFields: []string{"mcp_servers"}}},
		{"anthropic container", DialectAnthropic, `{"max_tokens":9,` + msg + `,"container":"container_1"}`, RequestPolicy{AllowedFields: []string{"container"}}},
		{"anthropic priority tier", DialectAnthropic, `{"max_tokens":9,` + msg + `,"service_tier":"priority"}`, RequestPolicy{AllowedFields: []string{"service_tier"}}},
		{"anthropic fallback models", DialectAnthropic, `{"max_tokens":9,` + msg + `,"fallbacks":[{"model":"other"}]}`, RequestPolicy{AllowedFields: []string{"fallbacks"}}},
		{"anthropic defined client tool", DialectAnthropic, `{"max_tokens":9,` + msg + `,"tools":[{"type":"bash_20250124","name":"bash"}]}`, RequestPolicy{AllowedToolTypes: []string{"bash_20250124"}}},
	}
	for _, tc := range denied {
		route := openai
		if tc.dialect == DialectAnthropic {
			route = anthropic
		}
		if _, err := g.Forward(t.Context(), route, tc.dialect, []byte(tc.body)); !errors.Is(err, ErrFeatureDenied) {
			t.Error(tc.name, "unary:", err)
		}
		if _, err := PlanForward(route.Policy, tc.dialect, []byte(tc.body), false); !errors.Is(err, ErrFeatureDenied) {
			t.Error(tc.name, "plan:", err)
		}
		stream := strings.Replace(tc.body, `{`, `{"stream":true,`, 1)
		if _, err := g.ForwardStream(t.Context(), route, tc.dialect, []byte(stream), func(Event) error { return nil }); !errors.Is(err, ErrFeatureDenied) {
			t.Error(tc.name, "stream:", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("a refused request reached the provider", calls.Load())
	}
	// Named by the alias's policy, the same requests go through.
	for _, tc := range denied {
		if tc.name == "openai tool without a type" {
			continue
		}
		route := openai
		if tc.dialect == DialectAnthropic {
			route = anthropic
		}
		route.Policy = tc.allow
		before := calls.Load()
		if _, err := g.Forward(t.Context(), route, tc.dialect, []byte(tc.body)); err != nil || calls.Load() != before+1 {
			t.Error(tc.name, "allowed by the policy but refused:", err)
		}
	}
	// Client tools and the plain options always pass.
	for _, c := range []struct{ dialect, body string }{
		{DialectOpenAI, `{` + msg + `,"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}},{"type":"custom","custom":{"name":"g"}}],"tool_choice":"auto",` +
			`"parallel_tool_calls":true,"temperature":0.2,"top_p":0.9,"stop":["x"],"seed":1,"response_format":{"type":"json_object"},"logprobs":true,"top_logprobs":2,` +
			`"frequency_penalty":0,"presence_penalty":0,"logit_bias":{},"user":"u","reasoning_effort":"low","functions":[{"name":"h"}],"function_call":"auto","n":1,"stream_options":null}`},
		{DialectAnthropic, `{"max_tokens":9,` + msg + `,"system":"be brief","tools":[{"name":"bash","input_schema":{}},{"type":"custom","name":"x","input_schema":{}}],` +
			`"tool_choice":{"type":"auto"},"temperature":0.2,"top_p":0.9,"top_k":5,"stop_sequences":["x"],"metadata":{"user_id":"u"},"thinking":{"type":"enabled","budget_tokens":1024},` +
			`"output_config":{"effort":"low"}}`},
	} {
		route := openai
		if c.dialect == DialectAnthropic {
			route = anthropic
		}
		before := calls.Load()
		if _, err := g.Forward(t.Context(), route, c.dialect, []byte(c.body)); err != nil || calls.Load() != before+1 {
			t.Error(c.dialect, "plain request refused:", err)
		}
	}
}

// A field the policy does not name passes only with a value that changes
// nothing: null is dropped, and a default value (store false, the automatic
// service tier) is forwarded as written.
func TestNeutralValuesOfDeniedFieldsPass(t *testing.T) {
	srv, _, body := recorder(t)
	g := fast(Config{})
	openai := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/o"}
	_, err := g.Forward(t.Context(), openai, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"store":false,"service_tier":"auto","metadata":null,"web_search_options":null}`))
	if err != nil {
		t.Fatal(err)
	}
	sent := sentFields(t, body)
	if string(sent["store"]) != "false" || string(sent["service_tier"]) != `"auto"` || sent["metadata"] != nil || sent["web_search_options"] != nil {
		t.Fatal("neutral values:", body.Load())
	}
	if _, ok := sent["metadata"]; ok {
		t.Fatal("a null denied field was forwarded:", body.Load())
	}
	anthropic := Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "c", Secret: "s", Key: "t/a"}
	if _, err = g.Forward(t.Context(), anthropic, DialectAnthropic, []byte(`{"max_tokens":9,"messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only"}`)); err != nil {
		t.Fatal(err)
	}
}

// A request that declares no output cap is held to one: the alias's maximum
// output, else the platform's default, written into the forwarded request in
// the field the alias names, and reserved (S-13).
func TestARequestWithoutAnOutputCapIsHeldToTheAliasMaximum(t *testing.T) {
	srv, _, body := recorder(t)
	g := fast(Config{})
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/o"}
	uncapped := []byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":null}`)
	for _, tc := range []struct {
		policy RequestPolicy
		field  string
		cap    int
	}{
		{RequestPolicy{}, "max_tokens", DefaultForwardOutput},
		{RequestPolicy{MaxOutputTokens: 32000}, "max_tokens", 32000},
		{RequestPolicy{MaxOutputTokens: 500, OutputCapField: "max_completion_tokens"}, "max_completion_tokens", 500},
	} {
		route.Policy = tc.policy
		plan, err := PlanForward(tc.policy, DialectOpenAI, uncapped, false)
		if err != nil || plan.Output != int64(tc.cap) {
			t.Fatal("plan", plan, err)
		}
		if _, err = g.Forward(t.Context(), route, DialectOpenAI, uncapped); err != nil {
			t.Fatal(err)
		}
		sent := sentFields(t, body)
		if string(sent[tc.field]) != strings.TrimSpace(string(mustJSON(tc.cap))) {
			t.Fatal("injected cap", body.Load())
		}
		if other := map[string]string{"max_tokens": "max_completion_tokens", "max_completion_tokens": "max_tokens"}[tc.field]; sent[other] != nil {
			t.Fatal("both caps sent", body.Load())
		}
	}
	// A declared cap is kept and reserved, even above the alias's maximum,
	// and written in the field the provider reads, whichever the agent's SDK
	// used: a server that reads max_tokens only (Ollama) would ignore a
	// max_completion_tokens.
	route.Policy = RequestPolicy{MaxOutputTokens: 100}
	declared := []byte(`{"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":300}`)
	if plan, err := PlanForward(route.Policy, DialectOpenAI, declared, false); err != nil || plan.Output != 300 {
		t.Fatal(plan, err)
	}
	if _, err := g.Forward(t.Context(), route, DialectOpenAI, declared); err != nil {
		t.Fatal(err)
	}
	if sent := sentFields(t, body); string(sent["max_tokens"]) != "300" || sent["max_completion_tokens"] != nil {
		t.Fatal("declared cap", body.Load())
	}
	route.Policy = RequestPolicy{OutputCapField: "max_completion_tokens"}
	if _, err := g.Forward(t.Context(), route, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":70}`)); err != nil {
		t.Fatal(err)
	}
	if sent := sentFields(t, body); string(sent["max_completion_tokens"]) != "70" || sent["max_tokens"] != nil {
		t.Fatal("declared cap in the other field", body.Load())
	}
	// Both declared: the reserved one is the one sent.
	both := []byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":9000,"max_completion_tokens":40}`)
	if plan, err := PlanForward(route.Policy, DialectOpenAI, both, false); err != nil || plan.Output != 40 {
		t.Fatal(plan, err)
	}
	if _, err := g.Forward(t.Context(), route, DialectOpenAI, both); err != nil {
		t.Fatal(err)
	}
	if sent := sentFields(t, body); string(sent["max_completion_tokens"]) != "40" || sent["max_tokens"] != nil {
		t.Fatal("both caps", body.Load())
	}
	// The unary text route is held the same way: its default is 1,024.
	ask := Request{Messages: []Message{{Role: "user", Content: "hi"}}}
	for _, tc := range []struct {
		policy RequestPolicy
		field  string
		cap    int
	}{
		{RequestPolicy{}, "max_tokens", DefaultCompleteOutput},
		{RequestPolicy{MaxOutputTokens: 700, OutputCapField: "max_completion_tokens"}, "max_completion_tokens", 700},
	} {
		route.Policy = tc.policy
		if CompleteOutputCap(tc.policy, ask) != tc.cap {
			t.Fatal("complete cap", CompleteOutputCap(tc.policy, ask))
		}
		if _, err := g.Complete(t.Context(), route, ask); err != nil {
			t.Fatal(err)
		}
		if sent := sentFields(t, body); string(sent[tc.field]) != strings.TrimSpace(string(mustJSON(tc.cap))) {
			t.Fatal("complete cap sent", body.Load())
		}
	}
	anthropic := Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "c", Secret: "s", Key: "t/a", Policy: RequestPolicy{MaxOutputTokens: 2048}}
	if _, err := g.Complete(t.Context(), anthropic, ask); err != nil {
		t.Fatal(err)
	}
	if sent := sentFields(t, body); string(sent["max_tokens"]) != "2048" {
		t.Fatal("anthropic complete cap", body.Load())
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Media the provider fetches itself make a small body with a large input: each
// image by URL or file and each document by URL or file reserves a fixed,
// conservative amount, beside the body's own estimate (S-13).
func TestMediaByReferenceAreEstimatedConservatively(t *testing.T) {
	text := []byte(`{"messages":[{"role":"user","content":"describe"}]}`)
	base, err := PlanForward(RequestPolicy{}, DialectOpenAI, text, false)
	if err != nil || base.Input != EstimateTokens(text) || base.Input < int64(len(text))/3 {
		t.Fatal(base, err)
	}
	for _, tc := range []struct {
		name, dialect, content string
		images, documents      int64
	}{
		{"openai image url", DialectOpenAI, `[{"type":"text","text":"x"},{"type":"image_url","image_url":{"url":"https://img.example/a.png"}}]`, 1, 0},
		{"openai image url as a string", DialectOpenAI, `[{"type":"image_url","image_url":"https://img.example/a.png"}]`, 1, 0},
		{"openai inline image", DialectOpenAI, `[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]`, 0, 0},
		{"openai uploaded file", DialectOpenAI, `[{"type":"file","file":{"file_id":"file-1"}}]`, 0, 1},
		{"openai inline file", DialectOpenAI, `[{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0="}}]`, 0, 0},
		{"anthropic image url", DialectAnthropic, `[{"type":"image","source":{"type":"url","url":"https://img.example/a.png"}}]`, 1, 0},
		{"anthropic image file", DialectAnthropic, `[{"type":"image","source":{"type":"file","file_id":"f"}}]`, 1, 0},
		{"anthropic inline image", DialectAnthropic, `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]`, 0, 0},
		{"anthropic pdf url", DialectAnthropic, `[{"type":"document","source":{"type":"url","url":"https://doc.example/a.pdf"}}]`, 0, 1},
		{"anthropic text document", DialectAnthropic, `[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"abc"}}]`, 0, 0},
		{"anthropic tool result with images", DialectAnthropic, `[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://a"}},{"type":"image","source":{"type":"url","url":"https://b"}}]}]`, 2, 0},
	} {
		body := []byte(`{"max_tokens":10,"messages":[{"role":"user","content":` + tc.content + `}]}`)
		plan, err := PlanForward(RequestPolicy{}, tc.dialect, body, false)
		want := EstimateTokens(body) + tc.images*ImageInputTokens + tc.documents*DocumentInputTokens
		if err != nil || plan.Input != want {
			t.Error(tc.name, plan.Input, "want", want, err)
		}
	}
	// Text in scripts other than ASCII counts each of its bytes as a token.
	if EstimateTokens([]byte("abcdef")) != 3 || EstimateTokens([]byte("日本")) != 7 {
		t.Fatal(EstimateTokens([]byte("abcdef")), EstimateTokens([]byte("日本")))
	}
}

// An answer that reports no usage, or only part of it, says so: the
// accounting then counts the reservation in place of what is missing, never
// zero (L-06).
func TestAnAnswerWithoutUsageSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name, dialect, answer string
		usage                 Usage
		missing               Unreported
	}{
		{"openai none", DialectOpenAI, `{"choices":[{"message":{"content":"ok"}}]}`, Usage{}, Unreported{Input: true, Output: true}},
		{"openai null", DialectOpenAI, `{"choices":[{"message":{"content":"ok"}}],"usage":null}`, Usage{}, Unreported{Input: true, Output: true}},
		{"openai output only", DialectOpenAI, `{"choices":[{"message":{"content":"ok"}}],"usage":{"completion_tokens":4}}`, Usage{OutputTokens: 4}, Unreported{Input: true}},
		{"openai both", DialectOpenAI, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":0,"completion_tokens":4}}`, Usage{OutputTokens: 4}, Unreported{}},
		{"anthropic none", DialectAnthropic, `{"content":[{"type":"text","text":"ok"}]}`, Usage{}, Unreported{Input: true, Output: true}},
		{"anthropic input only", DialectAnthropic, `{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":5,"cache_read_input_tokens":2}}`, Usage{InputTokens: 7}, Unreported{Output: true}},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.answer)) }))
		kind, body := "openai_compatible", forwardBody
		if tc.dialect == DialectAnthropic {
			kind = "anthropic"
		}
		route := Route{Kind: kind, BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/" + tc.name}
		out, err := fast(Config{}).Forward(t.Context(), route, tc.dialect, []byte(body))
		if err != nil || out.Usage != tc.usage || out.Unreported != tc.missing {
			t.Error(tc.name, "forward", out.Usage, out.Unreported, err)
		}
		res, err := fast(Config{}).Complete(t.Context(), route, ask)
		if err != nil || res.Usage != tc.usage || res.Unreported != tc.missing {
			t.Error(tc.name, "complete", res.Usage, res.Unreported, err)
		}
		srv.Close()
	}
}
