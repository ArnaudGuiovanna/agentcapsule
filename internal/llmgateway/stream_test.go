package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// provider is a fake model server that answers with an event stream, written
// and flushed block by block.
type provider struct {
	*httptest.Server
	calls atomic.Int32
	body  atomic.Value // the last request's body
}

func streamProvider(t *testing.T, serve func(n int32, w http.ResponseWriter, r *http.Request, send func(...string))) *provider {
	t.Helper()
	p := &provider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := p.calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		p.body.Store(string(b))
		send := func(blocks ...string) {
			for _, b := range blocks {
				_, _ = io.WriteString(w, b)
				w.(http.Flusher).Flush()
			}
		}
		serve(n, w, r, send)
	}))
	t.Cleanup(p.Close)
	return p
}

// sent decodes the last request the provider received.
func (p *provider) sent(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(p.body.Load().(string)), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func eventStream(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

// cut breaks the connection in the middle of the answer.
func cut() { panic(http.ErrAbortHandler) }

var openAIStream = []string{
	`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"},"finish_reason":null}],"usage":null}` + "\n\n",
	": keep-alive\n\n",
	`data: {"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}],"usage":null}` + "\n\n",
	`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}` + "\n\n",
	`data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}` + "\n\n",
	"data: [DONE]\n\n",
}

var anthropicStream = []string{
	"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]," +
		"\"usage\":{\"input_tokens\":20,\"cache_creation_input_tokens\":100,\"cache_read_input_tokens\":7,\"output_tokens\":1}}}\n\n",
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
	"event: ping\ndata: {\"type\": \"ping\"}\n\n",
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Bon\"}}\n\n",
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"jour\"}}\n\n",
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":15}}\n\n",
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
}

// events splits stream blocks into the events a sink must receive.
func events(t *testing.T, blocks []string) []Event {
	t.Helper()
	var out []Event
	r := newSSEReader(strings.NewReader(strings.Join(blocks, "")), func() {})
	for {
		name, data, err := r.next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "[DONE]" {
			out = append(out, Event{Name: name, Data: data})
		}
	}
}

func collect(got *[]Event) func(Event) error {
	return func(e Event) error { *got = append(*got, e); return nil }
}

func sameEvents(t *testing.T, got, want []Event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d events relayed, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Fatalf("event %d: %s %s, want %s %s", i, got[i].Name, got[i].Data, want[i].Name, want[i].Data)
		}
	}
}

var streamRoute = Route{Kind: "openai_compatible", UpstreamModel: "m-up", Secret: "sk-test", Key: "t/fast"} // gitleaks:allow test fixture, not a credential

func routeTo(base string, r Route) Route { r.BaseURL = base; return r }

// ForwardStream asks the provider for a stream with its final usage, relays
// each event exactly as the provider sent it, in order, and reads the usage
// of the last chunk. OpenAI's [DONE] ends the stream and is not relayed.
func TestForwardStreamRelaysOpenAIEventsAndTheFinalUsage(t *testing.T) {
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, r *http.Request, send func(...string)) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		eventStream(w)
		send(openAIStream...)
	})
	var got []Event
	body := []byte(`{"model":"fast","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":false},"max_tokens":20,"tools":[]}`)
	out, err := fast(Config{}).ForwardStream(t.Context(), routeTo(p.URL+"/v1", streamRoute), DialectOpenAI, body, collect(&got))
	if err != nil || out.Usage != (Usage{InputTokens: 12, OutputTokens: 5}) || out.FirstEvent <= 0 {
		t.Fatal(out, err)
	}
	sameEvents(t, got, events(t, openAIStream))
	sent := p.sent(t)
	if string(sent["model"]) != `"m-up"` || string(sent["stream"]) != "true" || string(sent["stream_options"]) != `{"include_usage":true}` ||
		string(sent["tools"]) != "[]" || string(sent["max_tokens"]) != "20" {
		t.Fatal("upstream request", p.body.Load())
	}
}

// Anthropic: the input is message_start's, cache tokens included; each
// message_delta replaces the output, and the input fields it carries. ping is
// relayed like any event. The stream ends at message_stop.
func TestForwardStreamRelaysAnthropicEventsAndCountsCachedInput(t *testing.T) {
	ollama := slicesReplace(anthropicStream, 6, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},"+
		"\"usage\":{\"input_tokens\":1,\"cache_read_input_tokens\":37,\"output_tokens\":8}}\n\n")
	for _, tc := range []struct {
		name   string
		stream []string
		usage  Usage
	}{
		{"anthropic", anthropicStream, Usage{InputTokens: 127, OutputTokens: 15}},
		// Ollama's answer carries the input in message_delta: 1 + 100 + 37.
		{"delta-input", ollama, Usage{InputTokens: 138, OutputTokens: 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := streamProvider(t, func(_ int32, w http.ResponseWriter, r *http.Request, send func(...string)) {
				if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "sk-ant" || r.Header.Get("anthropic-version") == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				eventStream(w)
				send(tc.stream...)
			})
			var got []Event
			route := Route{Kind: "anthropic", BaseURL: p.URL, UpstreamModel: "c-up", Secret: "sk-ant", Key: "t/a"} // gitleaks:allow test fixture, not a credential
			body := []byte(`{"model":"claude","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"stream":true}`)
			out, err := fast(Config{}).ForwardStream(t.Context(), route, DialectAnthropic, body, collect(&got))
			if err != nil || out.Usage != tc.usage {
				t.Fatal(out, err)
			}
			sameEvents(t, got, events(t, tc.stream))
			sent := p.sent(t)
			if string(sent["model"]) != `"c-up"` || string(sent["stream"]) != "true" || sent["stream_options"] != nil {
				t.Fatal("upstream request", p.body.Load())
			}
		})
	}
}

func slicesReplace(s []string, i int, v string) []string {
	out := append([]string(nil), s...)
	out[i] = v
	return out
}

// The stream route takes a stream request only, with every other check of
// Forward; nothing reaches the provider otherwise.
func TestForwardStreamAcceptsOnlyAStreamRequest(t *testing.T) {
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) {
		eventStream(w)
		send(openAIStream...)
	})
	route := routeTo(p.URL, streamRoute)
	g := fast(Config{})
	for _, body := range []string{
		`{"messages":[{"role":"user","content":"hi"}]}`,
		`{"messages":[{"role":"user","content":"hi"}],"stream":false}`,
		`{"messages":[{"role":"user","content":"hi"}],"stream":null}`,
		`{"messages":[{"role":"user","content":"hi"}],"stream":"true"}`,
		`{"messages":[{"role":"user","content":"hi"}],"stream":true,"n":2}`,
		`{"messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":0}`,
		`{"messages":[],"stream":true}`,
	} {
		if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, []byte(body), func(Event) error { return nil }); !errors.Is(err, ErrInvalid) {
			t.Fatal(body, err)
		}
		if _, err := ForwardStreamOutputCap(DialectOpenAI, []byte(body)); !errors.Is(err, ErrInvalid) {
			t.Fatal("output cap of", body, err)
		}
	}
	anthropic := Route{Kind: "anthropic", BaseURL: p.URL, UpstreamModel: "c", Secret: "s", Key: "k"}
	if _, err := g.ForwardStream(t.Context(), anthropic, DialectAnthropic, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("anthropic without max_tokens", err)
	}
	if _, err := g.ForwardStream(t.Context(), anthropic, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil }); !errors.Is(err, ErrDialect) {
		t.Fatal("dialect", err)
	}
	if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("no sink", err)
	}
	if max, err := ForwardStreamOutputCap(DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true,"max_completion_tokens":30}`)); err != nil || max != 30 {
		t.Fatal("output cap", max, err)
	}
	if p.calls.Load() != 0 {
		t.Fatal("a refused request reached the provider")
	}
}

// CompleteStream relays the text only, in fragments, and returns the usage
// and the finish reason, for both kinds of provider.
func TestCompleteStreamRelaysTheTextOfBothKinds(t *testing.T) {
	for _, tc := range []struct {
		kind, path, text, finish string
		stream                   []string
		usage                    Usage
	}{
		{"openai_compatible", "/chat/completions", "Hello", "stop", openAIStream, Usage{12, 5}},
		{"anthropic", "/v1/messages", "Bonjour", "end_turn", anthropicStream, Usage{127, 15}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			p := streamProvider(t, func(_ int32, w http.ResponseWriter, r *http.Request, send func(...string)) {
				if r.URL.Path != tc.path {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				eventStream(w)
				send(tc.stream...)
			})
			var text []string
			route := Route{Kind: tc.kind, BaseURL: p.URL, UpstreamModel: "m", Secret: "s", Key: "k"}
			out, err := fast(Config{}).CompleteStream(t.Context(), route, ask, func(s string) error { text = append(text, s); return nil })
			if err != nil || strings.Join(text, "") != tc.text || len(text) != 2 || out.Usage != tc.usage || out.FinishReason != tc.finish || out.FirstEvent <= 0 {
				t.Fatal(text, out, err)
			}
			sent := p.sent(t)
			if string(sent["stream"]) != "true" || (tc.kind == "openai_compatible") != (string(sent["stream_options"]) == `{"include_usage":true}`) {
				t.Fatal("upstream request", p.body.Load())
			}
		})
	}
}

// A fragment of text is at most MaxStreamText bytes, split between two
// characters, so that its frame on the channel stays far below 64 KiB even
// with every character escaped.
func TestCompleteStreamSplitsLongFragmentsBetweenCharacters(t *testing.T) {
	long := strings.Repeat("é<", 6000) // 18,000 bytes, 48,000 once escaped
	chunk, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]string{"content": long}}}})
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) {
		eventStream(w)
		send("data: "+string(chunk)+"\n\n", openAIStream[4], openAIStream[5])
	})
	var parts []string
	_, err := fast(Config{}).CompleteStream(t.Context(), routeTo(p.URL, streamRoute), ask, func(s string) error { parts = append(parts, s); return nil })
	if err != nil || strings.Join(parts, "") != long || len(parts) < 3 {
		t.Fatal(len(parts), err)
	}
	for _, s := range parts {
		if len(s) == 0 || len(s) > MaxStreamText || !utf8.ValidString(s) {
			t.Fatal("fragment", len(s), utf8.ValidString(s))
		}
	}
}

// After the provider's first byte nothing is retried: a cut, a stream that
// ends without its final usage, a stream too big, an event that is not a JSON
// object, a provider's error event or an answer that is not a stream has an
// unknown outcome. The call is never sent twice.
func TestAStreamCutAfterTheFirstByteIsUnknownAndNeverRetried(t *testing.T) {
	head := openAIStream[:3]
	for _, tc := range []struct {
		name  string
		kind  string
		cfg   Config
		serve func(w http.ResponseWriter, send func(...string))
		want  error
	}{
		{"cut", "", Config{}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send(head...); cut() }, nil},
		{"ended", "", Config{}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send(head...) }, errStreamEnded},
		{"no-usage", "", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(openAIStream[0], openAIStream[2], openAIStream[3], openAIStream[5])
		}, errStreamUsage},
		{"anthropic-no-usage", "anthropic", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(anthropicStream[0], anthropicStream[3], anthropicStream[7])
		}, errStreamUsage},
		{"anthropic-error", "anthropic", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(anthropicStream[0], "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n")
		}, errStreamProvider},
		{"openai-error", "", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(head[0], `data: {"error":{"message":"server error","type":"server_error"}}`+"\n\n")
		}, errStreamProvider},
		{"too-big", "", Config{MaxResponse: 400}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send(openAIStream...) }, errStreamSize},
		{"not-json", "", Config{}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send(head[0], "data: hello\n\n") }, errStreamEvent},
		{"not-object", "", Config{}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send(head[0], "data: [1,2]\n\n") }, errStreamEvent},
		{"invalid-utf8", "", Config{}, func(w http.ResponseWriter, send func(...string)) { eventStream(w); send("data: {\"a\":\"\xff\"}\n\n") }, errStreamEvent},
		{"anthropic-done", "anthropic", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(anthropicStream[0], "data: [DONE]\n\n")
		}, errStreamEvent},
		{"long-line", "", Config{}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(head[0], ":"+strings.Repeat("x", maxSSELine)+"\n")
		}, errSSELine},
		{"not-a-stream", "", Config{}, func(w http.ResponseWriter, _ func(...string)) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
		}, errStreamType},
		{"idle", "", Config{StreamIdle: 100 * time.Millisecond}, func(w http.ResponseWriter, send func(...string)) {
			eventStream(w)
			send(head[0])
			time.Sleep(time.Second)
		}, errStreamIdle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) { tc.serve(w, send) })
			cfg := tc.cfg
			cfg.MaxAttempts = 3
			g := fast(cfg)
			var got []Event
			var err error
			if tc.kind == "anthropic" {
				_, err = g.ForwardStream(t.Context(), Route{Kind: "anthropic", BaseURL: p.URL, UpstreamModel: "c", Secret: "s", Key: "k"}, DialectAnthropic,
					[]byte(`{"max_tokens":9,"messages":[{"role":"user","content":"hi"}],"stream":true}`), collect(&got))
			} else {
				_, err = g.ForwardStream(t.Context(), routeTo(p.URL, streamRoute), DialectOpenAI,
					[]byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), collect(&got))
			}
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errStreamCut) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatal("not an unknown outcome:", err)
			}
			if n := p.calls.Load(); n != 1 {
				t.Fatal("a stream was sent again", n)
			}
			for _, e := range got {
				var v struct{ Type string }
				if json.Unmarshal(e.Data, &v) != nil || v.Type == "error" || v.Type == "message_stop" || bytes.Contains(e.Data, []byte(`"error"`)) {
					t.Fatalf("relayed %s", e.Data)
				}
			}
		})
	}
}

// Before the provider's first byte, retries are those of a call: a 429 or a
// 5xx is retried, another 4xx is a refusal, and a provider that never answers
// within the first byte's bound has an unknown outcome, not retried.
func TestAStreamRetriesOnlyBeforeTheFirstByte(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  int
		cfg    Config
		want   error
		calls  int32
		events int
	}{
		{"429", http.StatusTooManyRequests, Config{MaxAttempts: 2}, nil, 2, 4},
		{"503", http.StatusServiceUnavailable, Config{MaxAttempts: 2}, nil, 2, 4},
		{"429-twice", http.StatusTooManyRequests, Config{MaxAttempts: 1}, ErrRateLimited, 1, 0},
		{"401", http.StatusUnauthorized, Config{MaxAttempts: 3}, ErrRejected, 1, 0},
		{"redirect", http.StatusFound, Config{MaxAttempts: 3}, ErrRejected, 1, 0},
		{"first-byte", 0, Config{MaxAttempts: 3, StreamFirstByte: 100 * time.Millisecond}, ErrOutcomeUnknown, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := streamProvider(t, func(n int32, w http.ResponseWriter, r *http.Request, send func(...string)) {
				switch {
				case tc.first == 0:
					select {
					case <-r.Context().Done():
					case <-time.After(5 * time.Second):
					}
				case n == 1:
					w.Header().Set("Location", "http://127.0.0.1:1/")
					w.WriteHeader(tc.first)
				default:
					eventStream(w)
					send(openAIStream...)
				}
			})
			var got []Event
			_, err := fast(tc.cfg).ForwardStream(t.Context(), routeTo(p.URL, streamRoute), DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), collect(&got))
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) || errors.Is(err, errStreamCut) {
				t.Fatal(err)
			}
			if p.calls.Load() != tc.calls || len(got) != tc.events {
				t.Fatal("calls", p.calls.Load(), "events", len(got))
			}
		})
	}
}

// Comment lines keep a stream alive; the stream's total bound still holds.
func TestAStreamKeptAliveByCommentsStopsAtItsTotalBound(t *testing.T) {
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, r *http.Request, send func(...string)) {
		eventStream(w)
		send(openAIStream[0])
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Millisecond):
				send(": keep-alive\n")
			}
		}
	})
	start := time.Now()
	_, err := fast(Config{StreamIdle: 150 * time.Millisecond, StreamTotal: 600 * time.Millisecond}).ForwardStream(t.Context(), routeTo(p.URL, streamRoute), DialectOpenAI,
		[]byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil })
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errStreamTotal) || time.Since(start) < 500*time.Millisecond {
		t.Fatal(err, time.Since(start))
	}
}

// A sink that fails cancels the provider call: the outcome is unknown, and
// the provider is not at fault.
func TestASinkErrorCutsTheStreamWithoutBlamingTheProvider(t *testing.T) {
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) {
		eventStream(w)
		send(openAIStream...)
	})
	g := fast(Config{FailureLimit: 1})
	route := routeTo(p.URL, streamRoute)
	gone := errors.New("the guest left")
	n := 0
	_, err := g.ForwardStream(t.Context(), route, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error {
		if n++; n == 2 {
			return gone
		}
		return nil
	})
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, gone) || n != 2 {
		t.Fatal(err, n)
	}
	if _, err = g.ForwardStream(t.Context(), route, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil }); err != nil {
		t.Fatal("a sink error opened the breaker", err)
	}
}

// The breaker records a stream's success only at its end, and a cut as a
// failure: a half-open probe holds the breaker for its whole stream.
func TestTheBreakerJudgesAStreamAtItsEnd(t *testing.T) {
	var mode atomic.Int32 // 0 cut, 1 nominal, 2 held mid-stream
	held := make(chan struct{})
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) {
		eventStream(w)
		switch mode.Load() {
		case 0:
			send(openAIStream[0])
			cut()
		case 2:
			send(openAIStream[0])
			<-held
		}
		send(openAIStream...)
	})
	now := time.Unix(1000, 0)
	g := fast(Config{FailureLimit: 1, OpenFor: time.Minute, Now: func() time.Time { return now }})
	route := routeTo(p.URL, streamRoute)
	body := []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, body, func(Event) error { return nil }); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	mode.Store(1)
	if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, body, func(Event) error { return nil }); !errors.Is(err, ErrUnavailable) || p.calls.Load() != 1 {
		t.Fatal("a cut did not open the breaker", err)
	}
	now = now.Add(2 * time.Minute)
	mode.Store(2)
	first := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		once := false
		_, err := g.ForwardStream(context.Background(), route, DialectOpenAI, body, func(Event) error {
			if !once {
				once = true
				close(first)
			}
			return nil
		})
		done <- err
	}()
	<-first
	if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, body, func(Event) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a second call passed while the probe streamed", err)
	}
	close(held)
	if err := <-done; err != nil {
		t.Fatal("probe", err)
	}
	mode.Store(1)
	if _, err := g.ForwardStream(t.Context(), route, DialectOpenAI, body, func(Event) error { return nil }); err != nil {
		t.Fatal("the probe's success did not close the breaker", err)
	}
}

// A stream's span says it is one, and a cut after the first byte is
// stream_cut. No event reaches the span.
func TestStreamSpansCarryTheModeAndTheCutWithoutContent(t *testing.T) {
	var mode atomic.Int32
	p := streamProvider(t, func(_ int32, w http.ResponseWriter, _ *http.Request, send func(...string)) {
		eventStream(w)
		send(openAIStream[0])
		if mode.Load() == 1 {
			cut()
		}
		send(openAIStream[1:]...)
	})
	var sink spanSink
	tracer, err := telemetry.NewTracer(&sink, "agentcapsule-worker", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithTracer(context.Background(), tracer)
	route := routeTo(p.URL, streamRoute)
	if _, err = fast(Config{}).CompleteStream(ctx, route, ask, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	mode.Store(1)
	if _, err = fast(Config{}).ForwardStream(ctx, route, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"planted"}],"stream":true}`), func(Event) error { return nil }); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if _, err = fast(Config{}).Complete(ctx, route, ask); err == nil {
		t.Fatal("a stream answered a unary call")
	}
	tracer.Close()
	out := sink.b.String()
	for _, planted := range []string{"Hel", "planted", "sk-test", "m-up"} {
		if strings.Contains(out, planted) {
			t.Fatalf("%q reached a span", planted)
		}
	}
	for _, want := range []string{`{"key":"agentcapsule.llm.mode","value":{"stringValue":"stream"}}`, `{"key":"agentcapsule.llm.mode","value":{"stringValue":"unary"}}`,
		`{"key":"agentcapsule.outcome","value":{"stringValue":"stream_cut"}}`, `{"key":"agentcapsule.llm.output_tokens","value":{"intValue":"5"}}`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in\n%s", want, out)
		}
	}
}
