//go:build llmlive

package llmgateway

// Live provider streams (ADR 022), with the variables of live_test.go. The
// Anthropic API is the same server's (Ollama serves both):
// AGENTCAPSULE_TEST_LLM_ANTHROPIC_BASE_URL, by default the OpenAI base URL
// without its /v1.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func liveAnthropicRoute(t *testing.T) Route {
	t.Helper()
	r := liveRoute(t)
	r.Kind, r.Key = "anthropic", r.Key+"/anthropic"
	r.BaseURL = os.Getenv("AGENTCAPSULE_TEST_LLM_ANTHROPIC_BASE_URL")
	if r.BaseURL == "" {
		r.BaseURL = strings.TrimSuffix(strings.TrimRight(os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), "/"), "/v1")
	}
	return r
}

type liveDialect struct {
	dialect string
	route   Route
}

func liveDialects(t *testing.T) []liveDialect {
	return []liveDialect{{DialectOpenAI, liveRoute(t)}, {DialectAnthropic, liveAnthropicRoute(t)}}
}

func liveBody(stream bool) []byte {
	b, _ := json.Marshal(map[string]any{"model": "agent-alias", "max_tokens": 16, "temperature": 0, "stream": stream,
		"messages": []map[string]string{{"role": "user", "content": "Say hello in one short sentence."}}})
	return b
}

// Both of the server's APIs stream through ForwardStream: events relayed in
// order, the final usage read, and the same input count as the unary call.
func TestLiveStreamOfBothDialectsRelaysEventsAndUsage(t *testing.T) {
	for _, d := range liveDialects(t) {
		t.Run(d.dialect, func(t *testing.T) {
			g := live(Config{Timeout: 2 * time.Minute, MaxAttempts: 1})
			unary, err := g.Forward(t.Context(), d.route, d.dialect, liveBody(false))
			if err != nil {
				t.Fatal("unary call", err)
			}
			var names []string
			var last Event
			out, err := g.ForwardStream(t.Context(), d.route, d.dialect, liveBody(true), func(e Event) error {
				names, last = append(names, e.Name), e
				return nil
			})
			if err != nil || len(names) < 3 || out.FirstEvent <= 0 {
				t.Fatal("stream", err, len(names))
			}
			if out.Usage.InputTokens != unary.Usage.InputTokens || out.Usage.OutputTokens <= 0 || out.Usage.OutputTokens > 16 {
				t.Fatalf("stream usage %+v, unary %+v", out.Usage, unary.Usage)
			}
			switch d.dialect {
			case DialectOpenAI:
				if names[0] != "" || !strings.Contains(string(last.Data), `"usage"`) {
					t.Fatal("the last OpenAI event is not the usage chunk", string(last.Data))
				}
			case DialectAnthropic:
				if names[0] != "message_start" || names[len(names)-1] != "message_stop" || !strings.Contains(strings.Join(names, " "), "content_block_delta") {
					t.Fatal("Anthropic events", names)
				}
			}
			t.Logf("%s: %d events, first after %s, usage %+v (unary %+v)", d.dialect, len(names), out.FirstEvent, out.Usage, unary.Usage)
		})
	}
}

// CompleteStream gives the text in fragments with the usage, for both kinds
// of provider.
func TestLiveCompleteStreamOfBothKindsGivesTheText(t *testing.T) {
	for _, d := range liveDialects(t) {
		t.Run(d.route.Kind, func(t *testing.T) {
			var text []string
			out, err := live(Config{Timeout: 2 * time.Minute, MaxAttempts: 1}).CompleteStream(t.Context(), d.route, short(), func(s string) error {
				text = append(text, s)
				return nil
			})
			if err != nil || len(text) == 0 || out.Usage.InputTokens <= 0 || out.Usage.OutputTokens <= 0 || out.Usage.OutputTokens > 16 || out.FinishReason == "" {
				t.Fatal(err, len(text), out)
			}
			t.Logf("%s: %d fragments, %d bytes, usage %+v, finish %s, first event after %s", d.route.Kind, len(text), len(strings.Join(text, "")), out.Usage, out.FinishReason, out.FirstEvent)
		})
	}
}

// cutTransport breaks every answer's body after a few hundred bytes, as a
// network cut would, and counts the requests.
type cutTransport struct {
	countingTransport
	after int64
}

func (c *cutTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.countingTransport.RoundTrip(r)
	if err == nil {
		resp.Body = &cutBody{ReadCloser: resp.Body, left: c.after}
	}
	return resp, err
}

type cutBody struct {
	io.ReadCloser
	left int64
}

func (b *cutBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// A stream cut by the network, or by a client that leaves, after the first
// event has an unknown outcome and is never sent again.
func TestLiveStreamCutAfterItsFirstEventIsUnknownAndNotRetried(t *testing.T) {
	for _, d := range liveDialects(t) {
		t.Run(d.dialect, func(t *testing.T) {
			cut := &cutTransport{after: 400}
			g := NewForTests(Config{Timeout: 2 * time.Minute, MaxAttempts: 3}, TestOptions{Loopback: true,
				Transport: func(next http.RoundTripper) http.RoundTripper { cut.next = next; return cut }})
			events := 0
			_, err := g.ForwardStream(t.Context(), d.route, d.dialect, liveBody(true), func(Event) error { events++; return nil })
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errStreamCut) || events == 0 || cut.n.Load() != 1 {
				t.Fatal("a network cut", err, events, cut.n.Load())
			}
			sent := &countingTransport{}
			g = NewForTests(Config{Timeout: 2 * time.Minute, MaxAttempts: 3}, TestOptions{Loopback: true,
				Transport: func(next http.RoundTripper) http.RoundTripper { sent.next = next; return sent }})
			left := errors.New("the guest left")
			events = 0
			_, err = g.ForwardStream(t.Context(), d.route, d.dialect, liveBody(true), func(Event) error {
				if events++; events == 2 {
					return left
				}
				return nil
			})
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, left) || sent.n.Load() != 1 {
				t.Fatal("a client that left", err, sent.n.Load())
			}
		})
	}
}
