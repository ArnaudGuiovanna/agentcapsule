package llmgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writtenThenCut is a provider that reads each request in full, then closes
// the connection without answering: the request reached it, and it may have
// done (and billed) the work.
func writtenThenCut(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// A transport error once the request may have been written is an unknown
// outcome: never retried, never read as "nothing was accepted". This holds for
// every entry of the gateway, unary and stream.
func TestACutAfterTheRequestWasWrittenIsUnknownAndNeverRetried(t *testing.T) {
	srv, calls := writtenThenCut(t)
	g := fast(Config{MaxAttempts: 3})
	openai := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s", Key: "t/cut"}
	anthropic := Route{Kind: "anthropic", BaseURL: srv.URL, UpstreamModel: "c", Secret: "s", Key: "t/cut-a"}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"complete", func() error { _, err := g.Complete(t.Context(), openai, ask); return err }},
		{"complete-anthropic", func() error { _, err := g.Complete(t.Context(), anthropic, ask); return err }},
		{"forward", func() error { _, err := g.Forward(t.Context(), openai, DialectOpenAI, []byte(forwardBody)); return err }},
		{"embed", func() error { _, err := g.Embed(t.Context(), openai, EmbedRequest{Input: []string{"x"}}); return err }},
		{"forward-stream", func() error {
			_, err := g.ForwardStream(t.Context(), openai, DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil })
			return err
		}},
		{"complete-stream", func() error {
			_, err := g.CompleteStream(t.Context(), anthropic, ask, func(string) error { return nil })
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls.Load()
			if err := tc.call(); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("a cut after writing is not an unknown outcome:", err)
			}
			if n := calls.Load() - before; n != 1 {
				t.Fatal("the request was sent", n, "times")
			}
		})
	}
}

// Before a connection exists nothing can have been written: a name that does
// not resolve, a refused connection or a failed TLS handshake is retried and
// stays ErrUnavailable, the outcome the accounting releases.
func TestFailuresBeforeAConnectionAreRetriedAsNothingSent(t *testing.T) {
	_, port, calls := mockProvider(t, false)
	// DNS fails once, then answers.
	var lookups atomic.Int32
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return nil, &net.DNSError{Err: "temporary failure", Name: host, IsTemporary: true}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	g := fastWith(Config{MaxAttempts: 2}, TestOptions{Loopback: true, Lookup: lookup})
	out, err := g.Complete(t.Context(), openAIRoute("http://provider.test:"+port), ask)
	if err != nil || out.Text != "hello" || calls.Load() != 1 || lookups.Load() != 2 {
		t.Fatal("a DNS failure was not retried as nothing sent:", err, calls.Load(), lookups.Load())
	}
	// A port nobody listens on: both attempts dial, nothing is sent.
	closed := httptest.NewServer(http.NotFoundHandler())
	gone := closed.URL
	closed.Close()
	var dials atomic.Int32
	counting := fastWith(Config{MaxAttempts: 2}, TestOptions{Loopback: true, Transport: func(rt http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) { dials.Add(1); return rt.RoundTrip(r) })
	}})
	if _, err = counting.Complete(t.Context(), openAIRoute(gone), ask); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrOutcomeUnknown) || dials.Load() != 2 {
		t.Fatal("a refused connection:", err, dials.Load())
	}
	stream := func(base string) error {
		_, err := counting.ForwardStream(t.Context(), openAIRoute(base), DialectOpenAI, []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`), func(Event) error { return nil })
		return err
	}
	dials.Store(0)
	if err = stream(gone); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrOutcomeUnknown) || dials.Load() != 2 {
		t.Fatal("a stream to a refused connection:", err, dials.Load())
	}
	// A TLS server whose certificate the gateway does not trust: the
	// handshake fails before any byte of the request.
	secure, _, secureCalls := mockProvider(t, true)
	dials.Store(0)
	if _, err = counting.Complete(t.Context(), openAIRoute(secure.URL), ask); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrOutcomeUnknown) || dials.Load() != 2 || secureCalls.Load() != 0 {
		t.Fatal("a failed TLS handshake:", err, dials.Load(), secureCalls.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The gateway keeps enough idle connections per provider for concurrent
// calls to reuse them (P-12): a second burst opens no new connection.
func TestTheGatewayKeepsIdleConnectionsPerProvider(t *testing.T) {
	var kept int
	g := fastWith(Config{}, TestOptions{Loopback: true, Transport: func(rt http.RoundTripper) http.RoundTripper {
		kept = rt.(*http.Transport).MaxIdleConnsPerHost
		return rt
	}})
	if kept != DefaultMaxIdleConnsPerHost || DefaultMaxIdleConnsPerHost < 16 {
		t.Fatal("idle connections per host:", kept)
	}
	fastWith(Config{MaxIdleConnsPerHost: 7}, TestOptions{Loopback: true, Transport: func(rt http.RoundTripper) http.RoundTripper {
		kept = rt.(*http.Transport).MaxIdleConnsPerHost
		return rt
	}})
	if kept != 7 {
		t.Fatal("configured idle connections per host:", kept)
	}
	const burst = 10
	var opened atomic.Int32
	arrived := make(chan struct{}, burst)
	var gate atomic.Pointer[chan struct{}]
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-*gate.Load()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	route := openAIRoute(srv.URL)
	// Each burst holds its calls until all of them reached the provider, so
	// that each needs its own connection.
	run := func() {
		open := make(chan struct{})
		gate.Store(&open)
		var wg sync.WaitGroup
		for range burst {
			wg.Go(func() {
				if _, err := g.Complete(context.Background(), route, ask); err != nil {
					t.Error(err)
				}
			})
		}
		for range burst {
			<-arrived
		}
		close(open)
		wg.Wait()
	}
	run()
	first := opened.Load()
	time.Sleep(200 * time.Millisecond) // the transport puts the connections back
	run()
	if first != burst || opened.Load()-first > 2 {
		t.Fatal("connections opened:", first, "then", opened.Load()-first)
	}
}
