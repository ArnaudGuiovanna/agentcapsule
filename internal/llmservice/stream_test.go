package llmservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// Fake provider streams, OpenAI and Anthropic.
var (
	openAIChunks = []string{
		`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"},"finish_reason":null}],"usage":null}` + "\n\n",
		`data: {"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}],"usage":null}` + "\n\n",
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}` + "\n\n",
		`data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}` + "\n\n",
		"data: [DONE]\n\n",
	}
	anthropicEvents = []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]," +
			"\"usage\":{\"input_tokens\":20,\"cache_creation_input_tokens\":100,\"cache_read_input_tokens\":7,\"output_tokens\":1}}}\n\n",
		"event: ping\ndata: {\"type\":\"ping\"}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Bonjour\"}}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
)

// streamLab is an agent with a placement, two aliases (fast: OpenAI, claude:
// Anthropic) on a fake provider whose answer each test chooses, and the
// metered service.
type streamLab struct {
	*tenantLab
	owner  Principal
	caller VMCaller
	svc    *Service
	calls  atomic.Int32
	mode   atomic.Value // the provider's answer, see serve
	held   chan struct{}
	resume func() // ends a held stream; once, also at the test's end
	seen   *firstEvents
}

type firstEvents struct {
	mu     sync.Mutex
	events []CallEvent
	first  []time.Duration
}

func (f *firstEvents) ObserveLLM(e CallEvent) {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
}
func (f *firstEvents) ObserveFirstEvent(d time.Duration) {
	f.mu.Lock()
	f.first = append(f.first, d)
	f.mu.Unlock()
}

func newStreamLab(t *testing.T, attempts int) *streamLab {
	t.Helper()
	l, c, owner := agentLab(t)
	s := &streamLab{tenantLab: l, owner: owner, held: make(chan struct{}), seen: &firstEvents{}}
	s.resume = sync.OnceFunc(func() { close(s.held) })
	s.mode.Store("nominal")
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(s.resume) // before srv.Close, which waits for a held stream
	for _, p := range []struct{ key, kind, alias, base string }{
		{"sp-openai", "openai_compatible", "fast", srv.URL + "/v1"},
		{"sp-anthropic", "anthropic", "claude", srv.URL},
	} {
		r, err := l.a.CreateLLMProvider(t.Context(), owner, p.key, CreateLLMProviderInput{Name: p.key, Kind: p.kind, BaseURL: "https://llm.example.org", Secret: providerSecret})
		var v LLMProvider
		if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
			t.Fatal("create provider", err)
		}
		if _, err = l.db.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1 WHERE id=$2`, p.base, v.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = l.a.CreateLLMAlias(t.Context(), owner, "alias-"+p.alias, CreateLLMAliasInput{Alias: p.alias, ProviderID: v.ID, UpstreamModel: "up-" + p.alias,
			InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
			t.Fatal(err)
		}
	}
	agent := activateTenantAgent(t, l, c, owner, "stream-agent")
	if err := l.s.RegisterPlacement(t.Context(), agent, "local"); err != nil {
		t.Log("placement already registered:", err)
	}
	pl, err := l.s.ClaimPlacement(t.Context(), agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", pl.Generation)
	if err = l.s.ConfirmPlacement(t.Context(), agent, "local", "worker", pl.Generation, vm); err != nil {
		t.Fatal(err)
	}
	s.caller = VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: pl.Generation}
	g := llmgateway.NewForTests(llmgateway.Config{MaxAttempts: attempts, Backoff: time.Millisecond, MaxResponse: 4096, StreamIdle: 2 * time.Second}, llmgateway.TestOptions{Loopback: true})
	if s.svc, err = New(l.a, g); err != nil {
		t.Fatal(err)
	}
	s.svc.Observe(s.seen)
	return s
}

// serve answers as the lab's mode says: nominal, cut (in the middle),
// cut-early (before any event), no-usage, too-big, 429, 429-once (then
// nominal), held (one event, then the rest once held is closed).
func (s *streamLab) serve(w http.ResponseWriter, r *http.Request) {
	n := s.calls.Add(1)
	_, _ = io.Copy(io.Discard, r.Body)
	stream := openAIChunks
	if r.URL.Path == "/v1/messages" {
		stream = anthropicEvents
	}
	send := func(blocks ...string) {
		for _, b := range blocks {
			_, _ = io.WriteString(w, b)
			w.(http.Flusher).Flush()
		}
	}
	mode := s.mode.Load().(string)
	switch {
	case mode == "429" || mode == "429-once" && n%2 == 1:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	switch mode {
	case "cut":
		send(stream[:2]...)
		panic(http.ErrAbortHandler)
	case "cut-early":
		send(": opening\n\n")
		panic(http.ErrAbortHandler)
	case "no-usage":
		send(stream[0], stream[1], stream[len(stream)-1])
	case "too-big":
		for range 64 {
			send(stream[1])
		}
	case "held":
		send(stream[0])
		<-s.held
		send(stream[1:]...)
	default:
		send(stream...)
	}
}

func (s *streamLab) usage(t *testing.T, key string) (id, state string, in, out *int64) {
	t.Helper()
	if err := s.db.QueryRow(t.Context(), `SELECT id,state,input_tokens,output_tokens FROM llm_usage WHERE agent_id=$1 AND request_key=$2`,
		s.caller.AgentID, key).Scan(&id, &state, &in, &out); err != nil {
		t.Fatal(key, err)
	}
	return id, state, in, out
}

func (s *streamLab) forward(t *testing.T, key, alias string, sink func(llmgateway.Event) error) (StreamEnd, error) {
	t.Helper()
	dialect, body := "openai", `{"model":"fast","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":32}`
	if alias == "claude" {
		dialect, body = "anthropic", `{"model":"claude","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":32}`
	}
	return s.svc.ForwardStreamFromVM(t.Context(), s.caller, key, alias, dialect, []byte(body), nil, sink)
}

func relay(got *[]string) func(llmgateway.Event) error {
	return func(e llmgateway.Event) error { *got = append(*got, e.Name+" "+string(e.Data)); return nil }
}

// A nominal stream is relayed event by event and settled at the exact usage
// the provider reported, for both dialects; its key is never sent again.
func TestAModelStreamSettlesTheExactUsage(t *testing.T) {
	s := newStreamLab(t, 1)
	for _, tc := range []struct {
		alias  string
		events int
		usage  llmgateway.Usage
	}{
		{"fast", 4, llmgateway.Usage{InputTokens: 12, OutputTokens: 5}},
		{"claude", 5, llmgateway.Usage{InputTokens: 127, OutputTokens: 15}},
	} {
		var got []string
		key := "nominal-" + tc.alias
		end, err := s.forward(t, key, tc.alias, relay(&got))
		if err != nil || end.Outcome != StreamCompleted || end.Usage != tc.usage || len(got) != tc.events {
			t.Fatal(tc.alias, end, err, len(got))
		}
		if _, state, in, out := s.usage(t, key); state != "settled" || *in != tc.usage.InputTokens || *out != tc.usage.OutputTokens {
			t.Fatal(tc.alias, "not settled at the provider's usage", state)
		}
		before := s.calls.Load()
		if _, err = s.forward(t, key, tc.alias, relay(&got)); !errors.Is(err, ErrLLMAlreadyProcessed) || s.calls.Load() != before {
			t.Fatal(tc.alias, "a settled key was streamed again", err)
		}
	}
	// The text route: fragments of text only, the finish reason, the same
	// accounting.
	var text []string
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}, MaxTokens: 32}
	end, err := s.svc.CompleteStreamFromVM(t.Context(), s.caller, "text-1", "fast", q, nil, func(s string) error { text = append(text, s); return nil })
	if err != nil || end.Outcome != StreamCompleted || strings.Join(text, "") != "Hello" || end.FinishReason != "stop" || end.Usage.OutputTokens != 5 {
		t.Fatal(end, err, text)
	}
	if _, state, _, _ := s.usage(t, "text-1"); state != "settled" {
		t.Fatal("text stream not settled", state)
	}
	rep, err := s.a.LLMUsage(t.Context(), s.owner, "day")
	if err != nil || rep.Totals.Calls != 3 || rep.Totals.SettledInput != 12+127+12 || rep.Totals.SettledOutput != 5+15+5 || rep.Totals.PendingTokens != 0 || rep.Totals.UnknownTokens != 0 {
		t.Fatal("usage report", rep.Totals, err)
	}
	s.seen.mu.Lock()
	defer s.seen.mu.Unlock()
	if len(s.seen.first) != 3 || len(s.seen.events) != 3 || s.seen.events[1].Outcome != "settled" || s.seen.events[1].InputTokens != 127 {
		t.Fatal("observer", s.seen.first, s.seen.events)
	}
}

// After its first byte a stream is never sent again: a cut, a stream without
// usage or past its size leaves the reservation unknown, counted, listed for
// the organization, which settles it. A guest that leaves cuts it too.
func TestACutModelStreamStaysUnknownAndReconcilable(t *testing.T) {
	s := newStreamLab(t, 1)
	for _, tc := range []struct {
		mode, alias string
		events      int
		sink        func(*[]string) func(llmgateway.Event) error
	}{
		{"cut", "fast", 2, relay},
		{"cut", "claude", 2, relay},
		{"no-usage", "fast", 2, relay},
		{"no-usage", "claude", 2, relay},
		{"too-big", "fast", 1, relay},
		{"nominal", "fast", 2, func(got *[]string) func(llmgateway.Event) error {
			return func(e llmgateway.Event) error {
				if *got = append(*got, e.Name); len(*got) == 2 {
					return errors.New("the guest left")
				}
				return nil
			}
		}},
	} {
		s.mode.Store(tc.mode)
		key := tc.mode + "-" + tc.alias
		var got []string
		before := s.calls.Load()
		end, err := s.forward(t, key, tc.alias, tc.sink(&got))
		if err != nil || end.Outcome != StreamOutcomeUnknown || end.Usage != (llmgateway.Usage{}) || len(got) < tc.events || s.calls.Load() != before+1 {
			t.Fatal(key, end, err, len(got))
		}
		if _, state, _, _ := s.usage(t, key); state != "unknown" {
			t.Fatal(key, "a cut stream is", state)
		}
		s.mode.Store("nominal")
		if _, err = s.forward(t, key, tc.alias, relay(&got)); !errors.Is(err, ErrLLMAlreadyProcessed) || s.calls.Load() != before+1 {
			t.Fatal(key, "a cut stream's key was sent again", err)
		}
	}
	// Cut before its first event: nothing was relayed, so the answer is the
	// refusal outcome_unknown; the reservation is unknown all the same.
	s.mode.Store("cut-early")
	var got []string
	if _, err := s.forward(t, "early", "fast", relay(&got)); !errors.Is(err, llmgateway.ErrOutcomeUnknown) || len(got) != 0 {
		t.Fatal("cut before the first event", err, got)
	}
	if _, state, _, _ := s.usage(t, "early"); state != "unknown" {
		t.Fatal("early cut", state)
	}
	// Every unknown call is listed, counted, and settled by the organization.
	calls, err := s.a.ListLLMUnresolved(t.Context(), s.owner, "", 200)
	if err != nil || len(calls) != 7 {
		t.Fatal("unresolved", len(calls), err)
	}
	rep, err := s.a.LLMUsage(t.Context(), s.owner, "day")
	if err != nil || rep.Totals.UnknownTokens <= 0 || rep.Totals.SettledInput != 0 {
		t.Fatal("an uncertain stream stopped counting", rep.Totals, err)
	}
	id, _, _, _ := s.usage(t, "cut-claude")
	if r, err := s.a.SettleLLMOutcome(t.Context(), s.owner, id, "settle-cut", SettleLLMOutcomeInput{InputTokens: 127, OutputTokens: 3}); err != nil || r.Status != 200 {
		t.Fatal("reconcile", err)
	}
	if _, state, in, _ := s.usage(t, "cut-claude"); state != "settled" || *in != 127 {
		t.Fatal("reconciled", state)
	}
}

// A refusal before the first byte releases the reservation, as for a call; a
// 429 is retried before the first byte only.
func TestAStreamRefusedBeforeItsFirstByteIsReleased(t *testing.T) {
	s := newStreamLab(t, 2)
	s.mode.Store("429")
	var got []string
	if _, err := s.forward(t, "limited", "fast", relay(&got)); !errors.Is(err, llmgateway.ErrRateLimited) || len(got) != 0 || s.calls.Load() != 2 {
		t.Fatal("429", err, s.calls.Load())
	}
	if _, state, _, _ := s.usage(t, "limited"); state != "released" {
		t.Fatal("a refused stream kept its reservation", state)
	}
	s.mode.Store("429-once")
	end, err := s.forward(t, "retried", "claude", relay(&got))
	if err != nil || end.Outcome != StreamCompleted || s.calls.Load() != 4 {
		t.Fatal("429 then a stream", end, err, s.calls.Load())
	}
	if _, state, _, _ := s.usage(t, "retried"); state != "settled" {
		t.Fatal("retried stream", state)
	}
}

// A key replayed while its stream still runs in this process answers
// outcome_unknown without reaching the provider, and leaves the reservation
// to the running stream: it is not made unknown under it, so the
// organization cannot resolve it before the stream settles.
func TestReplayingAStreamKeyInFlightNeverReachesTheProvider(t *testing.T) {
	s := newStreamLab(t, 1)
	s.mode.Store("held")
	first := make(chan struct{})
	type result struct {
		end StreamEnd
		err error
	}
	done := make(chan result, 1)
	go func() {
		once := sync.Once{}
		end, err := s.svc.ForwardStreamFromVM(t.Context(), s.caller, "live", "fast", "openai",
			[]byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":32}`), nil,
			func(llmgateway.Event) error { once.Do(func() { close(first) }); return nil })
		done <- result{end, err}
	}()
	<-first
	var got []string
	if _, err := s.forward(t, "live", "fast", relay(&got)); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("replay of a running stream", err)
	}
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}}
	if _, err := s.svc.CallFromVM(t.Context(), s.caller, "live", "fast", q, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("a call under a running stream's key", err)
	}
	if s.calls.Load() != 1 || len(got) != 0 {
		t.Fatal("a replay reached the provider", s.calls.Load())
	}
	id, state, _, _ := s.usage(t, "live")
	if state != "reserved" {
		t.Fatal("a replay changed a running stream's reservation to", state)
	}
	if _, err := s.a.ReleaseLLMOutcome(t.Context(), s.owner, id, "too-early"); !errors.Is(err, ErrTransition) {
		t.Fatal("the organization resolved a running stream", err)
	}
	s.resume()
	r := <-done
	if r.err != nil || r.end.Outcome != StreamCompleted || r.end.Usage.InputTokens != 12 {
		t.Fatal("the running stream", r.end, r.err)
	}
	if _, state, in, _ := s.usage(t, "live"); state != "settled" || *in != 12 {
		t.Fatal("the running stream's settlement", state)
	}
	if _, err := s.forward(t, "live", "fast", relay(&got)); !errors.Is(err, ErrLLMAlreadyProcessed) || s.calls.Load() != 1 {
		t.Fatal("a settled stream's key", err)
	}
	// A reservation left by a call no process runs any more (its worker
	// died) is made unknown at its replay, and never sent.
	if _, err := s.a.ReserveLLM(t.Context(), s.owner.TenantID, s.caller.AgentID, "fast", "orphan", 10, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.forward(t, "orphan", "fast", relay(&got)); !errors.Is(err, llmgateway.ErrOutcomeUnknown) || s.calls.Load() != 1 {
		t.Fatal("orphan", err)
	}
	if _, state, _, _ := s.usage(t, "orphan"); state != "unknown" {
		t.Fatal("orphan", state)
	}
}

// A call reserved under a host admission that then fails never runs: nothing
// reached the provider, so its reservation is released at once rather than
// left "reserved" until the organization resolves it (audit finding L-08),
// and its key is given back, so that its replay finds no running call. Every
// route behaves so.
func TestAFailedAdmissionGivesTheKeyBack(t *testing.T) {
	s := newStreamLab(t, 1)
	lost := errors.New("the hold was lost")
	admission := func(ctx context.Context, fn func(context.Context) error) error {
		if err := fn(ctx); err != nil {
			return err
		}
		return lost
	}
	body := []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":32}`)
	q := llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}, MaxTokens: 8}
	for key, call := range map[string]func(admission func(context.Context, func(context.Context) error) error) error{
		"adm-stream": func(a func(context.Context, func(context.Context) error) error) error {
			_, err := s.svc.ForwardStreamFromVM(t.Context(), s.caller, "adm-stream", "fast", "openai", body, a, func(llmgateway.Event) error { return nil })
			return err
		},
		"adm-forward": func(a func(context.Context, func(context.Context) error) error) error {
			_, err := s.svc.ForwardFromVM(t.Context(), s.caller, "adm-forward", "fast", "openai", []byte(`{"messages":[{"role":"user","content":"hi"}]}`), a)
			return err
		},
		"adm-call": func(a func(context.Context, func(context.Context) error) error) error {
			_, err := s.svc.CallFromVM(t.Context(), s.caller, "adm-call", "claude", q, a)
			return err
		},
	} {
		if err := call(admission); !errors.Is(err, lost) {
			t.Fatal(key, err)
		}
		if _, state, _, _ := s.usage(t, key); state != "released" {
			t.Fatal(key, "a reservation whose admission failed is", state)
		}
		if err := call(nil); !errors.Is(err, ErrLLMAlreadyProcessed) {
			t.Fatal(key, "replay:", err)
		}
	}
	if s.calls.Load() != 0 {
		t.Fatal("a call whose admission failed reached the provider", s.calls.Load())
	}
	rep, err := s.a.LLMUsage(t.Context(), s.owner, "day")
	if err != nil || rep.Totals.PendingTokens != 0 || rep.Totals.UnknownTokens != 0 || rep.Totals.Calls != 0 {
		t.Fatal("a failed admission still counts", rep.Totals, err)
	}
	if calls, err := s.a.ListLLMUnresolved(t.Context(), s.owner, "", 10); err != nil || len(calls) != 0 {
		t.Fatal("a failed admission waits for the organization", calls, err)
	}
}
