package capsuleprotocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
)

// Each frame of an output stream is one strict JSON object of a known type.
func TestOutputStreamFramesAreStrict(t *testing.T) {
	for _, line := range []string{
		`{"type":"delta","seq":1,"text":"The NPV is computed "}`,
		`{"type":"step","seq":2,"step":"retrieval","state":"started","label":"Searching the course"}`,
		`{"type":"step","seq":3,"step":"a.b-c_9","state":"done"}`,
	} {
		if _, closing, err := parseHarnessFrame([]byte(line)); err != nil || closing {
			t.Error("refused", line, err)
		}
	}
	if _, closing, err := parseHarnessFrame([]byte(`{"type":"close"}`)); err != nil || !closing {
		t.Fatal("close", err)
	}
	for _, line := range []string{
		`{"type":"delta","seq":1,"text":"x","extra":1}`,
		`{"type":"delta","seq":0,"text":"x"}`,
		`{"type":"delta","text":"x"}`,
		`{"type":"delta","seq":1,"text":""}`,
		`{"type":"delta","seq":1,"text":"a\u0000b"}`,
		"{\"type\":\"delta\",\"seq\":1,\"text\":\"\xff\"}",
		`{"type":"delta","seq":1,"text":"x"} {}`,
		`{"type":"step","seq":1,"step":"Retrieval","state":"started"}`,
		`{"type":"step","seq":1,"step":"retrieval","state":"running"}`,
		`{"type":"step","seq":1,"step":"retrieval","state":"done","label":""}`,
		`{"type":"step","seq":1,"step":"retrieval","state":"done","label":"a\u0007b"}`,
		`{"type":"step","seq":1,"step":"retrieval","state":"done","label":"` + strings.Repeat("l", 257) + `"}`,
		`{"type":"step","seq":1,"step":"retrieval","state":"done","text":"x"}`,
		`{"type":"close","seq":4}`,
		`{"type":"open","protocol":"capsule.v1","operation_id":"op"}`,
		`{"type":"result","seq":1}`,
		`["delta"]`,
	} {
		if _, _, err := parseHarnessFrame([]byte(line)); err == nil {
			t.Error("accepted", line)
		}
	}
	id := Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	good, err := encodeFrame(openFrame{Type: "open", Protocol: Version, Identity: id, OperationID: "op_1"})
	if err != nil {
		t.Fatal(err)
	}
	if o, err := parseOpen(bytes.TrimSpace(good)); err != nil || o.Attempt != nil || o.OperationID != "op_1" {
		t.Fatal("open", o, err)
	}
	for _, line := range []string{
		`{"type":"open","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"operation_id":"op","attempt":0}`,
		`{"type":"open","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"operation_id":""}`,
		`{"type":"open","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"operation_id":"op","seq":1}`,
		`{"type":"delta","seq":1,"text":"x"}`,
	} {
		if _, err := parseOpen([]byte(line)); err == nil {
			t.Error("accepted open", line)
		}
	}
	// A stored frame keeps its text as sent, without HTML escapes.
	b, err := OutputFrame{Type: "delta", Seq: 1, Text: "<a> & b"}.Encode()
	if err != nil || string(b) != `{"type":"delta","seq":1,"text":"<a> & b"}` {
		t.Fatal(string(b), err)
	}
	chunk, err := EncodeOutputChunk([]OutputFrame{{Type: "delta", Seq: 1, Text: "a"}, {Type: "step", Seq: 2, Step: "s", State: "done"}})
	if err != nil || string(chunk) != `[{"type":"delta","seq":1,"text":"a"},{"type":"step","seq":2,"step":"s","state":"done"}]` {
		t.Fatal(string(chunk), err)
	}
	// The platform's frames come in order: opened, acks, cancel, closed.
	seq := controlSequence{identity: id}
	for _, line := range []string{
		`{"type":"opened","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"attempt":2,"seq":0}`,
		`{"type":"ack","seq":3}`, `{"type":"cancel"}`, `{"type":"closed","reason":"terminal"}`,
	} {
		f, err := parseControlFrame([]byte(line))
		if err != nil || seq.next(f) != nil {
			t.Fatal("control frame", line, err)
		}
	}
	for _, tc := range []struct {
		opened bool
		line   string
	}{
		{false, `{"type":"ack","seq":1}`},
		{false, `{"type":"opened","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"b","generation":1,"vm_id":"0123456789abcdef"},"attempt":1,"seq":0}`},
		{true, `{"type":"closed","reason":"later"}`},
		{true, `{"type":"ack","seq":0}`},
		{true, `{"type":"opened","protocol":"capsule.v1","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"attempt":1,"seq":0}`},
	} {
		s := controlSequence{identity: id, opened: tc.opened}
		f, err := parseControlFrame([]byte(tc.line))
		if err == nil && s.next(f) == nil {
			t.Error("accepted control frame", tc.line)
		}
	}
}

// streamFake is a host whose output streams are kept in memory.
type streamFake struct {
	platformFake
	deny     bool
	refuse   error
	closing  string
	mu       sync.Mutex
	opens    []string
	attempts []int
	chunks   [][]OutputFrame
	streams  []*fakeStream
	appended chan struct{}
	closed   atomic.Int32
}

func (f *streamFake) RequireCapability(_ context.Context, name string) error {
	if f.deny && name == capability.StreamOutput {
		return &PlatformError{Code: "capability_denied"}
	}
	return nil
}

func (f *streamFake) OpenOutputStream(_ context.Context, op string, attempt int) (OutputStream, error) {
	if f.refuse != nil {
		return nil, f.refuse
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens = append(f.opens, op)
	f.attempts = append(f.attempts, attempt)
	s := &fakeStream{fake: f, signals: make(chan StreamSignal, 1)}
	f.streams = append(f.streams, s)
	return s, nil
}

func (f *streamFake) stored() []OutputFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []OutputFrame
	for _, c := range f.chunks {
		out = append(out, c...)
	}
	return out
}

type fakeStream struct {
	fake      *streamFake
	last      int64
	signals   chan StreamSignal
	discarded atomic.Int32
	refuse    string
	reason    atomic.Pointer[string]
}

func (s *fakeStream) Attempt() int    { return 1 }
func (s *fakeStream) LastSeq() int64  { return s.last }
func (s *fakeStream) Closing() string { return s.fake.closing }
func (s *fakeStream) Append(_ context.Context, frames []OutputFrame) (string, error) {
	if s.refuse != "" {
		return s.refuse, nil
	}
	s.fake.mu.Lock()
	s.fake.chunks = append(s.fake.chunks, slices.Clone(frames))
	s.fake.mu.Unlock()
	s.last = frames[len(frames)-1].Seq
	if s.fake.appended != nil {
		s.fake.appended <- struct{}{}
	}
	return "", nil
}
func (s *fakeStream) Signals() <-chan StreamSignal { return s.signals }
func (s *fakeStream) Close(reason string, dropped int) {
	s.reason.Store(&reason)
	s.discarded.Add(int32(dropped))
	s.fake.closed.Add(1)
}

// A harness streams deltas and steps over one full-duplex call; the host
// coalesces them, acknowledges what it stored, and answers close with done.
func TestOutputStreamCarriesFramesFullDuplex(t *testing.T) {
	api := &streamFake{appended: make(chan struct{}, 16)}
	c, _, _, _ := platformFixtureFor(t, api)
	w, err := c.OpenOutputStream(t.Context(), "op_1")
	if err != nil || w.Attempt() != 1 || w.Seq() != 0 {
		t.Fatal("open", err)
	}
	if err = w.Step("retrieval", StepStarted, "Searching the course"); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"The NPV ", "is computed ", "by discounting."} {
		if err = w.Delta(text); err != nil {
			t.Fatal(err)
		}
	}
	// Full duplex: the platform acknowledges before the harness has closed.
	select {
	case <-api.appended:
	case <-time.After(5 * time.Second):
		t.Fatal("no chunk within the coalescing window")
	}
	deadline := time.Now().Add(5 * time.Second)
	for w.Acked() != 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w.Acked() != 4 {
		t.Fatal("ack before close", w.Acked())
	}
	if err = w.Delta(" More."); err != nil {
		t.Fatal(err)
	}
	reason, err := w.Close(t.Context())
	if err != nil || reason != StreamDone || w.Acked() != 5 {
		t.Fatal("close", reason, err, w.Acked())
	}
	got := api.stored()
	if len(got) != 5 || got[0] != (OutputFrame{Type: "step", Seq: 1, Step: "retrieval", State: StepStarted, Label: "Searching the course"}) ||
		got[4] != (OutputFrame{Type: "delta", Seq: 5, Text: " More."}) {
		t.Fatal("stored frames", got)
	}
	if len(api.chunks) != 2 || !slices.Equal(api.opens, []string{"op_1"}) || api.attempts[0] != 0 {
		t.Fatal("chunks", len(api.chunks), api.opens, api.attempts)
	}
	if err = w.Delta("after close"); !errors.Is(err, ErrStreamClosed) {
		t.Fatal("a delta after close", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for api.closed.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if api.closed.Load() != 1 {
		t.Fatal("the host did not close the stream")
	}
	// Reopening names the attempt.
	w, err = c.ReopenOutputStream(t.Context(), "op_1", 1)
	if err != nil || api.attempts[1] != 1 {
		t.Fatal("reopen", err, api.attempts)
	}
	w.Abort()
}

// A cancellation reaches the harness: cancel, then closed terminal; frames
// still buffered are dropped, never stored.
func TestOutputStreamCarriesTheCancellation(t *testing.T) {
	api := &streamFake{}
	c, _, _, _ := platformFixtureFor(t, api)
	w, err := c.OpenOutputStream(t.Context(), "op_1")
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	s := api.streams[0]
	api.mu.Unlock()
	s.signals <- StreamSignal{Reason: StreamCanceled}
	select {
	case <-w.Canceled():
	case <-time.After(5 * time.Second):
		t.Fatal("the cancellation did not reach the harness")
	}
	<-w.Done()
	if w.Reason() != StreamTerminal {
		t.Fatal("reason", w.Reason(), w.Err())
	}
	if err = w.Delta("too late"); !errors.Is(err, ErrStreamClosed) {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.reason.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r := s.reason.Load(); r == nil || *r != StreamTerminal {
		t.Fatal("the host closed the stream with", r)
	}
}

// The opening's refusals are the channel's JSON answers, before any frame;
// an opening that closes at once says why after opened.
func TestOutputStreamOpeningRefusals(t *testing.T) {
	for _, tc := range []struct {
		api  *streamFake
		code string
	}{
		{&streamFake{deny: true}, "capability_denied"},
		{&streamFake{refuse: &PlatformError{Code: "transition"}}, "transition"},
		{&streamFake{refuse: &PlatformError{Code: "not_found"}}, "not_found"},
		{&streamFake{refuse: errors.New("private SQL detail")}, "unavailable"},
	} {
		c, _, _, _ := platformFixtureFor(t, tc.api)
		_, err := c.OpenOutputStream(t.Context(), "op_1")
		var refusal *PlatformError
		if !errors.As(err, &refusal) || refusal.Code != tc.code {
			t.Error(tc.code, err)
		}
	}
	api := &streamFake{closing: StreamReset}
	c, _, _, _ := platformFixtureFor(t, api)
	w, err := c.OpenOutputStream(t.Context(), "op_1")
	if err != nil {
		t.Fatal(err)
	}
	<-w.Done()
	if w.Reason() != StreamReset {
		t.Fatal("reason", w.Reason())
	}
}

// rawStream opens the route with lines written by hand and returns the
// answer's status and lines.
func rawStream(t *testing.T, c *PlatformClient, lines ...string) (int, []string) {
	t.Helper()
	body := strings.Join(lines, "\n") + "\n"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.client.endpoint(OutputStreamPath), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := *c.client.http
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.Split(strings.TrimSpace(string(b)), "\n")
}

// A malformed frame, a gap in seq or a frame too large closes the stream
// invalid; the frames before it are stored. A bad first line is refused.
func TestOutputStreamClosesOnAnInvalidFrame(t *testing.T) {
	api := &streamFake{}
	c, host, _, _ := platformFixtureFor(t, api)
	open, _ := encodeFrame(openFrame{Type: "open", Protocol: Version, Identity: host.Identity, OperationID: "op_1"})
	first := strings.TrimSpace(string(open))
	for _, tc := range []struct {
		name   string
		lines  []string
		stored int
	}{
		{"unknown field", []string{first, `{"type":"delta","seq":1,"text":"a"}`, `{"type":"delta","seq":2,"text":"b","x":1}`}, 1},
		{"gap", []string{first, `{"type":"delta","seq":1,"text":"a"}`, `{"type":"delta","seq":3,"text":"c"}`}, 1},
		{"too large", []string{first, `{"type":"delta","seq":1,"text":"` + strings.Repeat("z", MaxStreamFrameBytes) + `"}`}, 0},
		{"second open", []string{first, first}, 0},
	} {
		api.mu.Lock()
		api.chunks = nil
		api.mu.Unlock()
		status, lines := rawStream(t, c, tc.lines...)
		if status != 200 || len(lines) < 2 || lines[len(lines)-1] != `{"type":"closed","reason":"invalid"}` || len(api.stored()) != tc.stored {
			t.Error(tc.name, status, lines, len(api.stored()))
		}
	}
	for _, lines := range [][]string{{`{"type":"delta","seq":1,"text":"a"}`}, {strings.Replace(first, `"agent_id":"a"`, `"agent_id":"b"`, 1)}} {
		if status, _ := rawStream(t, c, lines...); status != http.StatusBadRequest && status != http.StatusForbidden {
			t.Error("a bad first line", lines, status)
		}
	}
}

// A stream with no frame for its idle bound closes idle, after storing what
// it had.
func TestOutputStreamClosesIdle(t *testing.T) {
	harness, host := net.Pipe()
	defer harness.Close()
	defer host.Close()
	api := &streamFake{}
	s, _ := api.OpenOutputStream(t.Context(), "op", 0)
	var answer bytes.Buffer
	var mu sync.Mutex
	out := &frameWriter{w: writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return answer.Write(b) })}
	done := make(chan struct{})
	var closed string
	go func() {
		defer close(done)
		closed, _ = runOutputStream(t.Context(), Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, s,
			newFrameReader(host, host.SetReadDeadline), out, OutputStreamSettings{CoalesceWindow: time.Hour, CoalesceBytes: 4096, IdleTimeout: 200 * time.Millisecond})
	}()
	if _, err := harness.Write([]byte(`{"type":"delta","seq":1,"text":"only one"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle stream stayed open")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasSuffix(answer.String(), `{"type":"ack","seq":1}`+"\n"+`{"type":"closed","reason":"idle"}`+"\n") || len(api.stored()) != 1 || closed != StreamIdle {
		t.Fatal(answer.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// A stream holds one of the VM's 16 slots for its whole life: the 17th call
// is refused unavailable.
func TestOutputStreamsHoldTheVMSlots(t *testing.T) {
	api := &streamFake{}
	c, _, _, _ := platformFixtureFor(t, api)
	var streams []*OutputStreamWriter
	for range 16 {
		w, err := c.OpenOutputStream(t.Context(), "op_1")
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, w)
	}
	_, err := c.OpenOutputStream(t.Context(), "op_1")
	var refusal *PlatformError
	if !errors.As(err, &refusal) || refusal.Code != "unavailable" {
		t.Fatal("a 17th stream", err)
	}
	if err = c.Health(t.Context()); err == nil {
		t.Fatal("another call took a slot held by the streams")
	}
	for _, w := range streams {
		if reason, err := w.Close(t.Context()); err != nil || reason != StreamDone {
			t.Fatal(reason, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.Health(t.Context()) != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err = c.Health(t.Context()); err != nil {
		t.Fatal("the slots were not released", err)
	}
}
