package referenceharness

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// fakeOutput records what the harness streams; cancelAfter cancels the
// invocation once that many deltas came.
type fakeOutput struct {
	mu          sync.Mutex
	frames      []string
	closed      bool
	cancelAfter int
	canceled    chan struct{}
	done        chan struct{}
}

func (f *fakeOutput) Delta(text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, "delta:"+text)
	if f.cancelAfter > 0 && len(f.frames)-1 == f.cancelAfter {
		close(f.canceled)
		close(f.done)
	}
	return nil
}
func (f *fakeOutput) Step(step, state, label string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, "step:"+step+":"+state)
	return nil
}
func (f *fakeOutput) Close(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return capsuleprotocol.StreamDone, nil
}
func (f *fakeOutput) Canceled() <-chan struct{} { return f.canceled }
func (f *fakeOutput) Done() <-chan struct{}     { return f.done }
func (f *fakeOutput) Abort()                    {}

func streamingEngine(t *testing.T, w *worker, out *fakeOutput) *Engine {
	t.Helper()
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h, err := New("a", s, w)
	if err != nil {
		t.Fatal(err)
	}
	h.streamPace = 0
	h.openStream = func(_ context.Context, op string) (outputStream, error) {
		if op != "op-s1" && op != "op-s2" {
			t.Error("opened the stream of", op)
		}
		return out, nil
	}
	return h
}

// "/stream <n>" answers working, then streams n deltas between two steps,
// closes the stream and files the deltas' text: a demonstration without a
// model. A retried filing does not stream again.
func TestStreamCommandStreamsThenFiles(t *testing.T) {
	out := &fakeOutput{canceled: make(chan struct{}), done: make(chan struct{})}
	w := &worker{failComplete: true}
	h := streamingEngine(t, w, out)
	if r := apply(t, h, invocationEvent(t, "s1", "/stream 3")); !capsuleprotocol.IsWorkingResult(r.Result) {
		t.Fatal("not working", string(r.Result))
	}
	if _, err := h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{"step:echo.stream:started", "delta:word1", "delta: word2", "delta: word3", "step:echo.stream:done"}
	if strings.Join(out.frames, "|") != strings.Join(want, "|") || !out.closed {
		t.Fatal("streamed", out.frames, out.closed)
	}
	ready(t, h)
	if _, err := h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(out.frames) != len(want) || len(w.completions) != 2 || w.completions[1].Content[0].Text != "word1 word2 word3" {
		t.Fatal("the retry streamed again, or the answer differs", out.frames, w.completions)
	}
	for _, text := range []string{"/stream 0", "/stream 2001", "/stream many"} {
		var m capsuleprotocol.OwnerMessage
		if r := apply(t, h, invocationEvent(t, strings.ReplaceAll(text, " ", "-"), text)); json.Unmarshal(r.Result, &m) != nil || !strings.HasPrefix(m.Content[0].Text, "Usage: /stream") {
			t.Fatal("bad count accepted", text, string(r.Result))
		}
	}
}

// A cancellation stops the stream and the work, files nothing, and
// "/stream canceled" reports it.
func TestStreamCommandStopsWhenCanceled(t *testing.T) {
	out := &fakeOutput{cancelAfter: 2, canceled: make(chan struct{}), done: make(chan struct{})}
	w := &worker{}
	h := streamingEngine(t, w, out)
	var m capsuleprotocol.OwnerMessage
	if r := apply(t, h, invocationEvent(t, "q0", "/stream canceled")); json.Unmarshal(r.Result, &m) != nil || m.Content[0].Text != "No stream was canceled." {
		t.Fatal(string(r.Result))
	}
	apply(t, h, invocationEvent(t, "s2", "/stream 50"))
	if _, err := h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(out.frames) != 3 || len(w.completions) != 0 {
		t.Fatal("the stream went on after the cancellation, or filed", out.frames, w.completions)
	}
	ready(t, h)
	if worked, err := h.Step(t.Context()); err != nil || worked {
		t.Fatal("canceled work retried", err)
	}
	if r := apply(t, h, invocationEvent(t, "q1", "/stream canceled")); json.Unmarshal(r.Result, &m) != nil || m.Content[0].Text != "Canceled streams: op-s2." {
		t.Fatal(string(r.Result))
	}
}

// Without a platform that streams, the command answers at once.
func TestStreamCommandWithoutAStreamIsAnsweredHonestly(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, _ := New("a", s, &worker{})
	var m capsuleprotocol.OwnerMessage
	if r := apply(t, h, invocationEvent(t, "s3", "/stream 3")); json.Unmarshal(r.Result, &m) != nil || !strings.Contains(m.Content[0].Text, "unavailable") {
		t.Fatal(string(r.Result))
	}
}
