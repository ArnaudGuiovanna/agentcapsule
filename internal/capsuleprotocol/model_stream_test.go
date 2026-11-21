//go:build linux

package capsuleprotocol

import (
	"context"
	"errors"
	"iter"
	"strings"
	"sync"
	"testing"
	"time"
)

type modelStreamFake struct {
	platformFake
	finish chan struct{}
	deny   bool
}

func (m *modelStreamFake) RequireCapability(ctx context.Context, name string) error {
	if name != "llm.invoke" || m.deny {
		return &PlatformError{Code: "capability_denied"}
	}
	return nil
}
func modelTestEnd() LLMStreamFrame {
	tokens := int64(2)
	soft := false
	return LLMStreamFrame{Type: "end", Outcome: "completed", InputTokens: &tokens, OutputTokens: &tokens, SoftExceeded: &soft}
}
func (m *modelStreamFake) CompleteLLMStream(ctx context.Context, key string, in LLMRequest, send func(LLMStreamFrame) error) error {
	if key == "denied" {
		return &PlatformError{Code: "quota_exceeded"}
	}
	if err := send(LLMStreamFrame{Type: "text", Text: "early"}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.finish:
	}
	if key == "cut" {
		return errors.New("local diagnostic")
	}
	return send(modelTestEnd())
}
func (m *modelStreamFake) ForwardLLMStream(ctx context.Context, key string, in LLMForward, send func(LLMStreamFrame) error) error {
	event := &LLMStreamEvent{Name: "content_block_delta", Data: []byte(`{"delta":{"text":"<x> & 😀"}}`)}
	if err := send(LLMStreamFrame{Type: "event", Event: event}); err != nil {
		return err
	}
	return send(modelTestEnd())
}

func TestModelStreamsReachTheGuestBeforeCompletion(t *testing.T) {
	api := &modelStreamFake{finish: make(chan struct{})}
	client, _, _ := localStreamBridge(t, api)
	in := LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "hi"}}}
	var types []string
	for f, e := range client.CompleteLLMStream(t.Context(), "ok", in) {
		if e != nil || f.Seq != int64(len(types)) {
			t.Fatal("frame", f, e)
		}
		types = append(types, f.Type)
		if f.Type == "text" {
			if f.Text != "early" {
				t.Fatal(f)
			}
			close(api.finish) // provider only completes after the guest receives text
		}
		if f.Type == "end" && (f.Outcome != "completed" || *f.InputTokens != 2 || *f.SoftExceeded) {
			t.Fatal(f)
		}
	}
	if strings.Join(types, ",") != "start,text,end" {
		t.Fatal(types)
	}
	fwd := LLMForward{Alias: "fast", Dialect: "anthropic", Body: []byte(`{"stream":true}`)}
	types = nil
	for f, e := range client.ForwardLLMStream(t.Context(), "native", fwd) {
		if e != nil {
			t.Fatal(e)
		}
		types = append(types, f.Type)
		if f.Type == "event" && (f.Event.Name != "content_block_delta" || string(f.Event.Data) != `{"delta":{"text":"<x> & 😀"}}`) {
			t.Fatal(f.Event)
		}
	}
	if strings.Join(types, ",") != "start,event,end" {
		t.Fatal(types)
	}
	for f, e := range client.CompleteLLMStream(t.Context(), "cut", in) {
		if e != nil || f.Type == "end" && (f.Outcome != "outcome_unknown" || f.InputTokens != nil) {
			t.Fatal("cut", f, e)
		}
	}
}

func TestModelStreamAdmissionAndSlots(t *testing.T) {
	api := &modelStreamFake{finish: make(chan struct{})}
	client, _, _ := localStreamBridge(t, api)
	in := LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "hi"}}}
	refused := func(frames iter.Seq2[LLMStreamFrame, error], code string) {
		t.Helper()
		n := 0
		for _, e := range frames {
			var pe *PlatformError
			if !errors.As(e, &pe) || pe.Code != code {
				t.Fatalf("want %s, got %v", code, e)
			}
			n++
		}
		if n != 1 {
			t.Fatal("refusal count", n)
		}
	}
	refused(client.CompleteLLMStream(t.Context(), "denied", in), "quota_exceeded")
	refused(client.ForwardLLMStream(t.Context(), "absent", LLMForward{Alias: "fast", Dialect: "openai", Body: []byte("{}")}), "invalid")
	blocked, _, _ := localStreamBridge(t, &modelStreamFake{deny: true})
	refused(blocked.CompleteLLMStream(t.Context(), "missing", in), "capability_denied")
	opened := make(chan struct{}, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for f, err := range client.CompleteLLMStream(t.Context(), "held", in) {
				if err != nil {
					t.Error(err)
					return
				}
				if f.Type == "text" {
					opened <- struct{}{}
				}
			}
		})
	}
	defer func() { close(api.finish); workers.Wait() }()
	timeout := time.After(10 * time.Second)
	for range 16 {
		select {
		case <-opened:
		case <-timeout:
			t.Fatal("streams did not open")
		}
	}
	refused(client.CompleteLLMStream(t.Context(), "full", in), "unavailable")
}

func TestModelStreamStrictFrames(t *testing.T) {
	for _, line := range []string{
		`{"type":"text","seq":2,"text":"x"}`,
		`{"type":"text","seq":1,"text":"x","outcome":"completed"}`,
		`{"type":"text","seq":1,"text":""}`,
		`{"type":"event","seq":1,"event":{"data":{}}}`,
		`{"type":"end","seq":1,"outcome":"completed"}`,
		`{"type":"end","seq":1,"outcome":"outcome_unknown","input_tokens":null}`,
	} {
		if _, err := readModelFrame([]byte(line), Identity{}, CompleteLLMStreamPath, 1); err == nil {
			t.Fatal("accepted", line)
		}
	}
	if _, err := newFrameReader(strings.NewReader(strings.Repeat("x", MaxStreamFrameBytes)+"\n"), nil).next(0); !errors.Is(err, ErrProtocol) {
		t.Fatal("oversized", err)
	}
}
