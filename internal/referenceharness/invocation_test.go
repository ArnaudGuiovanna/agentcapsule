package referenceharness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// worker is a platform that also serves the post-delivery bridges.
type worker struct {
	ledger
	file                 []byte
	fetches, models      int
	completions          []capsuleprotocol.InvocationCompletion
	keys                 []string
	failComplete, cancel bool
}

func (w *worker) FetchAttachment(_ context.Context, ref capsuleprotocol.AttachmentRef) ([]byte, error) {
	w.fetches++
	return append([]byte(nil), w.file...), nil
}
func (w *worker) CompleteLLM(_ context.Context, key string, in capsuleprotocol.LLMRequest) (capsuleprotocol.LLMResult, error) {
	w.models++
	if in.Alias != "fast" || !strings.HasSuffix(key, "/llm") {
		return capsuleprotocol.LLMResult{}, &capsuleprotocol.PlatformError{Code: "not_found"}
	}
	return capsuleprotocol.LLMResult{Text: "model says: " + in.Messages[0].Content}, nil
}
func (w *worker) CompleteInvocation(_ context.Context, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	w.completions = append(w.completions, in)
	w.keys = append(w.keys, key)
	if w.cancel {
		return capsuleprotocol.CompletionReceipt{}, &capsuleprotocol.PlatformError{Code: "transition"}
	}
	if w.failComplete {
		w.failComplete = false
		return capsuleprotocol.CompletionReceipt{}, &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	return capsuleprotocol.CompletionReceipt{OperationID: in.OperationID, State: in.Outcome}, nil
}

func invocationEvent(t *testing.T, id, text string, refs ...capsuleprotocol.AttachmentRef) harnessstore.Event {
	t.Helper()
	b, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op-" + id, Attachments: refs,
		Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: id, Subjects: []string{"agent/a", "event/" + id}, Body: b}
}

func TestInvocationNeedingThePlatformIsAnsweredAfterDelivery(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := &worker{file: []byte("file content"), failComplete: true}
	h, _ := New("a", s, w)
	sum := sha256.Sum256(w.file)
	ref := capsuleprotocol.AttachmentRef{ID: "att_0123456789abcdef0123456789abcdef", Name: "f.txt", MediaType: "text/plain", Size: int64(len(w.file)), SHA256: hex.EncodeToString(sum[:])}

	// Delivery returns at once: no platform call happens inside it.
	e1 := invocationEvent(t, "e1", "/llm fast hello", ref)
	r := apply(t, h, e1)
	if !capsuleprotocol.IsWorkingResult(r.Result) || w.fetches != 0 || w.models != 0 || len(w.completions) != 0 {
		t.Fatal("platform used during delivery, or not acknowledged working", string(r.Result))
	}
	if replay := apply(t, h, e1); !replay.Replayed || !capsuleprotocol.IsWorkingResult(replay.Result) {
		t.Fatal("redelivery changed the acknowledgment")
	}
	// After delivery: read, ask the model, post. A transient failure to post
	// retries the same answer under the same key, without asking again.
	if _, err = h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	ready(t, h)
	if _, err = h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w.fetches != 1 || w.models != 1 || len(w.completions) != 2 || w.keys[0] != w.keys[1] {
		t.Fatal("retry recomputed or changed key", w.fetches, w.models, len(w.completions))
	}
	got := w.completions[1]
	if got.OperationID != "op-e1" || got.Outcome != "completed" || len(got.Content) != 2 ||
		!strings.Contains(got.Content[0].Text, ref.SHA256) || got.Content[1].Text != "model says: hello" {
		t.Fatal("answer", got)
	}
	if worked, err := h.Step(t.Context()); err != nil || worked {
		t.Fatal("finished work repeated", err)
	}

	// A plain message is still answered within the delivery.
	if r := apply(t, h, invocationEvent(t, "e2", "just echo")); capsuleprotocol.IsWorkingResult(r.Result) {
		t.Fatal("a plain message was deferred")
	}
	// A canceled invocation stops the work instead of retrying forever.
	w.cancel = true
	apply(t, h, invocationEvent(t, "e3", "/llm fast bye"))
	if _, err = h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	ready(t, h)
	if worked, err := h.Step(t.Context()); err != nil || worked {
		t.Fatal("canceled work retried", err)
	}
}

func TestInvocationWithoutWorkBridgeIsAnsweredHonestly(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, _ := New("a", s, &ledger{})
	r := apply(t, h, invocationEvent(t, "e1", "/llm fast hello"))
	if capsuleprotocol.IsWorkingResult(r.Result) || !strings.Contains(string(r.Result), "unavailable") {
		t.Fatal("deferred without a way to finish", string(r.Result))
	}
}
