package referenceharness

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// deniedPlatform refuses every submission as the host does for an agent
// without agents.delegate.
type deniedPlatform struct{ ledger }

func (d *deniedPlatform) Submit(context.Context, string, capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	d.submits++
	return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "capability_denied"}
}

// The echo keeps JSON parts as they came.
func TestEchoKeepsJSONParts(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, _ := New("a", s, &ledger{})
	content := []capsuleprotocol.ContentPart{{Type: "text", Text: "rows"}, {Type: "json", JSON: `{"n":[1,2]}`}}
	b, _ := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op",
		Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)}, Content: content})
	r := apply(t, h, harnessstore.Event{ID: "e", Subjects: []string{"agent/a", "event/e"}, Body: b})
	var echoed capsuleprotocol.OwnerMessage
	if json.Unmarshal(r.Result, &echoed) != nil || len(echoed.Content) != 2 || echoed.Content[1] != content[1] {
		t.Fatal(string(r.Result))
	}
}

// A request the agent may not send (capability_denied) is not retried.
func TestADeniedCapabilityStopsTheOutgoingWork(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := &deniedPlatform{}
	h, _ := New("a", s, p)
	apply(t, h, instruction(t))
	if worked, err := h.Step(t.Context()); err != nil || !worked || p.submits != 1 {
		t.Fatal(worked, err, p.submits)
	}
	ready(t, h)
	if worked, err := h.Step(t.Context()); err != nil || worked || p.submits != 1 {
		t.Fatal("a denied request was sent again", worked, err, p.submits)
	}
	var state, reason string
	if err = s.Local(t.Context(), []string{"agent/a"}, func(tx harnessstore.SQL) error {
		return tx.QueryRowContext(t.Context(), "SELECT state,reason FROM reference_outgoing").Scan(&state, &reason)
	}); err != nil || state != "stopped" || reason != "capability_denied" {
		t.Fatal(state, reason, err)
	}
}
