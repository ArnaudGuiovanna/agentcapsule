package referenceharness

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type ledger struct {
	submits, replies, effects int
	key                       string
	body                      []byte
	lose                      bool
	transition                bool
	ownerPosts, ownerEffects  int
	ownerKey                  string
	ownerBody                 []byte
	loseOwner                 bool
}

func (l *ledger) Submit(_ context.Context, key string, in capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	l.submits++
	body, _ := json.Marshal(in)
	if l.key != "" && (l.key != key || string(l.body) != string(body)) {
		return capsuleprotocol.PlatformReceipt{}, errors.New("unstable retry identity")
	}
	if l.key == "" {
		l.key, l.body = key, body
		l.effects++
	}
	if l.lose {
		l.lose = false
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	return capsuleprotocol.PlatformReceipt{RequestID: "r", State: "PENDING_APPROVAL", Replayed: l.submits > 1}, nil
}
func (l *ledger) Reply(_ context.Context, id, key string, in capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	l.replies++
	if l.transition {
		l.transition = false
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "transition"}
	}
	l.effects++
	if id != "r" || in.Outcome != "completed" || in.Payload == nil {
		return capsuleprotocol.PlatformReceipt{}, errors.New("invalid reply")
	}
	return capsuleprotocol.PlatformReceipt{RequestID: id, State: "REPLIED"}, nil
}
func (l *ledger) PostOwner(_ context.Context, key string, in capsuleprotocol.OwnerPost) (capsuleprotocol.OwnerPostReceipt, error) {
	l.ownerPosts++
	body, _ := json.Marshal(in)
	if l.ownerKey != "" && (l.ownerKey != key || string(l.ownerBody) != string(body)) {
		return capsuleprotocol.OwnerPostReceipt{}, errors.New("unstable owner message retry")
	}
	if l.ownerKey == "" {
		l.ownerKey, l.ownerBody = key, body
		l.ownerEffects++
	}
	if l.loseOwner {
		l.loseOwner = false
		return capsuleprotocol.OwnerPostReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	return capsuleprotocol.OwnerPostReceipt{MessageID: "summary", Replayed: l.ownerPosts > 1}, nil
}
func instruction(t *testing.T) harnessstore.Event {
	t.Helper()
	b, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op", Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 3, ExpiresAt: time.Now().Add(time.Hour)}, Content: []capsuleprotocol.TextContent{{Type: "text", Text: "/ask b private question"}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: "instruction", Subjects: []string{"agent/a", "event/instruction"}, Body: b}
}
func peer(t *testing.T, kind string) harnessstore.Event {
	t.Helper()
	b, err := json.Marshal(capsuleprotocol.PeerEvent{Kind: kind, RequestID: "r", SenderAgentID: "a", RecipientAgentID: "b", Sequence: 1, Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "/ask c relay this"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: kind, Subjects: []string{"agent/a", "agent/b", "request/r", "event/" + kind}, Body: b}
}
func apply(t *testing.T, h *Engine, e harnessstore.Event) harnessstore.Receipt {
	t.Helper()
	r, err := h.store.Apply(t.Context(), e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) { return h.Handle(ctx, e, tx) })
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func ready(t *testing.T, h *Engine) {
	t.Helper()
	if err := h.store.Local(t.Context(), []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE reference_outgoing SET next_ns=0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
func TestOutgoingIntentRollbackAndRestartAfterUnknownCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harness.db")
	s, err := harnessstore.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger{lose: true}
	h, _ := New("a", s, l)
	if _, err = h.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	e := instruction(t)
	injected := errors.New("rollback")
	_, err = s.Apply(t.Context(), e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		if _, err := h.Handle(ctx, e, tx); err != nil {
			return nil, err
		}
		return nil, injected
	})
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if worked, err := h.Step(t.Context()); err != nil || worked || l.submits != 0 {
		t.Fatal("rolled back intent sent", err)
	}
	first := apply(t, h, e)
	if replay := apply(t, h, e); !replay.Replayed || string(replay.Result) != string(first.Result) {
		t.Fatal("delivery replay changed result")
	}
	if _, err = h.Step(t.Context()); err != nil || l.effects != 1 {
		t.Fatal("first remote commit", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = harnessstore.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, _ = New("a", s, l)
	ready(t, h)
	if _, err = h.Step(t.Context()); err != nil || l.submits != 2 || l.effects != 1 {
		t.Fatal("restart did not replay identical intent", err)
	}
	if worked, err := h.Step(t.Context()); err != nil || worked {
		t.Fatal("completed work repeated", err)
	}
	var n int
	if err = s.Local(t.Context(), []string{"agent/a"}, func(tx harnessstore.SQL) error {
		return tx.QueryRowContext(t.Context(), "SELECT count(*) FROM echo_events").Scan(&n)
	}); err != nil || n != 1 {
		t.Fatal("duplicate local effect", n, err)
	}
}
func TestPeerCannotRelayAndReplyRetriesBeforeDeliveryACK(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l := &ledger{transition: true}
	h, _ := New("b", s, l)
	apply(t, h, peer(t, "request"))
	if _, err = h.Step(t.Context()); err != nil || l.replies != 1 || l.effects != 0 {
		t.Fatal(err)
	}
	ready(t, h)
	if _, err = h.Step(t.Context()); err != nil || l.replies != 2 || l.effects != 1 || l.submits != 0 {
		t.Fatal("peer content acquired mandate or reply lost", err)
	}
	a, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	other := &ledger{loseOwner: true}
	sender, _ := New("a", a, other)
	apply(t, sender, peer(t, "reply"))
	if worked, err := sender.Step(t.Context()); err != nil || !worked || other.submits != 0 || other.ownerEffects != 1 {
		t.Fatal("response caused new request", err)
	}
	ready(t, sender)
	if _, err := sender.Step(t.Context()); err != nil || other.ownerEffects != 1 || other.ownerPosts != 2 {
		t.Fatal("owner summary duplicated", err)
	}
}
func TestLocalRevocationAndTerminalStatusCancelPendingReply(t *testing.T) {
	for _, mode := range []string{"fence", "status"} {
		t.Run(mode, func(t *testing.T) {
			s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "b.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			l := &ledger{}
			h, _ := New("b", s, l)
			apply(t, h, peer(t, "request"))
			if mode == "fence" {
				if err = s.Fence(t.Context(), "request/r"); err != nil {
					t.Fatal(err)
				}
			} else {
				apply(t, h, harnessstore.Event{ID: "closed", Subjects: []string{"agent/b", "event/closed", "notification/closed"}, Body: []byte(`{"Kind":"status","RequestID":"r","Status":"CANCELED","Sequence":2}`)})
			}
			if _, err = h.Step(t.Context()); err != nil || l.effects != 0 {
				t.Fatal("revoked work reached remote", err)
			}
			if worked, err := h.Step(t.Context()); err != nil || worked {
				t.Fatal("stopped work blocks queue", err)
			}
		})
	}
}
