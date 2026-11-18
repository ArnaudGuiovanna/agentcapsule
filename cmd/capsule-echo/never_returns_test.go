//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func invocationEvent(t *testing.T, agent, id, text string) harnessstore.Event {
	t.Helper()
	body, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op_" + id,
		Mandate: capsuleprotocol.InstructionMandate{ID: "mdt_" + id, MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: "evt_" + id, Subjects: []string{"agent/" + agent, "event/evt_" + id}, Body: body}
}

// A never-returns harness holds its store with an invocation that asks it
// to never return (ADR 012, question 7): its handler runs a statement that
// never ends, past the request's own deadline, so that the store's write
// transaction stays open and a fence cannot commit. Only the harness's stop
// ends it. The store is then free, and another invocation is answered.
func TestNeverReturnsHoldsItsStoreUntilTheHarnessStops(t *testing.T) {
	const agent = "agt_stuck"
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lifetime, stop := context.WithCancel(t.Context())
	defer stop()
	handle := neverReturns(agent, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		return []byte(`{"echo":true}`), nil
	}, lifetime)
	apply := func(ctx context.Context, e harnessstore.Event) (harnessstore.Receipt, error) {
		return store.Apply(ctx, e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) { return handle(ctx, e, tx) })
	}
	held := invocationEvent(t, agent, "held", "please never return")
	done := make(chan error, 1)
	go func() {
		request, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := apply(request, held)
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	select {
	case err = <-done:
		t.Fatal("the held invocation returned", err)
	default:
	}
	fence, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	err = store.Fence(fence, "agent/peer")
	cancel()
	if err == nil {
		t.Fatal("a fence committed in a held store")
	}
	select {
	case err = <-done:
		t.Fatal("the held invocation returned", err)
	default:
	}
	stop()
	select {
	case err = <-done:
		if !errors.Is(err, errHeld) {
			t.Fatal("the held invocation after the harness's stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the harness's stop did not end the held invocation")
	}
	if err = store.Fence(t.Context(), "agent/peer"); err != nil {
		t.Fatal("the store after the harness's stop", err)
	}
	r, err := apply(t.Context(), invocationEvent(t, agent, "ordinary", "an ordinary question"))
	if err != nil || !bytes.Equal(r.Result, []byte(`{"echo":true}`)) {
		t.Fatal("an ordinary invocation", string(r.Result), err)
	}
	r, err = apply(t.Context(), harnessstore.Event{ID: "evt_message", Subjects: []string{"agent/" + agent}, Body: []byte("never return")})
	if err != nil || !bytes.Equal(r.Result, []byte(`{"echo":true}`)) {
		t.Fatal("an event that is no invocation", string(r.Result), err)
	}
}
