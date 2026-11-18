//go:build linux && cgo

package worker

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// contentGuest serves one boot's control protocol and keeps the body of each
// event it receives. acceptJSON is whether its harness accepts JSON content.
func contentGuest(t *testing.T, acceptJSON bool) (*capsuleprotocol.Client, chan []byte) {
	t.Helper()
	h, g, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{AgentID: "a", Incarnation: 1, Generation: 1, VMID: "0123456789abcdef"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	received := make(chan []byte, 4)
	server, err := capsuleprotocol.NewServer(g, capsuleprotocol.ShutdownClean, store, func(_ context.Context, e harnessstore.Event, _ harnessstore.SQL) ([]byte, error) {
		received <- e.Body
		return []byte(`{"received":true}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if acceptJSON {
		server.AcceptJSONContent()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewClient(h, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	// What host.Control does before it returns a session.
	if err = client.RequireControlContract(t.Context()); err != nil {
		t.Fatal(err)
	}
	return client, received
}

// A harness that did not negotiate JSON content gets each JSON part as text,
// never a body it would refuse; one that did gets the JSON value.
func TestDeliveryGivesJSONAsTextToAHarnessWithoutIt(t *testing.T) {
	content := []capsuleprotocol.ContentPart{{Type: "text", Text: "order"}, {Type: "json", JSON: `{"id": 7}`}}
	body, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op_1",
		Mandate: capsuleprotocol.InstructionMandate{ID: "mdt_1", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)}, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	e := harnessstore.Event{ID: "ev1", Subjects: []string{"agent/a", "event/ev1"}, Body: body}
	w := &Placements{}
	for _, accept := range []bool{false, true} {
		client, received := contentGuest(t, accept)
		if _, err = w.deliverToGuest(t.Context(), "a", client, e, true); err != nil {
			t.Fatal(accept, err)
		}
		in, err := capsuleprotocol.DecodeInvocation(harnessstore.Event{ID: e.ID, Subjects: e.Subjects, Body: <-received}, "a")
		if err != nil {
			t.Fatal(err)
		}
		want := capsuleprotocol.ContentPart{Type: "text", Text: `{"id":7}`}
		if accept {
			want = capsuleprotocol.ContentPart{Type: "json", JSON: `{"id":7}`}
		}
		if in.Content[0] != content[0] || in.Content[1] != want {
			t.Fatal(accept, in.Content)
		}
	}
}
