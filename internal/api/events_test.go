package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

func TestInvocationEventsReplayAndRetention(t *testing.T) {
	f := newRBACFixture(t)
	ctx := t.Context()
	agent := f.ids["agent"]
	token := f.token(t, "user")
	op := f.invoke(t, "user")
	store := f.l.store
	claim, err := store.ClaimPlacement(ctx, agent, "local", "event-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := controlplane.VMCaller{AgentID: agent, HostID: "local", Generation: claim.Generation, VMID: fmt.Sprintf("%016x", claim.Generation)}
	if err = store.ConfirmPlacement(ctx, agent, vm.HostID, "event-worker", vm.Generation, vm.VMID); err != nil {
		t.Fatal(err)
	}
	ack := func(op string, body []byte) {
		t.Helper()
		var mailbox string
		if err := f.db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mailbox); err != nil {
			t.Fatal(err)
		}
		delivery, err := f.transit.ClaimInstruction(ctx, mailbox, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.transit.AuthorizeInstruction(ctx, mailbox, delivery.Token); err != nil {
			t.Fatal(err)
		}
		if err = f.transit.AcknowledgeInstruction(ctx, mailbox, delivery.Token, body); err != nil {
			t.Fatal(err)
		}
	}
	ack(op, capsuleprotocol.WorkingResult())
	if _, err = f.transit.OpenOutputStreamFromVM(ctx, vm, op, 0); err != nil {
		t.Fatal(err)
	}
	limits := controlplane.DefaultStreamLimits
	limits.MaxFrames = 64
	for i := int64(1); i <= 65; i++ {
		frame := capsuleprotocol.OutputFrame{Type: "delta", Seq: i, Text: fmt.Sprintf("secret-%d", i)}
		if i == 2 {
			frame = capsuleprotocol.OutputFrame{Type: "step", Seq: i, Step: "lookup", State: "done"}
		}
		if _, err = f.transit.AppendOutputStreamFromVM(ctx, vm, op, 1, []capsuleprotocol.OutputFrame{frame}, limits); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.transit.CompleteInvocationFromVM(ctx, vm, "finish-events", capsuleprotocol.InvocationCompletion{OperationID: op, Outcome: "completed", Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private outcome"}}})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	metrics := telemetry.NewRegistry()
	f.server.EnableTelemetry(metrics, &logs)
	events := func(op, cursor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/invocations/"+op+"/events", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if cursor != "" {
			req.Header.Set("Last-Event-ID", cursor)
		}
		w := httptest.NewRecorder()
		f.server.ServeHTTP(w, req)
		return w
	}
	w := events(op, "other")
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = events(op, "1:62")
	body := w.Body.String()
	if w.Code != 200 || strings.Count(body, "event: delta") != 2 || !strings.Contains(body, "id: 1:63") || !strings.Contains(body, "event: truncated") || !strings.Contains(body, `"result":{"content"`) || !strings.HasPrefix(body, "event: state") {
		t.Fatal("replay", w.Code, body)
	}
	w = events(op, "2:999")
	body = w.Body.String()
	if strings.Count(body, "event: delta") != 63 || strings.Count(body, "event: step") != 1 || !strings.Contains(body, "event: reset\nid: 1:0") || strings.Index(body, "id: 1:64") > strings.Index(body, "event: truncated") || strings.Index(body, "event: truncated") > strings.Index(body, "event: end") {
		t.Fatal("reset", body)
	}
	retained := func(op string) bool {
		var read bool
		if err := f.db.QueryRow(ctx, "SELECT p.purge_after IS NOT NULL FROM owner_instructions i JOIN transit_payloads p ON p.id=i.result_payload_id WHERE i.operation_id=$1", op).Scan(&read); err != nil {
			t.Fatal(err)
		}
		return read
	}
	if !retained(op) {
		t.Fatal("inline result did not start retention")
	}
	large := f.invoke(t, "user")
	ack(large, []byte(`{"content":[{"type":"text","text":"`+strings.Repeat("a", 32<<10)+`"}]}`))
	w = events(large, "")
	body = w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `"result_available":true`) || strings.Contains(body, `"content"`) || retained(large) {
		t.Fatal("large result retention", w.Code, body)
	}
	var exp bytes.Buffer
	if _, err = metrics.WriteTo(&exp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(exp.String()+logs.String(), "secret-") || strings.Contains(logs.String(), "private outcome") || strings.Contains(exp.String(), `agentcapsule_api_request_duration_seconds_count{route="/v1/invocations/{id}/events"}`) || !strings.Contains(exp.String(), `agentcapsule_api_requests_total{route="/v1/invocations/{id}/events",method="GET",status_class="2xx"} 3`) {
		t.Fatal("event telemetry", logs.String())
	}
}

func TestInvocationEventsRevokeAndCapacity(t *testing.T) {
	f := newRBACFixture(t)
	token := f.token(t, "user")
	op := f.invoke(t, "user")
	other := f.invoke(t, "user")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := f.server.StartEventStreams(ctx, 4); err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(f.server)
	defer h.Close()
	c := &http.Client{Timeout: 9 * time.Second}
	open := func(op string) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, "GET", h.URL+"/v1/invocations/"+op+"/events", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	var readers []*bufio.Reader
	for i := 0; i < 4; i++ {
		res := open(op)
		defer res.Body.Close()
		read := bufio.NewReader(res.Body)
		readers = append(readers, read)
		first, err := read.ReadString('\n')
		if err != nil || res.StatusCode != 200 || first != "event: state\n" {
			t.Fatal(res.StatusCode, first, err)
		}
	}
	for id, want := range map[string]int{op: 429, other: 503} {
		res := open(id)
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != want {
			t.Fatal(want, res.StatusCode, string(body), err)
		}
	}
	var assignment string
	if err := f.db.QueryRow(ctx, "SELECT id FROM agent_assignments WHERE agent_id=$1 AND principal_id=$2 AND status='active'", f.ids["agent"], f.ids["user_principal"]).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	f.must(t, "owner", "POST", "/v1/agents/"+f.ids["agent"]+"/assignments/"+assignment+"/revoke", "{}", 200, nil)
	for _, read := range readers {
		body, err := io.ReadAll(read)
		if err != nil || !strings.HasSuffix(string(body), "event: revoked\ndata: {}\n\n") {
			t.Fatal("live revocation", string(body), err)
		}
	}
}
