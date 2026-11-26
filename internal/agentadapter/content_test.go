//go:build linux

package agentadapter

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

var rows = capsuleprotocol.ContentPart{Type: "json", JSON: `{"rows":[1,2]}`}

// A call the agent's capabilities do not allow is refused in the terms of
// the agent's SDK, as a permission error, not as an outage to retry.
func TestCapabilityRefusalsAreExplained(t *testing.T) {
	denied := &capsuleprotocol.PlatformError{Code: "capability_denied"}
	if status, kind, _ := explain(denied, "default"); status != 403 || kind != "permission_error" {
		t.Fatal("model call", status, kind)
	}
	if err := sendError(denied); !errors.Is(err, a2a.ErrUnauthorized) {
		t.Fatal("request", err)
	}
	w := httptest.NewRecorder()
	platformStatus(w, denied)
	if w.Code != 403 {
		t.Fatal("card", w.Code)
	}
}

func structuredInvocation(t *testing.T, id string) harnessstore.Event {
	t.Helper()
	b, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op-" + id,
		Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.ContentPart{{Type: "text", Text: "total"}, rows}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: id, Subjects: []string{"agent/a", "event/" + id}, Body: b}
}

// A command reads JSON parts as their compact text; a runner that answers with
// JSON values (an A2A server agent) has them posted as JSON parts.
func TestJSONContentReachesTheRunAndComesBack(t *testing.T) {
	var got Job
	l := newLab(t, func(_ context.Context, j Job) Output {
		got = j
		return Output{Completed: true, Text: "sum", Content: []capsuleprotocol.ContentPart{{Type: "text", Text: "sum"}, {Type: "json", JSON: `{"sum":3}`}}}
	})
	l.deliver(structuredInvocation(t, "e1"))
	l.drain()
	if got.Kind != "invocation" || got.Text != "total\n\n"+`{"rows":[1,2]}` || len(got.Content) != 2 || got.Content[1] != rows {
		t.Fatalf("job %+v", got)
	}
	if len(l.p.completions) != 1 || !reflect.DeepEqual(l.p.completions[0].Content,
		[]capsuleprotocol.ContentPart{{Type: "text", Text: "sum"}, {Type: "json", JSON: `{"sum":3}`}}) {
		t.Fatal(l.p.completions)
	}
	// A request from another agent is answered the same way.
	b, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "request", RequestID: "arq_1", SenderAgentID: "b", RecipientAgentID: "a", Sequence: 1,
		Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.ContentPart{rows}}})
	l.deliver(harnessstore.Event{ID: "p1", Subjects: []string{"agent/a", "agent/b", "request/arq_1", "event/p1"}, Body: b})
	l.drain()
	if got.Kind != "request" || got.Content[0] != rows || len(l.p.replies) != 1 || l.p.replies[0].Payload.Content[1].JSON != `{"sum":3}` {
		t.Fatal(got, l.p.replies)
	}
}

// An answer whose JSON does not fit is posted as its text, never lost.
func TestAnOversizedJSONAnswerFallsBackToText(t *testing.T) {
	big := capsuleprotocol.JSONValue(`"` + stringOf('x', 40<<10) + `"`)
	l := newLab(t, func(context.Context, Job) Output {
		return Output{Completed: true, Text: "the text", Content: []capsuleprotocol.ContentPart{{Type: "json", JSON: big}}}
	})
	l.deliver(invocation(t, "e1", "go"))
	l.drain()
	if len(l.p.completions) != 1 || len(l.p.completions[0].Content) != 1 || l.p.completions[0].Content[0].Text != "the text" {
		t.Fatal(l.p.completions)
	}
}

func stringOf(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// The server runner sends JSON parts to an A2A agent as data parts, and the
// data parts of its answer come back as JSON parts.
func TestServerRunnerSendsAndReceivesDataParts(t *testing.T) {
	var received a2a.ContentParts
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			received = ec.Message.Parts
			for _, e := range []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message),
				a2a.NewArtifactEvent(ec, a2a.NewTextPart("sum"), a2a.NewDataPart(map[string]any{"sum": 3})),
				a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil)} {
				if !yield(e, nil) {
					return
				}
			}
		}
	})
	server := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor)))
	defer server.Close()
	got := ServerRunner(serverConfig(server.URL), ready{})(t.Context(), Job{ID: "op", Text: "total\n\n{\"rows\":[1,2]}",
		Content: []capsuleprotocol.ContentPart{{Type: "text", Text: "total"}, rows}})
	if len(received) != 2 || received[0].Text() != "total" || !reflect.DeepEqual(received[1].Data(), map[string]any{"rows": []any{1.0, 2.0}}) {
		t.Fatalf("message parts %+v", received)
	}
	want := Output{Completed: true, Text: "sum\n\n{\"sum\":3}", Content: []capsuleprotocol.ContentPart{{Type: "text", Text: "sum"}, {Type: "json", JSON: `{"sum":3}`}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

// An agent sends another agent a message with a data part: the request
// carries it as a JSON part, and a JSON reply is a data part of the task's
// artifact.
func TestTheA2AEndpointCarriesDataParts(t *testing.T) {
	var artifact a2a.ContentParts
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		client, _, err := l.client(ctx, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		m := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("check"), a2a.NewDataPart(map[string]any{"order": 7}))
		result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: m,
			Config: &a2a.SendMessageConfig{ReturnImmediately: true, AcceptedOutputModes: []string{"application/json"}}})
		if err != nil {
			t.Error(err)
			return ""
		}
		task := result.(*a2a.Task)
		reply, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "reply", RequestID: string(task.ID), SenderAgentID: "a", RecipientAgentID: "b", Sequence: 1,
			Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.ContentPart{{Type: "text", Text: "ok"}, {Type: "json", JSON: `{"valid":true}`}}}})
		id := "reply-" + string(task.ID)
		l.deliver(harnessstore.Event{ID: id, Subjects: []string{"agent/a", "agent/b", "request/" + string(task.ID), "event/" + id}, Body: reply})
		done, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
		if err != nil || len(done.Artifacts) != 1 {
			t.Error(done, err)
			return ""
		}
		artifact = done.Artifacts[0].Parts
		return "done"
	})
	l.deliver(invocation(t, "e1", "go"))
	l.drain()
	s := l.peers.submissions
	if len(s) != 1 || !reflect.DeepEqual(s[0].Payload.Content, []capsuleprotocol.ContentPart{{Type: "text", Text: "check"}, {Type: "json", JSON: `{"order":7}`}}) {
		t.Fatalf("submission %+v", s)
	}
	if len(artifact) != 2 || artifact[0].Text() != "ok" || !reflect.DeepEqual(artifact[1].Data(), map[string]any{"valid": true}) {
		t.Fatalf("artifact %+v", artifact)
	}
}

func TestStructuredCommandReceivesJobEnvelopeOnStdin(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"version":1,"command":["/bin/cat"],"input":"job-json"}`))
	if err != nil {
		t.Fatal(err)
	}
	run := CommandRunner(cfg, t.TempDir())
	for _, kind := range []string{"invocation", "request"} {
		out := run(t.Context(), Job{Kind: kind, Text: "offer", Content: []capsuleprotocol.ContentPart{rows}})
		var body struct {
			Kind, Text string
			Content    []capsuleprotocol.ContentPart
		}
		if !out.Completed || json.Unmarshal([]byte(out.Text), &body) != nil || body.Kind != kind || body.Text != "offer" || !reflect.DeepEqual(body.Content, []capsuleprotocol.ContentPart{rows}) {
			t.Fatalf("invalid job envelope %s", out.Text)
		}
	}
}
