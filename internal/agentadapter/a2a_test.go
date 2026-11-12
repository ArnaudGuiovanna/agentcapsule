//go:build linux

package agentadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// peers is the platform side of the A2A endpoint: agent b is described,
// agent c is discoverable but never described, anything else is unknown.
type peers struct {
	mu          sync.Mutex
	submissions []capsuleprotocol.Submission
	keys        []string
	byKey       map[string]string
	states      map[string]string
	code        string          // a refusal of every submission
	statusDown  bool            // RequestStatus answers "unavailable"
	onSubmit    func(id string) // called once per new request, outside the lock
	searches    []capsuleprotocol.DirectoryQuery
}

func newPeers() *peers { return &peers{byKey: map[string]string{}, states: map[string]string{}} }

func (p *peers) Submit(_ context.Context, key string, in capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	p.mu.Lock()
	if p.code != "" {
		p.mu.Unlock()
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: p.code}
	}
	if in.Payload == nil || in.Payload.Validate() != nil || in.MandateID == "" || in.ExpiresAt.IsZero() {
		p.mu.Unlock()
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "invalid"}
	}
	p.keys = append(p.keys, key)
	if id, ok := p.byKey[key]; ok {
		state := p.states[id]
		p.mu.Unlock()
		return capsuleprotocol.PlatformReceipt{RequestID: id, State: state, Replayed: true}, nil
	}
	id := fmt.Sprintf("arq_%d", len(p.byKey)+1)
	p.byKey[key], p.states[id] = id, "PENDING_APPROVAL"
	p.submissions = append(p.submissions, in)
	on := p.onSubmit
	p.mu.Unlock()
	if on != nil {
		on(id)
	}
	return capsuleprotocol.PlatformReceipt{RequestID: id, State: "PENDING_APPROVAL"}, nil
}

func (p *peers) set(id, state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.states[id] = state
}

func (p *peers) FindAgents(_ context.Context, q capsuleprotocol.DirectoryQuery) ([]capsuleprotocol.DirectoryAgent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.searches = append(p.searches, q)
	return []capsuleprotocol.DirectoryAgent{{AgentID: "b", Description: "Summarizes long documents.", Skills: []int{10302}, Domains: []int{111}}}, nil
}

func (p *peers) DescribeAgent(_ context.Context, id string) (capsuleprotocol.DirectoryAgent, error) {
	switch id {
	case "b":
		return capsuleprotocol.DirectoryAgent{AgentID: "b", Description: "Summarizes long documents.", Skills: []int{10302}, Domains: []int{111}}, nil
	case "c":
		return capsuleprotocol.DirectoryAgent{AgentID: "c", Skills: []int{}, Domains: []int{}}, nil
	}
	return capsuleprotocol.DirectoryAgent{}, &capsuleprotocol.PlatformError{Code: "not_found"}
}

func (p *peers) RequestStatus(_ context.Context, id string) (capsuleprotocol.RequestStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.statusDown {
		return capsuleprotocol.RequestStatus{}, &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	state, ok := p.states[id]
	if !ok {
		return capsuleprotocol.RequestStatus{}, &capsuleprotocol.PlatformError{Code: "not_found"}
	}
	return capsuleprotocol.RequestStatus{RequestID: id, RecipientAgentID: "b", State: state, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type a2aLab struct {
	*lab
	peers *peers
	url   string
}

// newA2ALab serves agent a's A2A endpoint; agent is the program each job
// runs, which may use an A2A client against the endpoint.
func newA2ALab(t *testing.T, agent func(ctx context.Context, l *a2aLab, j Job) string) *a2aLab {
	t.Helper()
	l := &a2aLab{peers: newPeers()}
	l.lab = newLab(t, func(ctx context.Context, j Job) Output {
		return Output{Completed: true, Text: agent(ctx, l, j)}
	})
	var endpoint *A2AEndpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { endpoint.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	var err error
	if endpoint, err = NewA2AEndpoint(l.engine, l.peers, server.URL); err != nil {
		t.Fatal(err)
	}
	endpoint.poll, endpoint.live = 5*time.Millisecond, 20*time.Millisecond
	l.url = server.URL
	return l
}

// client resolves a peer's Agent Card as an A2A client does, and connects.
func (l *a2aLab) client(ctx context.Context, peer string) (*a2aclient.Client, *a2a.AgentCard, error) {
	card, err := agentcard.DefaultResolver.Resolve(ctx, l.url+"/agents/"+peer, agentcard.WithPath(a2asrv.WellKnownAgentCardPath))
	if err != nil {
		return nil, nil, err
	}
	c, err := a2aclient.NewFromCard(ctx, card)
	return c, card, err
}

func text(s string) *a2a.Message { return a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(s)) }

func replyEvent(requestID, answer string) harnessstore.Event {
	b, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "reply", RequestID: requestID, SenderAgentID: "a", RecipientAgentID: "b", Sequence: 1,
		Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: answer}}}})
	return harnessstore.Event{ID: "reply-" + requestID, Subjects: []string{"agent/a", "agent/b", "request/" + requestID, "event/reply-" + requestID}, Body: b}
}

// statusEvent is a terminal notification in the host's own encoding
// (controlplane.ClaimDelivery): Go field names, no JSON tags.
func statusEvent(requestID, status, reason string) harnessstore.Event {
	b, _ := json.Marshal(struct {
		Kind, RequestID, PayloadRef, PayloadHash, Status, Reason string
		Sequence                                                 int64
	}{"status", requestID, "", "", status, reason, 2})
	id := "status-" + requestID
	return harnessstore.Event{ID: id, Subjects: []string{"agent/a", "notification/" + id, "event/" + id}, Body: b}
}

func state(t *a2a.Task) string {
	return string(t.Status.State) + "/" + t.Metadata["agentcapsule"].(map[string]any)["request_state"].(string)
}

// An unmodified agent with the official A2A Go SDK finds agent b's card, sends
// it a message while it answers an invocation, and follows the task from the
// recipient's consent to its reply, which is the task's artifact.
func TestTheOfficialA2AClientSendsARequestAndGetsTheReply(t *testing.T) {
	var log []string
	var taskID a2a.TaskID
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		client, card, err := l.client(ctx, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		if card.Name != "b" || card.Description != "Summarizes long documents." || len(card.Skills) != 1 || card.Skills[0].ID != "oasf-10302" ||
			card.Capabilities.Streaming || card.Capabilities.PushNotifications || card.SupportedInterfaces[0].URL != l.url+"/agents/b" ||
			card.SupportedInterfaces[0].ProtocolBinding != a2a.TransportProtocolJSONRPC || card.SupportedInterfaces[0].ProtocolVersion != "1.0" {
			t.Errorf("card %+v", card)
		}
		m := text("summarize: " + j.Text)
		m.ContextID = "mission-1"
		result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: m, Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
		if err != nil {
			t.Error(err)
			return ""
		}
		task := result.(*a2a.Task)
		taskID = task.ID
		log = append(log, state(task))
		if task.ContextID != "mission-1" || len(task.History) != 1 || task.History[0].Parts[0].Content != a2a.Text("summarize: "+j.Text) {
			t.Errorf("task %+v", task)
		}
		// The same message sent again is the same request.
		again, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: m, Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
		if err != nil || again.(*a2a.Task).ID != task.ID {
			t.Error("a resent message made another task", err)
		}
		for _, step := range []string{"DELIVERING", "PROCESSING", "REPLIED"} {
			l.peers.set(string(task.ID), step)
			got, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
			if err != nil {
				t.Error(err)
				return ""
			}
			log = append(log, state(got))
		}
		l.deliver(replyEvent(string(task.ID), "a short summary"))
		done, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
		if err != nil {
			t.Error(err)
			return ""
		}
		log = append(log, state(done))
		if len(done.Artifacts) != 1 || done.Artifacts[0].Parts[0].Content != a2a.Text("a short summary") {
			t.Errorf("artifacts %+v", done.Artifacts)
		}
		return "b says: a short summary"
	})
	l.deliver(invocation(t, "e1", "the report"))
	l.drain()
	want := "TASK_STATE_SUBMITTED/PENDING_APPROVAL TASK_STATE_SUBMITTED/DELIVERING TASK_STATE_WORKING/PROCESSING TASK_STATE_WORKING/PROCESSING TASK_STATE_COMPLETED/REPLIED"
	if strings.Join(log, " ") != want {
		t.Fatalf("states\n got %s\nwant %s", strings.Join(log, " "), want)
	}
	s := l.peers.submissions
	if len(s) != 1 || s[0].RecipientAgentID != "b" || s[0].MandateID != "grant" || s[0].Payload.Content[0].Text != "summarize: the report" {
		t.Fatalf("submission %+v", s)
	}
	if len(l.peers.keys) != 2 || l.peers.keys[0] != l.peers.keys[1] || !strings.HasPrefix(l.peers.keys[0], "a2a_") {
		t.Fatal("keys", l.peers.keys)
	}
	if len(l.p.completions) != 1 || l.p.completions[0].Content[0].Text != "b says: a short summary" {
		t.Fatal(l.p.completions)
	}
	// The task outlives the run: a later invocation, or the next boot, reads it.
	client, _, err := l.client(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	later, err := client.GetTask(t.Context(), &a2a.GetTaskRequest{ID: taskID, HistoryLength: new(int)})
	if err != nil || later.Status.State != a2a.TaskStateCompleted || len(later.History) != 0 {
		t.Fatal(later, err)
	}
}

// A blocking SendMessage (the A2A default) returns once the request has an
// outcome.
func TestABlockingMessageWaitsForTheOutcome(t *testing.T) {
	var got *a2a.Task
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		client, _, err := l.client(ctx, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: text(j.Text)})
		if err != nil {
			t.Error(err)
			return ""
		}
		got = result.(*a2a.Task)
		return "done"
	})
	l.peers.onSubmit = func(id string) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			l.peers.set(id, "PROCESSING")
			time.Sleep(50 * time.Millisecond)
			l.peers.set(id, "REPLIED")
			if _, err := l.store.Apply(context.Background(), replyEvent(id, "the answer"), func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
				return l.engine.Handle(ctx, replyEvent(id, "the answer"), tx)
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	l.deliver(invocation(t, "e1", "a question"))
	l.drain()
	if got == nil || got.Status.State != a2a.TaskStateCompleted || got.Artifacts[0].Parts[0].Content != a2a.Text("the answer") {
		t.Fatalf("%+v", got)
	}
}

// Ends without a reply: declined by the recipient side (a notification), and
// expired (read from the platform while the notification is on its way).
func TestRequestsThatEndWithoutAReply(t *testing.T) {
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		client, _, err := l.client(ctx, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		declined, _ := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: text("first"), Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
		expired, _ := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: text("second"), Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
		if declined == nil || expired == nil {
			t.Error("not sent")
			return ""
		}
		d, e := declined.(*a2a.Task).ID, expired.(*a2a.Task).ID
		l.peers.set(string(d), "DECLINED")
		l.deliver(statusEvent(string(d), "DECLINED", ""))
		l.peers.set(string(e), "EXPIRED")
		var out []string
		for _, id := range []a2a.TaskID{d, e} {
			task, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: id})
			if err != nil {
				t.Error(err)
				return ""
			}
			if task.Status.Message == nil || task.Status.Message.Role != a2a.MessageRoleAgent || len(task.Artifacts) != 0 {
				t.Errorf("%+v", task)
			}
			out = append(out, state(task))
		}
		// The platform no longer answers: the state already known stays.
		l.peers.statusDown = true
		if task, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: e}); err != nil || task.Status.State != a2a.TaskStateFailed {
			t.Error("known outcome lost", task, err)
		}
		return strings.Join(out, " ")
	})
	l.deliver(invocation(t, "e1", "go"))
	l.drain()
	if len(l.p.completions) != 1 || l.p.completions[0].Content[0].Text != "TASK_STATE_REJECTED/DECLINED TASK_STATE_FAILED/EXPIRED" {
		t.Fatal(l.p.completions)
	}
}

// The endpoint sends nothing it may not: outside an invocation, while
// answering another agent, past the mandate, or anything but text; it serves
// no card for itself or an unknown agent, and no task of another peer.
func TestTheA2AEndpointRefusals(t *testing.T) {
	type refusal struct {
		name string
		err  error
	}
	var refusals []refusal
	check := func(name string, err, want error) {
		if !errors.Is(err, want) {
			refusals = append(refusals, refusal{name, err})
		}
	}
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		client, _, err := l.client(ctx, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		send := func(m *a2a.Message, cfg *a2a.SendMessageConfig) error {
			_, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: m, Config: cfg})
			return err
		}
		if j.ID == "arq_in" { // answering another agent's request: no mandate
			check("from a peer request", send(text("onward"), nil), a2a.ErrUnauthorized)
			return "no"
		}
		data := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(map[string]any{"k": 1}))
		check("data part", send(data, nil), a2a.ErrUnsupportedContentType)
		followUp := text("more")
		followUp.TaskID = "arq_1"
		check("follow-up", send(followUp, nil), a2a.ErrInvalidParams)
		agentRole := a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("x"))
		check("agent role", send(agentRole, nil), a2a.ErrInvalidParams)
		check("empty", send(text("   "), nil), a2a.ErrInvalidParams)
		check("too large", send(text(strings.Repeat("x", 70<<10)), nil), a2a.ErrInvalidParams)
		check("push", send(text("x"), &a2a.SendMessageConfig{PushConfig: &a2a.PushConfig{URL: "http://127.0.0.1:1"}}), a2a.ErrPushNotificationNotSupported)
		check("output mode", send(text("x"), &a2a.SendMessageConfig{AcceptedOutputModes: []string{"image/png"}}), a2a.ErrUnsupportedContentType)
		first := text("one")
		if err := send(first, &a2a.SendMessageConfig{ReturnImmediately: true}); err != nil {
			t.Error(err)
		}
		reused := text("other content")
		reused.ID = first.ID
		check("messageId reused", send(reused, nil), a2a.ErrInvalidParams)
		l.peers.code = "mandate"
		check("mandate used up", send(text("two"), nil), a2a.ErrUnauthorized)
		l.peers.code = "not_found"
		check("hidden recipient", send(text("three"), nil), a2a.ErrUnauthorized)
		l.peers.code = "unavailable"
		check("platform down", send(text("four"), nil), a2a.ErrInternalError)
		l.peers.code = ""
		_, err = client.CancelTask(ctx, &a2a.CancelTaskRequest{ID: "arq_1"})
		check("cancel", err, a2a.ErrTaskNotCancelable)
		_, err = client.ListTasks(ctx, &a2a.ListTasksRequest{})
		check("list", err, a2a.ErrUnsupportedOperation)
		// The official client does not stream from a card without streaming;
		// a client that asks anyway is refused before anything is sent.
		r, err := http.Post(l.url+"/agents/b", "application/json", strings.NewReader(
			`{"jsonrpc":"2.0","id":7,"method":"SendStreamingMessage","params":{"message":{"messageId":"s","role":"ROLE_USER","parts":[{"text":"stream"}]}}}`))
		if err != nil {
			t.Error(err)
			return ""
		}
		streamed, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if !strings.Contains(string(streamed), "-32004") {
			t.Error("stream", string(streamed))
		}
		// Agent c is reachable too, but b's task is not c's.
		other, _, err := l.client(ctx, "c")
		if err != nil {
			t.Error(err)
			return ""
		}
		_, err = other.GetTask(ctx, &a2a.GetTaskRequest{ID: "arq_1"})
		check("another peer's task", err, a2a.ErrTaskNotFound)
		_, err = client.GetTask(ctx, &a2a.GetTaskRequest{ID: "arq_404"})
		check("unknown task", err, a2a.ErrTaskNotFound)
		return "ok"
	})
	// Outside any run.
	client, _, err := l.client(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendMessage(t.Context(), &a2a.SendMessageRequest{Message: text("idle")})
	check("outside a run", err, a2a.ErrUnauthorized)
	l.deliver(invocation(t, "e1", "go"))
	b, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "request", RequestID: "arq_in", SenderAgentID: "b", RecipientAgentID: "a", Sequence: 1,
		Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "a question from b"}}}})
	l.deliver(harnessstore.Event{ID: "p1", Subjects: []string{"agent/a", "agent/b", "request/arq_in", "event/p1"}, Body: b})
	l.drain()
	for _, r := range refusals {
		t.Errorf("%s: %v", r.name, r.err)
	}
	if len(l.peers.submissions) != 1 {
		t.Fatal("refused messages reached the platform", l.peers.submissions)
	}
	if card, _, err := l.client(t.Context(), "c"); err != nil || card == nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/agents/a/.well-known/agent-card.json", "/agents/z/.well-known/agent-card.json", "/agents/a", "/agents/b%2Fc", "/other"} {
		r, err := http.Get(l.url + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatal(path, r.Status)
		}
	}
}

// The card of an agent that never published a description says so; a client
// given the endpoint's own address finds the card there.
func TestCardsAndDiscovery(t *testing.T) {
	l := newA2ALab(t, func(context.Context, *a2aLab, Job) string { return "" })
	card, err := agentcard.DefaultResolver.Resolve(t.Context(), l.url+"/agents/c")
	if err != nil || card.Name != "c" || !strings.Contains(card.Description, "not published") || len(card.Skills) != 1 || card.Skills[0].ID != "text" {
		t.Fatal(card, err)
	}
	r, err := http.Get(l.url + "/agents?skill=10302&skill=10301")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var list struct{ Agents []*a2a.AgentCard }
	if r.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Agents) != 1 || list.Agents[0].Name != "b" ||
		list.Agents[0].SupportedInterfaces[0].URL != l.url+"/agents/b" {
		t.Fatal(r.Status, string(body))
	}
	if q := l.peers.searches; len(q) != 1 || len(q[0].Skills) != 2 {
		t.Fatal(q)
	}
	for _, bad := range []string{"/agents", "/agents?skill=x", "/agents?skill=0", "/agents?skill=1&skill=1"} {
		r, err := http.Get(l.url + bad)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatal(bad, r.Status)
		}
	}
}

// The host's terminal notification stops an unanswered request from another
// agent; its Go field names used to go unread.
func TestTheHostStatusNotificationStopsAnUnansweredRequest(t *testing.T) {
	l := newLab(t, nil)
	b, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "request", RequestID: "arq_1", SenderAgentID: "b", RecipientAgentID: "a", Sequence: 1,
		Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "late"}}}})
	l.deliver(harnessstore.Event{ID: "p1", Subjects: []string{"agent/a", "agent/b", "request/arq_1", "event/p1"}, Body: b})
	l.deliver(statusEvent("arq_1", "EXPIRED", "deadline"))
	l.drain()
	if len(l.runs) != 0 || len(l.p.replies) != 0 {
		t.Fatal("an ended request ran", l.runs, l.p.replies)
	}
}

// An agent that is itself an A2A server, built with the official SDK, answers
// an invocation by asking agent b through the adapter's A2A endpoint: A2A on
// both sides of the adapter, under the invocation's mandate.
func TestAServerAgentAsksAnotherAgentOverA2A(t *testing.T) {
	var endpoint string
	executor := a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			question := string(ec.Message.Parts[0].Content.(a2a.Text))
			answer := "no answer"
			card, err := agentcard.DefaultResolver.Resolve(ctx, endpoint+"/agents/b")
			if err == nil {
				var client *a2aclient.Client
				if client, err = a2aclient.NewFromCard(ctx, card); err == nil {
					var result a2a.SendMessageResult
					if result, err = client.SendMessage(ctx, &a2a.SendMessageRequest{Message: text(question)}); err == nil {
						if task, ok := result.(*a2a.Task); ok && len(task.Artifacts) == 1 {
							answer = "b says: " + string(task.Artifacts[0].Parts[0].Content.(a2a.Text))
						}
					}
				}
			}
			if err != nil {
				answer = "error: " + err.Error()
			}
			for _, e := range []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message), a2a.NewArtifactEvent(ec, a2a.NewTextPart(answer)),
				a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil)} {
				if !yield(e, nil) {
					return
				}
			}
		}
	})
	agent := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor)))
	defer agent.Close()
	run := ServerRunner(serverConfig(agent.URL), ready{})
	l := newA2ALab(t, func(ctx context.Context, _ *a2aLab, j Job) string { return run(ctx, j).Text })
	endpoint = l.url
	l.peers.onSubmit = func(id string) {
		go func() {
			l.peers.set(id, "REPLIED")
			e := replyEvent(id, "forty-two")
			if _, err := l.store.Apply(context.Background(), e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
				return l.engine.Handle(ctx, e, tx)
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	l.deliver(invocation(t, "e1", "what is the answer?"))
	l.drain()
	if len(l.p.completions) != 1 || l.p.completions[0].Content[0].Text != "b says: forty-two" {
		t.Fatal(l.p.completions)
	}
	if s := l.peers.submissions; len(s) != 1 || s[0].Payload.Content[0].Text != "what is the answer?" || s[0].MandateID != "grant" {
		t.Fatal(s)
	}
}
