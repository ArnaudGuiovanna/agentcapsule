package agentadapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// DefaultA2AAddress is the loopback address of the A2A endpoint.
const DefaultA2AAddress = "127.0.0.1:8412"

// PeerPlatform is what the A2A endpoint needs from the platform channel: send
// a request, find and describe the agents the caller may reach, and read the
// state of a request it sent. Every answer is the platform's; the endpoint
// decides nothing.
type PeerPlatform interface {
	Submit(context.Context, string, capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error)
	FindAgents(context.Context, capsuleprotocol.DirectoryQuery) ([]capsuleprotocol.DirectoryAgent, error)
	DescribeAgent(context.Context, string) (capsuleprotocol.DirectoryAgent, error)
	RequestStatus(context.Context, string) (capsuleprotocol.RequestStatus, error)
}

// A2AEndpoint serves the agents of the caller's organization as A2A agents on
// the VM's loopback (A2A 1.0, JSON-RPC binding). Each peer has an Agent Card
// at /agents/<id>/.well-known/agent-card.json and an endpoint at
// /agents/<id>; GET /agents?skill=<OASF id> lists the cards of the agents
// offering a skill (a GET on /agents/<id> also returns its card). A message becomes a request to that agent, sent through
// the platform under the mandate of the invocation that runs now; the task is
// that request, and its reply is the task's artifact.
type A2AEndpoint struct {
	engine   *Engine
	platform PeerPlatform
	base     string
	rpc      http.Handler
	// poll is how often a blocking SendMessage looks at its task; live, how
	// often it asks the platform for the request's state.
	poll, live time.Duration
}

// NewA2AEndpoint returns the A2A endpoint the agent reaches at base, for
// example http://127.0.0.1:8412.
func NewA2AEndpoint(engine *Engine, platform PeerPlatform, base string) (*A2AEndpoint, error) {
	if engine == nil || platform == nil || !strings.HasPrefix(base, "http://") {
		return nil, ErrConfig
	}
	e := &A2AEndpoint{engine: engine, platform: platform, base: strings.TrimSuffix(base, "/"), poll: 250 * time.Millisecond, live: 2 * time.Second}
	e.rpc = a2asrv.NewJSONRPCHandler(peerHandler{e}, a2asrv.WithTransportPanicHandler(func(any) error { return a2a.ErrInternalError }))
	return e, nil
}

// MaxA2ARequestBytes bounds one JSON-RPC request; a message itself is bounded
// by the 64 KiB of a request payload.
const MaxA2ARequestBytes = 256 << 10

type peerKey struct{}

func (e *A2AEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/agents" {
		if r.Method != http.MethodGet {
			plainError(w, http.StatusMethodNotAllowed, "use GET")
			return
		}
		e.list(w, r)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/agents/")
	if !ok {
		plainError(w, http.StatusNotFound, "not found")
		return
	}
	id, card := strings.CutSuffix(rest, a2asrv.WellKnownAgentCardPath)
	if !capsuleprotocol.ValidAgentID(id) || id == e.engine.agent {
		plainError(w, http.StatusNotFound, "no such agent")
		return
	}
	// The card is also served at the endpoint's own address: A2A clients
	// given an address with a path fetch the card from that address.
	if card || r.Method == http.MethodGet {
		if r.Method != http.MethodGet {
			plainError(w, http.StatusMethodNotAllowed, "use GET")
			return
		}
		e.card(w, r, id)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxA2ARequestBytes)
	e.rpc.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, id)))
}

func plainError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// platformStatus turns a refused platform read into an HTTP answer.
func platformStatus(w http.ResponseWriter, err error) {
	var remote *capsuleprotocol.PlatformError
	if errors.As(err, &remote) && remote.Code == "not_found" {
		plainError(w, http.StatusNotFound, "no such agent")
		return
	}
	plainError(w, http.StatusServiceUnavailable, "the platform is unavailable; try again")
}

func (e *A2AEndpoint) card(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	d, err := e.platform.DescribeAgent(ctx, id)
	if err != nil {
		platformStatus(w, err)
		return
	}
	writeJSON(w, e.agentCard(d))
}

func (e *A2AEndpoint) list(w http.ResponseWriter, r *http.Request) {
	var q capsuleprotocol.DirectoryQuery
	for _, s := range r.URL.Query()["skill"] {
		n, err := strconv.Atoi(s)
		if err != nil {
			plainError(w, http.StatusBadRequest, "skill is an OASF skill ID")
			return
		}
		q.Skills = append(q.Skills, n)
	}
	if q.Validate() != nil {
		plainError(w, http.StatusBadRequest, "give one to twenty distinct OASF skill IDs: /agents?skill=10302")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	found, err := e.platform.FindAgents(ctx, q)
	if err != nil {
		platformStatus(w, err)
		return
	}
	cards := make([]*a2a.AgentCard, 0, len(found))
	for _, d := range found {
		if capsuleprotocol.ValidAgentID(d.AgentID) && d.AgentID != e.engine.agent {
			cards = append(cards, e.agentCard(d))
		}
	}
	writeJSON(w, map[string]any{"agents": cards})
}

// oasfSkills names the skills of the interoperability profile.
var oasfSkills = map[int]string{
	10301: "language_processing/language_generation/text_completion",
	10302: "language_processing/language_generation/summarization",
}

func (e *A2AEndpoint) agentCard(d capsuleprotocol.DirectoryAgent) *a2a.AgentCard {
	description := d.Description
	if description == "" {
		description = "An agent of your organization. It has not published a description."
	}
	skills := make([]a2a.AgentSkill, 0, len(d.Skills))
	for _, id := range d.Skills {
		name, ok := oasfSkills[id]
		if !ok {
			name = fmt.Sprintf("OASF skill %d", id)
		}
		skills = append(skills, a2a.AgentSkill{ID: fmt.Sprintf("oasf-%d", id), Name: name,
			Description: "OASF skill " + strconv.Itoa(id) + " (" + name + ").", Tags: []string{"oasf", "oasf:" + strconv.Itoa(id)}})
	}
	if len(skills) == 0 {
		skills = append(skills, a2a.AgentSkill{ID: "text", Name: "Text requests", Description: "Answers a text request with text.", Tags: []string{"text"}})
	}
	return &a2a.AgentCard{
		Name:                d.AgentID,
		Description:         description,
		Version:             "1",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(e.base+"/agents/"+d.AgentID, a2a.TransportProtocolJSONRPC)},
		Capabilities:        a2a.AgentCapabilities{},
		DefaultInputModes:   []string{"text/plain"},
		DefaultOutputModes:  []string{"text/plain"},
		Skills:              skills,
	}
}

// peerHandler implements the A2A methods for the peer named in the request's
// path. Only SendMessage and GetTask are supported.
type peerHandler struct{ e *A2AEndpoint }

var _ a2asrv.RequestHandler = peerHandler{}

func peerFrom(ctx context.Context) string {
	id, _ := ctx.Value(peerKey{}).(string)
	return id
}

func invalid(message string) error { return a2a.NewError(a2a.ErrInvalidParams, message) }

// textContent keeps a message's text parts; anything else is refused.
func textContent(parts a2a.ContentParts) ([]capsuleprotocol.TextContent, error) {
	if len(parts) == 0 {
		return nil, invalid("the message has no part")
	}
	content := make([]capsuleprotocol.TextContent, 0, len(parts))
	for _, p := range parts {
		text, ok := p.Content.(a2a.Text)
		if !ok {
			return nil, a2a.NewError(a2a.ErrUnsupportedContentType, "only text parts are supported")
		}
		content = append(content, capsuleprotocol.TextContent{Type: "text", Text: string(text)})
	}
	if (capsuleprotocol.PeerPayload{Content: content}).Validate() != nil {
		return nil, invalid("a message is 1 to 32 non-empty text parts, at most 64 KiB in all")
	}
	return content, nil
}

// a2aKey is the request's idempotency key: the same message, sent again by the
// same run to the same agent, is the same request.
func a2aKey(work, peer, messageID string) string {
	digest := sha256.Sum256([]byte("agentcapsule-adapter-a2a-v1/" + work + "/" + peer + "/" + messageID))
	return "a2a_" + hex.EncodeToString(digest[:])
}

// sendError explains a refused submission in A2A terms.
func sendError(err error) error {
	var remote *capsuleprotocol.PlatformError
	if !errors.As(err, &remote) {
		return a2a.NewError(a2a.ErrInternalError, "the platform is unavailable; send the same message again")
	}
	switch remote.Code {
	case "not_found":
		return a2a.NewError(a2a.ErrUnauthorized, "this agent does not exist, is not discoverable, or is not of your organization")
	case "mandate":
		return a2a.NewError(a2a.ErrUnauthorized, "this invocation may send no more requests to other agents")
	case "expired":
		return a2a.NewError(a2a.ErrUnauthorized, "this invocation's permission to send requests has expired")
	case "conflict":
		return invalid("this messageId was already sent with other content; use a new messageId")
	case "invalid":
		return invalid("the platform refused this request")
	case "unauthorized":
		return a2a.NewError(a2a.ErrUnauthorized, "this agent may not send requests now")
	case "quota_exceeded", "rate_limited":
		return a2a.NewError(a2a.ErrServerError, "a platform limit refused this request; try again later")
	}
	return a2a.NewError(a2a.ErrInternalError, "the platform is unavailable; send the same message again")
}

func (h peerHandler) SendMessage(ctx context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	e := h.e
	peer := peerFrom(ctx)
	if req == nil || req.Message == nil {
		return nil, invalid("message is required")
	}
	if req.Config != nil && req.Config.PushConfig != nil {
		return nil, a2a.ErrPushNotificationNotSupported
	}
	if req.Config != nil && len(req.Config.AcceptedOutputModes) > 0 && !slices.Contains(req.Config.AcceptedOutputModes, "text/plain") {
		return nil, a2a.NewError(a2a.ErrUnsupportedContentType, "answers are text/plain")
	}
	m := req.Message
	if m.Role != a2a.MessageRoleUser {
		return nil, invalid("the message role must be ROLE_USER")
	}
	if m.ID == "" || len(m.ID) > 200 || len(m.ContextID) > 200 {
		return nil, invalid("messageId is required (at most 200 bytes), contextId at most 200 bytes")
	}
	if m.TaskID != "" {
		return nil, invalid("a task takes one message: send a new message instead of continuing a task")
	}
	content, err := textContent(m.Parts)
	if err != nil {
		return nil, err
	}
	job := e.engine.running.Load()
	if job == nil || job.mandate == nil {
		return nil, a2a.NewError(a2a.ErrUnauthorized, "requests to other agents can only be sent while the agent answers an invocation")
	}
	key := a2aKey(job.work, peer, m.ID)
	encoded, err := json.Marshal(content)
	if err != nil {
		return nil, a2a.ErrInternalError
	}
	contextID := m.ContextID
	if contextID == "" {
		contextID = a2a.NewContextID()
	}
	// The intent is recorded before the platform is called; a retry of the same
	// message finds it, and the platform replays the same request.
	err = e.engine.store.Local(ctx, append(slices.Clone(job.subjects), "agent/"+peer), func(tx harnessstore.SQL) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		var sent []byte
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT content,context_id FROM adapter_a2a_tasks WHERE key=?`, key).Scan(&sent, &existing)
		if err == nil {
			if string(sent) != string(encoded) {
				return errConflict
			}
			contextID = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO adapter_a2a_tasks(key,work,recipient,message_id,context_id,content,updated_ns) VALUES(?,?,?,?,?,?,?)`,
			key, job.work, peer, m.ID, contextID, encoded, time.Now().UnixNano())
		return err
	})
	switch {
	case errors.Is(err, errConflict):
		return nil, invalid("this messageId was already sent with other content; use a new messageId")
	case errors.Is(err, harnessstore.ErrFenced):
		return nil, a2a.NewError(a2a.ErrUnauthorized, "this agent or this invocation has been revoked")
	case err != nil:
		return nil, a2a.ErrInternalError
	}
	submit, cancel := context.WithTimeout(ctx, 30*time.Second)
	receipt, err := e.platform.Submit(submit, key, capsuleprotocol.Submission{RecipientAgentID: peer, MandateID: job.mandate.ID,
		ExpiresAt: job.mandate.ExpiresAt, Payload: &capsuleprotocol.PeerPayload{Content: content}})
	cancel()
	if err != nil {
		return nil, sendError(err)
	}
	if receipt.RequestID == "" || len(receipt.RequestID) > 100 {
		return nil, a2a.ErrInternalError
	}
	err = e.engine.store.Local(ctx, []string{"agent/" + e.engine.agent}, func(tx harnessstore.SQL) error {
		_, err := tx.ExecContext(ctx, `UPDATE adapter_a2a_tasks SET request_id=?,state=CASE WHEN state='' THEN ? ELSE state END,updated_ns=? WHERE key=?`,
			receipt.RequestID, receipt.State, time.Now().UnixNano(), key)
		return err
	})
	if err != nil {
		return nil, a2a.ErrInternalError
	}
	if req.Config != nil && req.Config.ReturnImmediately {
		return e.task(ctx, peer, receipt.RequestID, false)
	}
	// Blocking: wait for an outcome. The request's deadline bounds the wait,
	// since the platform ends a request that outlives it.
	poll := time.NewTicker(e.poll)
	defer poll.Stop()
	asked := time.Now()
	for {
		live := time.Since(asked) >= e.live
		if live {
			asked = time.Now()
		}
		t, err := e.task(ctx, peer, receipt.RequestID, live)
		if err != nil || t.Status.State.Terminal() {
			return t, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-poll.C:
		}
	}
}

var errConflict = errors.New("message already sent with other content")

// taskRow is a request the agent sent, with its outcome once known.
type taskRow struct {
	recipient, messageID, contextID, state, result, reason string
	content, reply                                         []capsuleprotocol.TextContent
	updated                                                int64
}

func (e *A2AEndpoint) load(ctx context.Context, requestID string) (taskRow, error) {
	var t taskRow
	var content, reply []byte
	var result, reason sql.NullString
	var received sql.NullInt64
	err := e.engine.store.Local(ctx, []string{"agent/" + e.engine.agent}, func(tx harnessstore.SQL) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT t.recipient,t.message_id,t.context_id,t.content,t.state,t.updated_ns,r.state,r.reply,r.reason,r.received_ns
            FROM adapter_a2a_tasks t LEFT JOIN adapter_a2a_results r ON r.request_id=t.request_id WHERE t.request_id=?`, requestID).
			Scan(&t.recipient, &t.messageID, &t.contextID, &content, &t.state, &t.updated, &result, &reply, &reason, &received)
	})
	if err != nil {
		return t, err
	}
	t.result, t.reason = result.String, reason.String
	if received.Valid {
		t.updated = received.Int64
	}
	if err = json.Unmarshal(content, &t.content); err != nil {
		return t, err
	}
	if len(reply) > 0 {
		if err = json.Unmarshal(reply, &t.reply); err != nil {
			return t, err
		}
	}
	return t, nil
}

// refresh asks the platform where a request without an outcome stands. A
// refusal leaves the last known state: the platform's notifications remain
// the outcome's source.
func (e *A2AEndpoint) refresh(ctx context.Context, requestID string, t *taskRow) {
	ask, cancel := context.WithTimeout(ctx, 5*time.Second)
	s, err := e.platform.RequestStatus(ask, requestID)
	cancel()
	if err != nil || s.RequestID != requestID || s.State == t.state {
		return
	}
	now := time.Now().UnixNano()
	switch s.State {
	case "PENDING_APPROVAL", "DELIVERING", "PROCESSING", "REPLIED":
		// The reply itself arrives as an event; until then the task is working.
		t.state, t.updated = s.State, now
		_ = e.engine.store.Local(ctx, []string{"agent/" + e.engine.agent}, func(tx harnessstore.SQL) error {
			_, err := tx.ExecContext(ctx, `UPDATE adapter_a2a_tasks SET state=?,updated_ns=? WHERE request_id=?`, s.State, now, requestID)
			return err
		})
	case "DECLINED", "EXPIRED", "CANCELED", "FAILED":
		t.result, t.updated = s.State, now
		_ = e.engine.store.Local(ctx, []string{"agent/" + e.engine.agent}, func(tx harnessstore.SQL) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO adapter_a2a_results(request_id,state,received_ns) VALUES(?,?,?) ON CONFLICT(request_id) DO NOTHING`,
				requestID, s.State, now)
			return err
		})
	}
}

// task returns the A2A view of a request the agent sent to peer.
func (e *A2AEndpoint) task(ctx context.Context, peer, requestID string, live bool) (*a2a.Task, error) {
	t, err := e.load(ctx, requestID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && t.recipient != peer {
		return nil, a2a.ErrTaskNotFound
	}
	if err != nil {
		return nil, a2a.ErrInternalError
	}
	if live && t.result == "" {
		e.refresh(ctx, requestID, &t)
	}
	return taskView(requestID, t), nil
}

// failure says why a task ended without an answer.
var failure = map[string]string{
	"DECLINED": "The recipient side declined the request.",
	"EXPIRED":  "The request reached its deadline without an answer.",
	"CANCELED": "The request was canceled before an answer.",
	"FAILED":   "The request could not be delivered or answered.",
}

func parts(content []capsuleprotocol.TextContent) a2a.ContentParts {
	out := make(a2a.ContentParts, 0, len(content))
	for _, c := range content {
		out = append(out, a2a.NewTextPart(c.Text))
	}
	return out
}

// taskView projects a request on an A2A task (docs/interop.md, "A2A states").
// The platform's own state is repeated in the task's metadata.
func taskView(requestID string, t taskRow) *a2a.Task {
	id := a2a.TaskID(requestID)
	state, internal := a2a.TaskStateSubmitted, t.state
	switch {
	case t.result == "REPLIED":
		state, internal = a2a.TaskStateCompleted, "REPLIED"
	case t.result == "DECLINED":
		state, internal = a2a.TaskStateRejected, t.result
	case t.result == "CANCELED":
		state, internal = a2a.TaskStateCanceled, t.result
	case t.result != "":
		state, internal = a2a.TaskStateFailed, t.result
	case t.state == "PROCESSING", t.state == "REPLIED":
		state = a2a.TaskStateWorking
	}
	if internal == "REPLIED" && t.result == "" {
		internal = "PROCESSING" // replied, but the reply has not arrived yet
	}
	stamp := time.Unix(0, t.updated).UTC()
	view := &a2a.Task{
		ID:        id,
		ContextID: t.contextID,
		Status:    a2a.TaskStatus{State: state, Timestamp: &stamp},
		History: []*a2a.Message{{ID: t.messageID, ContextID: t.contextID, TaskID: id, Role: a2a.MessageRoleUser,
			Parts: parts(t.content)}},
		Metadata: map[string]any{"agentcapsule": map[string]any{"request_state": internal, "recipient_agent_id": t.recipient}},
	}
	if t.reason != "" {
		view.Metadata["agentcapsule"].(map[string]any)["reason"] = t.reason
	}
	if note, ok := failure[t.result]; ok {
		view.Status.Message = &a2a.Message{ID: "status-" + requestID, ContextID: t.contextID, TaskID: id, Role: a2a.MessageRoleAgent,
			Parts: a2a.ContentParts{a2a.NewTextPart(note)}}
	}
	if t.result == "REPLIED" {
		view.Artifacts = []*a2a.Artifact{{ID: "reply", Name: "reply", Parts: parts(t.reply)}}
	}
	return view
}

func (h peerHandler) GetTask(ctx context.Context, req *a2a.GetTaskRequest) (*a2a.Task, error) {
	if req == nil || req.ID == "" || len(req.ID) > 100 {
		return nil, a2a.ErrTaskNotFound
	}
	if req.HistoryLength != nil && *req.HistoryLength < 0 {
		return nil, invalid("historyLength must not be negative")
	}
	t, err := h.e.task(ctx, peerFrom(ctx), string(req.ID), true)
	if err != nil {
		return nil, err
	}
	if req.HistoryLength != nil && *req.HistoryLength == 0 {
		t.History = nil
	}
	return t, nil
}

func (h peerHandler) CancelTask(ctx context.Context, req *a2a.CancelTaskRequest) (*a2a.Task, error) {
	if req == nil || req.ID == "" || len(req.ID) > 100 {
		return nil, a2a.ErrTaskNotFound
	}
	if _, err := h.e.task(ctx, peerFrom(ctx), string(req.ID), false); err != nil {
		return nil, err
	}
	return nil, a2a.NewError(a2a.ErrTaskNotCancelable, "only the sender's owner can cancel a request, through the platform API")
}

func (peerHandler) ListTasks(context.Context, *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	return nil, a2a.ErrUnsupportedOperation
}

func unsupportedStream(err error) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, err) }
}

func (peerHandler) SubscribeToTask(context.Context, *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return unsupportedStream(a2a.ErrUnsupportedOperation)
}

func (peerHandler) SendStreamingMessage(context.Context, *a2a.SendMessageRequest) iter.Seq2[a2a.Event, error] {
	return unsupportedStream(a2a.ErrUnsupportedOperation)
}

func (peerHandler) GetTaskPushConfig(context.Context, *a2a.GetTaskPushConfigRequest) (*a2a.PushConfig, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (peerHandler) ListTaskPushConfigs(context.Context, *a2a.ListTaskPushConfigRequest) (*a2a.ListTaskPushConfigResponse, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (peerHandler) CreateTaskPushConfig(context.Context, *a2a.PushConfig) (*a2a.PushConfig, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (peerHandler) DeleteTaskPushConfig(context.Context, *a2a.DeleteTaskPushConfigRequest) error {
	return a2a.ErrPushNotificationNotSupported
}

func (peerHandler) GetExtendedAgentCard(context.Context, *a2a.GetExtendedAgentCardRequest) (*a2a.AgentCard, error) {
	return nil, a2a.ErrExtendedCardNotConfigured
}
