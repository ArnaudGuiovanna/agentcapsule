// Package referenceharness implements the deterministic reference companion.
// It deliberately echoes peer data; it never interprets it as owner authority.
package referenceharness

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type Platform interface {
	Submit(context.Context, string, capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error)
	Reply(context.Context, string, string, capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error)
	PostOwner(context.Context, string, capsuleprotocol.OwnerPost) (capsuleprotocol.OwnerPostReceipt, error)
}

// WorkPlatform is what the harness needs to finish an invocation after
// acknowledging it "working": the delivery itself holds an exclusive host turn,
// so these calls only succeed afterwards, from Step.
type WorkPlatform interface {
	FetchAttachment(context.Context, capsuleprotocol.AttachmentRef) ([]byte, error)
	CompleteLLM(context.Context, string, capsuleprotocol.LLMRequest) (capsuleprotocol.LLMResult, error)
	CompleteInvocation(context.Context, string, capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error)
}

// invocationWork is an invocation answered later. Result is persisted once
// computed, so a retried completion never fetches or calls the model again.
type invocationWork struct {
	OperationID string                          `json:"operation_id"`
	Attachments []capsuleprotocol.AttachmentRef `json:"attachments,omitempty"`
	Alias       string                          `json:"alias,omitempty"`
	Prompt      string                          `json:"prompt,omitempty"`
	Result      []capsuleprotocol.TextContent   `json:"result,omitempty"`
}

type Engine struct {
	agent    string
	store    *harnessstore.Store
	platform Platform
	mu       sync.Mutex
}

func New(agent string, store *harnessstore.Store, platform Platform) (*Engine, error) {
	if agent == "" || store == nil {
		return nil, capsuleprotocol.ErrProtocol
	}
	return &Engine{agent: agent, store: store, platform: platform}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS echo_events(event_id TEXT PRIMARY KEY, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS reference_outgoing(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 request_id TEXT NOT NULL,
 subjects BLOB NOT NULL,
 body BLOB NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','done','stopped')),
 attempts INTEGER NOT NULL DEFAULT 0,
 next_ns INTEGER NOT NULL DEFAULT 0,
 receipt BLOB,
 reason TEXT NOT NULL DEFAULT ''
);`

type work struct {
	Kind         string                      `json:"kind"`
	RequestID    string                      `json:"request_id,omitempty"`
	Submission   *capsuleprotocol.Submission `json:"submission,omitempty"`
	Reply        *capsuleprotocol.Reply      `json:"reply,omitempty"`
	OwnerMessage *capsuleprotocol.OwnerPost  `json:"owner_message,omitempty"`
	Invocation   *invocationWork             `json:"invocation,omitempty"`
}

func enqueue(ctx context.Context, tx harnessstore.SQL, e harnessstore.Event, w work) error {
	body, err := json.Marshal(w)
	if err != nil {
		return err
	}
	subjects, err := json.Marshal(e.Subjects)
	if err != nil {
		return err
	}
	// Domain separation and an immutable incoming event give one durable key
	// per business effect, independent of boot, retries and wall clock.
	digest := sha256.Sum256([]byte("reference-outgoing-v1/" + w.Kind + "/" + e.ID))
	_, err = tx.ExecContext(ctx, `INSERT INTO reference_outgoing(id,request_id,subjects,body) VALUES(?,?,?,?)`,
		"ref_"+hex.EncodeToString(digest[:]), w.RequestID, subjects, body)
	return err
}

// Handle runs inside Store.Apply. Effect, outgoing intent and replayable ACK
// commit together. It never calls Platform or waits for a remote operation.
func (h *Engine) Handle(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO echo_events(event_id,body) VALUES(?,?)", e.ID, e.Body); err != nil {
		return nil, err
	}
	var kind struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(e.Body, &kind)
	switch kind.Kind {
	case "message.user":
		in, err := capsuleprotocol.DecodeInvocation(e, h.agent)
		if err != nil {
			return nil, err
		}
		llm := len(in.Content) == 1 && strings.HasPrefix(in.Content[0].Text, "/llm ")
		if llm || len(in.Attachments) > 0 {
			if _, ok := h.platform.(WorkPlatform); !ok {
				return ownerText("The platform channel is unavailable; files and model cannot be reached.")
			}
			iw := invocationWork{OperationID: in.OperationID, Attachments: in.Attachments}
			if llm {
				alias, prompt, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(in.Content[0].Text, "/llm ")), " ")
				if alias == "" || strings.TrimSpace(prompt) == "" {
					return ownerText("Usage: /llm <alias> <text>.")
				}
				iw.Alias, iw.Prompt = alias, strings.TrimSpace(prompt)
			}
			if err = enqueue(ctx, tx, e, work{Kind: "invocation", Invocation: &iw}); err != nil {
				return nil, err
			}
			// Delivery ends here; the answer follows from Step.
			return capsuleprotocol.WorkingResult(), nil
		}
		if len(in.Content) == 1 && strings.HasPrefix(in.Content[0].Text, "/ask ") {
			rest := strings.TrimSpace(strings.TrimPrefix(in.Content[0].Text, "/ask "))
			target, question, ok := strings.Cut(rest, " ")
			question = strings.TrimSpace(question)
			if !ok || target == "" || target == h.agent || len(target) > 100 || strings.ContainsAny(target, "\t\r\n/") || question == "" {
				return ownerText("Usage: /ask <agent-id> <text>, with another agent.")
			}
			if h.platform == nil {
				return ownerText("The platform channel is unavailable; no request was prepared.")
			}
			submission := capsuleprotocol.Submission{RecipientAgentID: target, MandateID: in.Mandate.ID,
				ExpiresAt: in.Mandate.ExpiresAt,
				Payload:   &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: question}}}}
			if err = enqueue(ctx, tx, e, work{Kind: "submit", Submission: &submission}); err != nil {
				return nil, err
			}
			return ownerText("Request recorded for " + target + ". Sending and consent are still pending.")
		}
		return json.Marshal(capsuleprotocol.OwnerMessage{Content: in.Content})
	case "request", "reply":
		peer, err := capsuleprotocol.DecodePeerEvent(e, h.agent)
		if err != nil {
			return nil, err
		}
		if peer.Kind == "request" {
			if h.platform == nil {
				return nil, capsuleprotocol.ErrTransport
			}
			// The echo policy discloses only the received text. In particular,
			// an /ask string here cannot create a submission or use a mandate.
			if err = enqueue(ctx, tx, e, work{Kind: "reply", RequestID: peer.RequestID,
				Reply: &capsuleprotocol.Reply{Outcome: "completed", Payload: &peer.Payload}}); err != nil {
				return nil, err
			}
		} else {
			if h.platform == nil {
				return nil, capsuleprotocol.ErrTransport
			}
			message := capsuleprotocol.OwnerPost{RequestID: peer.RequestID, Content: peer.Payload.Content}
			if message.Validate() != nil {
				// The owner-message limit is smaller than a peer payload. Keep
				// the request link and an honest notice rather than losing the ACK.
				message.Content = []capsuleprotocol.TextContent{{Type: "text", Text: "Reply received. Its full content is available in the request."}}
			}
			if err = enqueue(ctx, tx, e, work{Kind: "owner", RequestID: peer.RequestID, OwnerMessage: &message}); err != nil {
				return nil, err
			}
		}
		return []byte(`{"received":true}`), nil
	case "status":
		var status struct {
			Kind, RequestID, PayloadRef, PayloadHash, Status, Reason string
			Sequence                                                 int64
		}
		if err := json.Unmarshal(e.Body, &status); err != nil {
			return nil, err
		}
		if status.RequestID == "" || status.PayloadRef != "" || status.PayloadHash != "" || status.Sequence < 1 ||
			!slices.Contains([]string{"REPLIED", "DECLINED", "EXPIRED", "CANCELED", "FAILED"}, status.Status) || len(e.Subjects) != 3 {
			return nil, capsuleprotocol.ErrProtocol
		}
		for _, subject := range []string{"agent/" + h.agent, "event/" + e.ID, "notification/" + e.ID} {
			if !slices.Contains(e.Subjects, subject) {
				return nil, capsuleprotocol.ErrProtocol
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE reference_outgoing SET state='stopped',reason='request_terminal' WHERE request_id=? AND state='pending'`, status.RequestID); err != nil {
			return nil, err
		}
		return []byte(`{"received":true}`), nil
	default:
		// Generic control-only echo fixtures have no application authority.
		return json.Marshal(struct {
			Echo []byte `json:"echo"`
		}{e.Body})
	}
}

func ownerText(text string) ([]byte, error) {
	return json.Marshal(capsuleprotocol.OwnerMessage{Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}})
}

// Step attempts one eligible persisted operation. SQL locks are released before
// the RPC. The host rechecks boot/mandate/request authority inside its own commit.
// A crash or an ambiguous RPC leaves the SAME body and key available to retry.
func (h *Engine) Step(ctx context.Context) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.platform == nil {
		return false, nil
	}
	var id string
	var body, encodedSubjects []byte
	var attempts int
	err := h.store.Local(ctx, []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT id,subjects,body,attempts FROM reference_outgoing WHERE state='pending' AND next_ns<=? ORDER BY seq LIMIT 1`, time.Now().UnixNano()).Scan(&id, &encodedSubjects, &body, &attempts)
	})
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, harnessstore.ErrFenced) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var subjects []string
	var w work
	if err = json.Unmarshal(encodedSubjects, &subjects); err != nil {
		return false, err
	}
	if err = json.Unmarshal(body, &w); err != nil {
		return false, err
	}
	// Retry delay is scheduling only, never authorization. Persist it before
	// network I/O so an unavailable peer cannot monopolize the local queue.
	delay := time.Duration(1<<min(attempts, 4)) * 250 * time.Millisecond
	err = h.store.Local(ctx, subjects, func(tx harnessstore.SQL) error {
		tag, err := tx.ExecContext(ctx, `UPDATE reference_outgoing SET attempts=attempts+1,next_ns=? WHERE id=? AND state='pending'`, time.Now().Add(delay).UnixNano(), id)
		if err != nil {
			return err
		}
		n, err := tag.RowsAffected()
		if err == nil && n == 0 {
			return sql.ErrNoRows
		}
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if errors.Is(err, harnessstore.ErrFenced) {
		return true, h.finish(ctx, id, nil, "local_revocation")
	}
	if err != nil {
		return false, err
	}
	var receipt capsuleprotocol.PlatformReceipt
	var result []byte
	timeout := 15 * time.Second
	if w.Kind == "invocation" {
		timeout = 4 * time.Minute // attachments and a model call
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch {
	case w.Kind == "invocation" && w.Invocation != nil && w.Submission == nil && w.Reply == nil && w.OwnerMessage == nil:
		var done capsuleprotocol.CompletionReceipt
		done, err = h.completeInvocation(callCtx, id, subjects, w)
		if err == nil {
			result, err = json.Marshal(done)
		}
	case w.Kind == "owner" && w.OwnerMessage != nil && w.Submission == nil && w.Reply == nil:
		var ownerReceipt capsuleprotocol.OwnerPostReceipt
		ownerReceipt, err = h.platform.PostOwner(callCtx, id, *w.OwnerMessage)
		if err == nil {
			if ownerReceipt.MessageID == "" {
				return false, capsuleprotocol.ErrProtocol
			}
			result, err = json.Marshal(ownerReceipt)
		}
	case w.Kind == "submit" && w.Submission != nil && w.Reply == nil && w.OwnerMessage == nil:
		receipt, err = h.platform.Submit(callCtx, id, *w.Submission)
	case w.Kind == "reply" && w.Reply != nil && w.Submission == nil && w.OwnerMessage == nil && w.RequestID != "":
		receipt, err = h.platform.Reply(callCtx, w.RequestID, id, *w.Reply)
	default:
		return false, capsuleprotocol.ErrProtocol
	}
	if err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		var remote *capsuleprotocol.PlatformError
		if errors.As(err, &remote) {
			switch remote.Code {
			case "not_found", "mandate", "expired", "invalid", "conflict":
				return true, h.finish(ctx, id, nil, remote.Code)
			case "transition":
				if w.Kind == "invocation" { // canceled, or already ended
					return true, h.finish(ctx, id, nil, remote.Code)
				}
			}
		}
		// A reply can race the host's delivery ACK and see PROCESSING not
		// yet committed. 'transition' must be retried, not discarded.
		return true, nil
	}
	if w.Kind != "owner" && w.Kind != "invocation" {
		if receipt.RequestID == "" || w.Kind == "reply" && receipt.RequestID != w.RequestID {
			return false, capsuleprotocol.ErrProtocol
		}
		result, err = json.Marshal(receipt)
		if err != nil {
			return false, err
		}
	}
	return true, h.finish(ctx, id, result, "")
}

// completeInvocation computes the answer once, persists it, then posts it. A
// transient failure returns an error so Step retries later with the same key.
func (h *Engine) completeInvocation(ctx context.Context, id string, subjects []string, w work) (capsuleprotocol.CompletionReceipt, error) {
	wp, ok := h.platform.(WorkPlatform)
	if !ok {
		return capsuleprotocol.CompletionReceipt{}, capsuleprotocol.ErrProtocol
	}
	iw := *w.Invocation
	if len(iw.Result) == 0 {
		for _, ref := range iw.Attachments {
			data, err := wp.FetchAttachment(ctx, ref)
			if err != nil {
				if transient(err) {
					return capsuleprotocol.CompletionReceipt{}, err
				}
				iw.Result = append(iw.Result, text(fmt.Sprintf("File %s: unreadable (%s).", ref.Name, platformCode(err))))
				continue
			}
			sum := sha256.Sum256(data)
			iw.Result = append(iw.Result, text(fmt.Sprintf("File %s: %d bytes, sha256 %s.", ref.Name, len(data), hex.EncodeToString(sum[:]))))
			clear(data)
		}
		if iw.Alias != "" {
			r, err := wp.CompleteLLM(ctx, id+"/llm", capsuleprotocol.LLMRequest{Alias: iw.Alias,
				Messages: []capsuleprotocol.LLMMessage{{Role: "user", Content: iw.Prompt}}, MaxTokens: 256})
			switch {
			case err != nil && transient(err):
				return capsuleprotocol.CompletionReceipt{}, err
			case err != nil:
				iw.Result = append(iw.Result, text("Model unavailable ("+platformCode(err)+")."))
			case strings.TrimSpace(r.Text) == "":
				iw.Result = append(iw.Result, text("The model returned no text."))
			default:
				iw.Result = append(iw.Result, text(r.Text))
			}
		}
		w.Invocation = &iw
		body, err := json.Marshal(w)
		if err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
		if err = h.store.Local(ctx, subjects, func(tx harnessstore.SQL) error {
			_, err := tx.ExecContext(ctx, `UPDATE reference_outgoing SET body=? WHERE id=? AND state='pending'`, body, id)
			return err
		}); err != nil {
			return capsuleprotocol.CompletionReceipt{}, err
		}
	}
	return wp.CompleteInvocation(ctx, id, capsuleprotocol.InvocationCompletion{OperationID: iw.OperationID, Outcome: "completed", Content: iw.Result})
}

func text(s string) capsuleprotocol.TextContent {
	return capsuleprotocol.TextContent{Type: "text", Text: s}
}

// transient errors leave the work pending: the platform may answer later.
func transient(err error) bool {
	if errors.Is(err, capsuleprotocol.ErrTransport) {
		return true
	}
	var remote *capsuleprotocol.PlatformError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "unavailable", "commit_unknown", "rate_limited":
			return true
		}
		return false
	}
	return !errors.Is(err, capsuleprotocol.ErrProtocol)
}

func platformCode(err error) string {
	var remote *capsuleprotocol.PlatformError
	if errors.As(err, &remote) {
		return remote.Code
	}
	return "protocol"
}

func (h *Engine) finish(ctx context.Context, id string, receipt []byte, reason string) error {
	err := h.store.Local(ctx, []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		state := "done"
		if reason != "" {
			state = "stopped"
		}
		// Bookkeeping of an observed remote outcome is not a new peer effect.
		// A terminal notification that already stopped this work wins.
		_, err := tx.ExecContext(ctx, `UPDATE reference_outgoing SET state=?,receipt=?,reason=? WHERE id=? AND state='pending'`, state, receipt, reason, id)
		return err
	})
	if errors.Is(err, harnessstore.ErrFenced) {
		return nil
	}
	return err
}

func (h *Engine) Run(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		worked, err := h.Step(ctx)
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
