package agentadapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// Platform is what the adapter needs after a delivery: the invocation's files,
// and where its answer goes.
type Platform interface {
	FetchAttachment(context.Context, capsuleprotocol.AttachmentRef) ([]byte, error)
	CompleteInvocation(context.Context, string, capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error)
	Reply(context.Context, string, string, capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error)
}

// Job is one run of the agent's command.
type Job struct {
	ID    string // the operation or request it answers
	Text  string
	Files []string // absolute paths of the received files, if any
}

// Output is what a run produced. Completed is false when the program failed.
type Output struct {
	Completed bool
	Text      string
}

// Runner runs the agent's command for a job. Runs are sequential.
type Runner func(context.Context, Job) Output

// Engine is the adapter's harness: deliveries are recorded and acknowledged at
// once ("working"); the command runs afterwards, one job at a time, in arrival
// order, and its answer is posted with a key derived from the delivery.
type Engine struct {
	agent    string
	home     string
	store    *harnessstore.Store
	platform Platform
	run      Runner
	mu       sync.Mutex
	// running is the job whose command runs now, if any. The A2A endpoint
	// sends requests to other agents under its mandate, and only then.
	running atomic.Pointer[runningJob]
}

// runningJob is what the A2A endpoint needs of the job that runs now.
type runningJob struct {
	work     string   // the adapter_work id, which scopes the idempotency keys
	subjects []string // the delivered event's fence subjects
	mandate  *capsuleprotocol.InstructionMandate
}

func New(agent, home string, store *harnessstore.Store, platform Platform, run Runner) (*Engine, error) {
	if agent == "" || !filepath.IsAbs(home) || store == nil || run == nil {
		return nil, capsuleprotocol.ErrProtocol
	}
	return &Engine{agent: agent, home: home, store: store, platform: platform, run: run}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS adapter_a2a_tasks(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 key TEXT NOT NULL UNIQUE,
 work TEXT NOT NULL,
 recipient TEXT NOT NULL,
 message_id TEXT NOT NULL,
 context_id TEXT NOT NULL,
 content BLOB NOT NULL,
 request_id TEXT UNIQUE,
 state TEXT NOT NULL DEFAULT '',
 updated_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS adapter_a2a_results(
 request_id TEXT PRIMARY KEY,
 state TEXT NOT NULL,
 reply BLOB,
 reason TEXT NOT NULL DEFAULT '',
 received_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS adapter_work(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN ('invocation','request')),
 target TEXT NOT NULL,
 subjects BLOB NOT NULL,
 input BLOB NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','done','stopped')),
 completed INTEGER,
 output TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_ns INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT ''
);`

type input struct {
	Text        string                          `json:"text"`
	Attachments []capsuleprotocol.AttachmentRef `json:"attachments,omitempty"`
	// Mandate bounds the requests the run may send to other agents. Only an
	// invocation carries one; a request from another agent never does.
	Mandate *capsuleprotocol.InstructionMandate `json:"mandate,omitempty"`
}

func joined(content []capsuleprotocol.TextContent) string {
	parts := make([]string, 0, len(content))
	for _, c := range content {
		parts = append(parts, c.Text)
	}
	return strings.Join(parts, "\n\n")
}

func (h *Engine) record(ctx context.Context, tx harnessstore.SQL, e harnessstore.Event, kind, target string, in input) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	subjects, err := json.Marshal(e.Subjects)
	if err != nil {
		return err
	}
	// One durable key per delivered event: the platform sees the same key on
	// every retry of the answer, across restarts.
	digest := sha256.Sum256([]byte("agentcapsule-adapter-v1/" + kind + "/" + e.ID))
	_, err = tx.ExecContext(ctx, `INSERT INTO adapter_work(id,kind,target,subjects,input) VALUES(?,?,?,?,?)`,
		"adp_"+hex.EncodeToString(digest[:]), kind, target, subjects, body)
	return err
}

func received() ([]byte, error) { return []byte(`{"received":true}`), nil }

// Handle runs inside Store.Apply: the job and the acknowledgment commit together.
// It never calls the platform nor the agent.
func (h *Engine) Handle(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	var kind struct {
		Kind      string `json:"kind"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(e.Body, &kind)
	switch kind.Kind {
	case "message.user":
		in, err := capsuleprotocol.DecodeInvocation(e, h.agent)
		if err != nil {
			return nil, err
		}
		if h.platform == nil {
			return json.Marshal(capsuleprotocol.OwnerMessage{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "The platform channel is unavailable; the agent cannot answer."}}})
		}
		mandate := in.Mandate
		if err = h.record(ctx, tx, e, "invocation", in.OperationID, input{Text: joined(in.Content), Attachments: in.Attachments, Mandate: &mandate}); err != nil {
			return nil, err
		}
		return capsuleprotocol.WorkingResult(), nil
	case "request":
		peer, err := capsuleprotocol.DecodePeerEvent(e, h.agent)
		if err != nil {
			return nil, err
		}
		if h.platform == nil {
			return nil, capsuleprotocol.ErrTransport
		}
		if err = h.record(ctx, tx, e, "request", peer.RequestID, input{Text: joined(peer.Payload.Content)}); err != nil {
			return nil, err
		}
		return received()
	case "reply":
		// The answer to a request the agent sent through its A2A endpoint.
		peer, err := capsuleprotocol.DecodePeerEvent(e, h.agent)
		if err != nil {
			return nil, err
		}
		reply, err := json.Marshal(peer.Payload.Content)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_a2a_results(request_id,state,reply,received_ns) VALUES(?,'REPLIED',?,?)
            ON CONFLICT(request_id) DO NOTHING`, peer.RequestID, reply, time.Now().UnixNano()); err != nil {
			return nil, err
		}
		return received()
	case "status":
		// The host writes this notification with Go field names (RequestID,
		// Status, Reason); JSON field matching ignores case only, not the
		// underscore, so both spellings are read.
		var status struct {
			RequestID string `json:"RequestID"`
			Snake     string `json:"request_id"`
			Status    string `json:"Status"`
			Reason    string `json:"Reason"`
		}
		_ = json.Unmarshal(e.Body, &status)
		if status.RequestID == "" {
			status.RequestID = status.Snake
		}
		if status.RequestID == "" || len(status.RequestID) > 100 {
			return received()
		}
		// A request the agent received that ended (canceled, expired) needs no
		// answer any more.
		if _, err := tx.ExecContext(ctx, `UPDATE adapter_work SET state='stopped',reason='request_terminal' WHERE kind='request' AND target=? AND state='pending'`, status.RequestID); err != nil {
			return nil, err
		}
		// A request the agent sent ended without a reply.
		switch status.Status {
		case "DECLINED", "EXPIRED", "CANCELED", "FAILED":
			if _, err := tx.ExecContext(ctx, `INSERT INTO adapter_a2a_results(request_id,state,reason,received_ns) VALUES(?,?,?,?)
                ON CONFLICT(request_id) DO NOTHING`, status.RequestID, status.Status, truncate(status.Reason, 100), time.Now().UnixNano()); err != nil {
				return nil, err
			}
		}
		return received()
	}
	// Control fixtures.
	return received()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// MaxAnswerBytes is the longest answer posted; longer output is cut, with a note.
const MaxAnswerBytes = 30 * 1024

// Answer fits a program's output into one text answer.
func Answer(output string) string {
	output = strings.ToValidUTF8(strings.ReplaceAll(output, "\x00", ""), "�")
	if strings.TrimSpace(output) == "" {
		return "(The agent produced no output.)"
	}
	if len(output) <= MaxAnswerBytes {
		return output
	}
	note := fmt.Sprintf("\n\n[Output truncated to its first %d bytes.]", MaxAnswerBytes)
	cut := output[:MaxAnswerBytes]
	for !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + note
}

// Step takes the oldest due job: runs the command once if its output is not yet
// recorded, then posts the answer. Reports whether it found work.
func (h *Engine) Step(ctx context.Context) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.platform == nil {
		return false, nil
	}
	var id, kind, target string
	var encodedSubjects, encodedInput []byte
	var completed sql.NullBool
	var output sql.NullString
	var attempts int
	err := h.store.Local(ctx, []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT id,kind,target,subjects,input,completed,output,attempts FROM adapter_work WHERE state='pending' AND next_ns<=? ORDER BY seq LIMIT 1`,
			time.Now().UnixNano()).Scan(&id, &kind, &target, &encodedSubjects, &encodedInput, &completed, &output, &attempts)
	})
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, harnessstore.ErrFenced) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var subjects []string
	var in input
	if err = json.Unmarshal(encodedSubjects, &subjects); err != nil {
		return false, err
	}
	if err = json.Unmarshal(encodedInput, &in); err != nil {
		return false, err
	}
	// Schedule the next attempt before any I/O, so that a failing answer does
	// not hold the queue.
	delay := time.Duration(1<<min(attempts, 6)) * 250 * time.Millisecond
	err = h.store.Local(ctx, subjects, func(tx harnessstore.SQL) error {
		_, err := tx.ExecContext(ctx, `UPDATE adapter_work SET attempts=attempts+1,next_ns=? WHERE id=? AND state='pending'`, time.Now().Add(delay).UnixNano(), id)
		return err
	})
	if errors.Is(err, harnessstore.ErrFenced) {
		return true, h.finish(ctx, id, "local_revocation")
	}
	if err != nil {
		return false, err
	}
	if !completed.Valid {
		h.running.Store(&runningJob{work: id, subjects: subjects, mandate: in.Mandate})
		out, err := h.execute(ctx, target, in)
		h.running.Store(nil)
		if ctx.Err() != nil {
			// Stopping (sleep, shutdown): the interrupted run is not an
			// outcome. It runs again from the start after the restart.
			return true, ctx.Err()
		}
		if err != nil {
			return true, nil // the files could not be read yet; retry later
		}
		completed, output = sql.NullBool{Bool: out.Completed, Valid: true}, sql.NullString{String: Answer(out.Text), Valid: true}
		err = h.store.Local(ctx, subjects, func(tx harnessstore.SQL) error {
			_, err := tx.ExecContext(ctx, `UPDATE adapter_work SET completed=?,output=? WHERE id=? AND state='pending'`, completed.Bool, output.String, id)
			return err
		})
		if errors.Is(err, harnessstore.ErrFenced) {
			return true, h.finish(ctx, id, "local_revocation")
		}
		if err != nil {
			return false, err
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	content := []capsuleprotocol.TextContent{{Type: "text", Text: output.String}}
	if kind == "invocation" {
		done := capsuleprotocol.InvocationCompletion{OperationID: target, Outcome: "completed", Content: content}
		if !completed.Bool {
			done = capsuleprotocol.InvocationCompletion{OperationID: target, Outcome: "failed"}
		}
		_, err = h.platform.CompleteInvocation(callCtx, id, done)
	} else {
		if !completed.Bool {
			content = []capsuleprotocol.TextContent{{Type: "text", Text: "The agent could not answer this request."}}
		}
		_, err = h.platform.Reply(callCtx, target, id, capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: content}})
	}
	if err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		var remote *capsuleprotocol.PlatformError
		if errors.As(err, &remote) {
			switch remote.Code {
			case "not_found", "mandate", "expired", "invalid", "conflict":
				return true, h.finish(ctx, id, remote.Code)
			case "transition":
				if kind == "invocation" { // canceled, or already ended
					return true, h.finish(ctx, id, remote.Code)
				}
			}
		}
		return true, nil // retried later with the same key
	}
	return true, h.finish(ctx, id, "")
}

// execute fetches the job's files, runs the command once and removes the files.
// An error means the files could not be read yet.
func (h *Engine) execute(ctx context.Context, target string, in input) (Output, error) {
	job := Job{ID: target, Text: in.Text}
	if len(in.Attachments) > 0 {
		dir := filepath.Join(h.home, ".agentcapsule", "files", safeName(target, "job"))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Output{}, err
		}
		defer os.RemoveAll(dir)
		var listing []string
		for i, ref := range in.Attachments {
			data, err := h.platform.FetchAttachment(ctx, ref)
			if err != nil {
				var remote *capsuleprotocol.PlatformError
				if errors.As(err, &remote) && (remote.Code == "not_found" || remote.Code == "invalid") {
					listing = append(listing, fmt.Sprintf("- %s: unreadable (%s)", ref.Name, remote.Code))
					continue
				}
				return Output{}, err
			}
			path := filepath.Join(dir, fmt.Sprintf("%d-%s", i+1, safeName(ref.Name, "file")))
			err = os.WriteFile(path, data, 0o600)
			clear(data)
			if err != nil {
				return Output{}, err
			}
			job.Files = append(job.Files, path)
			listing = append(listing, fmt.Sprintf("- %s (%s, %d bytes)", path, ref.MediaType, ref.Size))
		}
		job.Text += "\n\nAttached files:\n" + strings.Join(listing, "\n")
	}
	return h.run(ctx, job), nil
}

// safeName keeps a file name readable without letting it leave its directory.
func safeName(name, fallback string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
		if b.Len() >= 100 {
			break
		}
	}
	s := strings.TrimLeft(b.String(), ".")
	if s == "" {
		return fallback
	}
	return s
}

func (h *Engine) finish(ctx context.Context, id, reason string) error {
	err := h.store.Local(ctx, []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		state := "done"
		if reason != "" {
			state = "stopped"
		}
		_, err := tx.ExecContext(ctx, `UPDATE adapter_work SET state=?,reason=? WHERE id=? AND state='pending'`, state, reason, id)
		return err
	})
	if errors.Is(err, harnessstore.ErrFenced) {
		return nil
	}
	return err
}

// Run works through the jobs until ctx ends.
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
