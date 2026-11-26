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
	Kind string // "invocation" or "request", from the recorded delivery
	ID   string // the operation or request it answers
	// Text is the message as text: its text parts, and its JSON parts as
	// compact JSON, separated by blank lines.
	Text string
	// Content is the message as received, JSON parts included, for a runner
	// that can pass them on (ServerRunner). Empty for work recorded before.
	Content []capsuleprotocol.ContentPart
	Files   []string     // absolute paths of the received files, if any
	Delta   func(string) // optional incremental invocation output
}

// Output is what a run produced. Completed is false when the program failed.
// Content, when set, is the answer with its JSON parts; Text is then its text
// form, posted instead if Content does not fit.
type Output struct {
	Completed bool
	Text      string
	Content   []capsuleprotocol.ContentPart
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
CREATE TABLE IF NOT EXISTS adapter_outputs(
 id TEXT PRIMARY KEY,
 content BLOB NOT NULL
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
	Text string `json:"text"`
	// Content keeps the parts as delivered; absent in work recorded before
	// JSON content.
	Content     []capsuleprotocol.ContentPart   `json:"content,omitempty"`
	Attachments []capsuleprotocol.AttachmentRef `json:"attachments,omitempty"`
	// Mandate bounds the requests the run may send to other agents. Only an
	// invocation carries one; a request from another agent never does.
	Mandate *capsuleprotocol.InstructionMandate `json:"mandate,omitempty"`
}

// joined is the text of a message: JSON parts are given as their compact JSON.
func joined(content []capsuleprotocol.ContentPart) string {
	parts := make([]string, 0, len(content))
	for _, c := range capsuleprotocol.TextOnly(content) {
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
		if err = h.record(ctx, tx, e, "invocation", in.OperationID, input{Text: joined(in.Content), Content: in.Content, Attachments: in.Attachments, Mandate: &mandate}); err != nil {
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
		if err = h.record(ctx, tx, e, "request", peer.RequestID, input{Text: joined(peer.Payload.Content), Content: peer.Payload.Content}); err != nil {
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
		// A request the agent sent ended without a reply; or it was replied,
		// but the reply was revoked before it arrived (its author deleted:
		// reason content_revoked). Either ends the task, without an artifact.
		switch status.Status {
		case "DECLINED", "EXPIRED", "CANCELED", "FAILED", "REPLIED":
			if status.Status == "REPLIED" && status.Reason == "" {
				break
			}
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
		out, err := h.execute(ctx, kind, target, in)
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
		// An answer with JSON parts is kept as well; the text stays its
		// fallback.
		var structured []byte
		if out.Completed && capsuleprotocol.HasJSON(out.Content) {
			if structured, err = json.Marshal(out.Content); err != nil {
				return false, err
			}
		}
		err = h.store.Local(ctx, subjects, func(tx harnessstore.SQL) error {
			if _, err := tx.ExecContext(ctx, `UPDATE adapter_work SET completed=?,output=? WHERE id=? AND state='pending'`, completed.Bool, output.String, id); err != nil {
				return err
			}
			if structured == nil {
				return nil
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO adapter_outputs(id,content) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET content=excluded.content`, id, structured)
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
	content := []capsuleprotocol.ContentPart{{Type: "text", Text: output.String}}
	if structured, err := h.structuredOutput(ctx, id, kind); err != nil {
		return false, err
	} else if structured != nil {
		content = structured
	}
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

// structuredOutput is the recorded answer with its JSON parts, or nil when
// there is none or it does not fit an answer: the text is posted then.
func (h *Engine) structuredOutput(ctx context.Context, id, kind string) ([]capsuleprotocol.ContentPart, error) {
	var raw []byte
	err := h.store.Local(ctx, []string{"agent/" + h.agent}, func(tx harnessstore.SQL) error {
		return tx.QueryRowContext(ctx, `SELECT content FROM adapter_outputs WHERE id=?`, id).Scan(&raw)
	})
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, harnessstore.ErrFenced) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var content []capsuleprotocol.ContentPart
	if json.Unmarshal(raw, &content) != nil {
		return nil, nil
	}
	valid := capsuleprotocol.OwnerMessage{Content: content}.Validate()
	if kind != "invocation" {
		valid = capsuleprotocol.PeerPayload{Content: content}.Validate()
	}
	if valid != nil {
		return nil, nil
	}
	return content, nil
}

// execute fetches the job's files, runs the command once and removes the files.
// An error means the files could not be read yet.
func (h *Engine) execute(ctx context.Context, kind, target string, in input) (Output, error) {
	job := Job{Kind: kind, ID: target, Text: in.Text, Content: in.Content}
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
		files := "Attached files:\n" + strings.Join(listing, "\n")
		job.Text += "\n\n" + files
		if len(job.Content) > 0 {
			job.Content = append(job.Content[:len(job.Content):len(job.Content)], capsuleprotocol.ContentPart{Type: "text", Text: files})
		}
	}
	opener, ok := h.platform.(interface {
		OpenOutputStream(context.Context, string) (*capsuleprotocol.OutputStreamWriter, error)
	})
	if !ok || kind != "invocation" {
		return h.run(ctx, job), nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stream *capsuleprotocol.OutputStreamWriter
	var once sync.Once
	job.Delta = func(text string) {
		if text == "" {
			return
		}
		once.Do(func() {
			stream, _ = opener.OpenOutputStream(ctx, target)
			if stream != nil {
				go func(w *capsuleprotocol.OutputStreamWriter) {
					select {
					case <-w.Canceled():
						cancel()
					case <-ctx.Done():
					}
				}(stream)
			}
		})
		if stream != nil && stream.Delta(text) != nil {
			stream.Abort()
			stream = nil
		}
	}
	result := h.run(ctx, job)
	if stream != nil {
		closeCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		_, _ = stream.Close(closeCtx)
		stop()
		stream.Abort()
	}
	return result, nil
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

// Run works through the jobs until ctx ends or the store fails. A store
// that a delivery's handler holds past its busy timeout is waited out: the
// job is tried again at the next tick.
func (h *Engine) Run(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		worked, err := h.Step(ctx)
		if err != nil && !harnessstore.Busy(err) {
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
