//go:build linux

package agentadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type platform struct {
	mu          sync.Mutex
	file        []byte
	fetches     int
	completions []capsuleprotocol.InvocationCompletion
	replies     []capsuleprotocol.Reply
	keys        []string
	fail        int    // answers refused as unavailable before one succeeds
	code        string // a terminal refusal
}

func (p *platform) FetchAttachment(context.Context, capsuleprotocol.AttachmentRef) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetches++
	return append([]byte(nil), p.file...), nil
}

func (p *platform) refuse() error {
	if p.code != "" {
		return &capsuleprotocol.PlatformError{Code: p.code}
	}
	if p.fail > 0 {
		p.fail--
		return &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	return nil
}

func (p *platform) CompleteInvocation(_ context.Context, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = append(p.keys, key)
	if err := in.Validate(); err != nil {
		return capsuleprotocol.CompletionReceipt{}, &capsuleprotocol.PlatformError{Code: "invalid"}
	}
	p.completions = append(p.completions, in)
	return capsuleprotocol.CompletionReceipt{OperationID: in.OperationID, State: in.Outcome}, p.refuse()
}

func (p *platform) Reply(_ context.Context, id, key string, in capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = append(p.keys, key)
	p.replies = append(p.replies, in)
	return capsuleprotocol.PlatformReceipt{RequestID: id, State: "REPLIED"}, p.refuse()
}

type lab struct {
	t      *testing.T
	store  *harnessstore.Store
	p      *platform
	engine *Engine
	home   string
	runs   []Job
}

func newLab(t *testing.T, run Runner) *lab {
	t.Helper()
	l := &lab{t: t, p: &platform{}, home: t.TempDir()}
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	l.store = s
	if run == nil {
		run = func(_ context.Context, j Job) Output {
			l.runs = append(l.runs, j)
			return Output{Completed: true, Text: "answer to: " + j.Text}
		}
	}
	if l.engine, err = New("a", l.home, s, l.p, run); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *lab) deliver(e harnessstore.Event) harnessstore.Receipt {
	l.t.Helper()
	r, err := l.store.Apply(l.t.Context(), e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) { return l.engine.Handle(ctx, e, tx) })
	if err != nil {
		l.t.Fatal(err)
	}
	return r
}

// drain runs every job that is due, ignoring retry delays.
func (l *lab) drain() {
	l.t.Helper()
	for range 20 {
		if err := l.store.Local(l.t.Context(), []string{"agent/a"}, func(tx harnessstore.SQL) error {
			_, err := tx.ExecContext(l.t.Context(), `UPDATE adapter_work SET next_ns=0`)
			return err
		}); err != nil {
			l.t.Fatal(err)
		}
		worked, err := l.engine.Step(l.t.Context())
		if err != nil {
			l.t.Fatal(err)
		}
		if !worked {
			return
		}
	}
}

func invocation(t *testing.T, id, text string, refs ...capsuleprotocol.AttachmentRef) harnessstore.Event {
	t.Helper()
	b, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op-" + id, Attachments: refs,
		Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: id, Subjects: []string{"agent/a", "event/" + id}, Body: b}
}

// A delivery is acknowledged "working" at once; the command runs afterwards,
// once, and its output is the answer, posted again with the same key until the
// platform takes it.
func TestInvocationRunsTheCommandOnceAfterTheDelivery(t *testing.T) {
	l := newLab(t, nil)
	l.p.fail = 2
	e := invocation(t, "e1", "summarize this")
	r := l.deliver(e)
	if !capsuleprotocol.IsWorkingResult(r.Result) || len(l.runs) != 0 {
		t.Fatal("not acknowledged working before running", string(r.Result))
	}
	if replay := l.deliver(e); !replay.Replayed || !capsuleprotocol.IsWorkingResult(replay.Result) {
		t.Fatal("redelivery", string(replay.Result))
	}
	l.drain()
	if len(l.runs) != 1 || l.runs[0].Text != "summarize this" || l.runs[0].ID != "op-e1" {
		t.Fatal("the command ran", len(l.runs), "times", l.runs)
	}
	if len(l.p.completions) != 3 || l.p.keys[0] != l.p.keys[2] {
		t.Fatal("answer not retried under one key", l.p.keys)
	}
	done := l.p.completions[2]
	if done.OperationID != "op-e1" || done.Outcome != "completed" || done.Content[0].Text != "answer to: summarize this" {
		t.Fatal(done)
	}
	// The key is derived from the delivered event, stable across restarts.
	digest := sha256.Sum256([]byte("agentcapsule-adapter-v1/invocation/e1"))
	if l.p.keys[0] != "adp_"+hex.EncodeToString(digest[:]) {
		t.Fatal(l.p.keys[0])
	}
	l.drain()
	if len(l.runs) != 1 || len(l.p.completions) != 3 {
		t.Fatal("finished work ran again")
	}
}

// Jobs run one at a time, in delivery order; a failed program is a failed invocation.
func TestJobsRunInOrderAndFailuresAreReported(t *testing.T) {
	l := newLab(t, func(_ context.Context, j Job) Output {
		return Output{Completed: !strings.Contains(j.Text, "fail"), Text: j.Text}
	})
	for _, id := range []string{"e1", "e2", "e3"} {
		text := "job " + id
		if id == "e2" {
			text = "please fail"
		}
		l.deliver(invocation(t, id, text))
	}
	l.drain()
	if len(l.p.completions) != 3 {
		t.Fatal(l.p.completions)
	}
	var order []string
	for _, c := range l.p.completions {
		order = append(order, c.OperationID+":"+c.Outcome)
	}
	if strings.Join(order, " ") != "op-e1:completed op-e2:failed op-e3:completed" {
		t.Fatal(order)
	}
}

// Received files are written under the agent's home for the run, listed in the
// text, and removed afterwards.
func TestFilesAreGivenToTheCommandThenRemoved(t *testing.T) {
	var seen []string
	var contents []string
	l := newLab(t, func(_ context.Context, j Job) Output {
		seen = j.Files
		for _, f := range j.Files {
			b, _ := os.ReadFile(f)
			contents = append(contents, string(b))
		}
		return Output{Completed: true, Text: j.Text}
	})
	l.p.file = []byte("quarterly numbers")
	sum := sha256.Sum256(l.p.file)
	ref := capsuleprotocol.AttachmentRef{ID: "att_0123456789abcdef0123456789abcdef", Name: "..rapport été.pdf", MediaType: "application/pdf",
		Size: int64(len(l.p.file)), SHA256: hex.EncodeToString(sum[:])}
	l.deliver(invocation(t, "e1", "read the report", ref))
	l.drain()
	if len(seen) != 1 || contents[0] != "quarterly numbers" || filepath.Dir(seen[0]) != filepath.Join(l.home, ".agentcapsule", "files", "op-e1") ||
		filepath.Base(seen[0]) != "1-rapport__t_.pdf" {
		t.Fatal(seen)
	}
	if _, err := os.Stat(seen[0]); !os.IsNotExist(err) {
		t.Fatal("file kept after the run", err)
	}
	text := l.p.completions[0].Content[0].Text
	if !strings.Contains(text, "read the report") || !strings.Contains(text, "Attached files:\n- "+seen[0]+" (application/pdf, 17 bytes)") {
		t.Fatal(text)
	}
}

// A request from another agent is answered by the same command, as a reply.
func TestARequestFromAnotherAgentIsAnsweredByTheCommand(t *testing.T) {
	l := newLab(t, nil)
	b, _ := json.Marshal(capsuleprotocol.PeerEvent{Kind: "request", RequestID: "arq_1", SenderAgentID: "b", RecipientAgentID: "a", Sequence: 1,
		Payload: capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "what is new?"}}}})
	r := l.deliver(harnessstore.Event{ID: "p1", Subjects: []string{"agent/a", "agent/b", "request/arq_1", "event/p1"}, Body: b})
	if string(r.Result) != `{"received":true}` {
		t.Fatal(string(r.Result))
	}
	l.drain()
	if len(l.p.replies) != 1 || l.p.replies[0].Outcome != "completed" || l.p.replies[0].Payload.Content[0].Text != "answer to: what is new?" {
		t.Fatal(l.p.replies)
	}
}

// A canceled invocation, or a revoked participant, ends the job without
// running it again.
func TestEndedOrRevokedWorkStops(t *testing.T) {
	l := newLab(t, nil)
	l.p.code = "transition"
	l.deliver(invocation(t, "e1", "x"))
	l.drain()
	l.drain()
	if len(l.runs) != 1 || len(l.p.completions) != 1 {
		t.Fatal("canceled work retried", len(l.runs), len(l.p.completions))
	}
	l.p.code = ""
	l.deliver(invocation(t, "e2", "y"))
	if err := l.store.Fence(t.Context(), "event/e2"); err != nil {
		t.Fatal(err)
	}
	l.drain()
	if len(l.runs) != 1 || len(l.p.completions) != 1 {
		t.Fatal("revoked work ran", len(l.runs))
	}
	var reason string
	_ = l.store.Local(t.Context(), []string{"agent/a"}, func(tx harnessstore.SQL) error {
		return tx.QueryRowContext(t.Context(), `SELECT reason FROM adapter_work WHERE target='op-e2'`).Scan(&reason)
	})
	if reason != "local_revocation" {
		t.Fatal(reason)
	}
}

// A run interrupted by the harness stopping (sleep) is not a failure: nothing
// is recorded or posted, and the job runs again after the restart.
func TestARunInterruptedByStoppingRunsAgain(t *testing.T) {
	runs := 0
	started := make(chan struct{})
	l := newLab(t, func(ctx context.Context, j Job) Output {
		runs++
		if runs == 1 {
			close(started)
			<-ctx.Done()
			return Output{} // what the command runner reports for a killed program
		}
		return Output{Completed: true, Text: "second run"}
	})
	l.deliver(invocation(t, "e1", "long task"))
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-started
		cancel()
	}()
	if _, err := l.engine.Step(ctx); err == nil {
		t.Fatal("a stopping run reported no interruption")
	}
	if len(l.p.completions) != 0 {
		t.Fatal("an interrupted run was posted", l.p.completions)
	}
	l.drain()
	if runs != 2 || len(l.p.completions) != 1 || l.p.completions[0].Outcome != "completed" || l.p.completions[0].Content[0].Text != "second run" {
		t.Fatal(runs, l.p.completions)
	}
}

// The real runner: the program reads its input, writes its answer, and finds
// its environment; a program that outlives its timeout is killed and failed.
func TestCommandRunnerRunsTheProgram(t *testing.T) {
	home := t.TempDir()
	script := filepath.Join(t.TempDir(), "agent.sh")
	if err := os.WriteFile(script, []byte(`#!/bin/sh
case "$1" in
  sleep) sleep 30 & sleep 30 ;;
  exit) echo partial; exit 3 ;;
esac
read -r line
echo "agent got: $line"
echo "home=$HOME pwd=$(pwd) openai=$OPENAI_BASE_URL anthropic=$ANTHROPIC_BASE_URL key=$OPENAI_API_KEY job=$AGENTCAPSULE_JOB_ID extra=$EXTRA"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig([]byte(`{"version":1,"command":["` + script + `"],"env":{"EXTRA":"yes","OPENAI_API_KEY":"kept-placeholder"},"timeout_seconds":1}`))
	if err != nil {
		t.Fatal(err)
	}
	out := CommandRunner(cfg, home)(t.Context(), Job{ID: "op-1", Text: "hello agent\nsecond line"})
	want := "agent got: hello agent\nhome=" + home + " pwd=" + home + " openai=http://127.0.0.1:8411/v1 anthropic=http://127.0.0.1:8411 key=kept-placeholder job=op-1 extra=yes\n"
	if !out.Completed || out.Text != want {
		t.Fatalf("%+v\n%s", out, want)
	}
	cfg.Command = []string{script, "exit"}
	if out = CommandRunner(cfg, home)(t.Context(), Job{ID: "op-2"}); out.Completed {
		t.Fatal("a failed program completed", out)
	}
	cfg.Command = []string{script, "sleep"}
	start := time.Now()
	if out = CommandRunner(cfg, home)(t.Context(), Job{ID: "op-3"}); out.Completed || time.Since(start) > 10*time.Second {
		t.Fatal("timeout", out, time.Since(start))
	}
	// Argument input: the text is the last argument.
	echo := filepath.Join(t.TempDir(), "args.sh")
	_ = os.WriteFile(echo, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\n"), 0o700)
	cfg, _ = ParseConfig([]byte(`{"version":1,"command":["` + echo + `","-p"],"input":"argument"}`))
	if out = CommandRunner(cfg, home)(t.Context(), Job{Text: "two words"}); out.Text != "-p|two words|" {
		t.Fatal(out)
	}
}

func TestAnswerFitsTheResultLimit(t *testing.T) {
	if Answer("  \n") == "" || Answer("ok") != "ok" {
		t.Fatal("short answers")
	}
	long := Answer(strings.Repeat("é", MaxAnswerBytes))
	if len(long) > MaxAnswerBytes+100 || !strings.Contains(long, "[Output truncated") || !strings.HasPrefix(long, "é") {
		t.Fatal(len(long))
	}
	if err := (capsuleprotocol.OwnerMessage{Content: []capsuleprotocol.TextContent{{Type: "text", Text: long}}}).Validate(); err != nil {
		t.Fatal("a cut answer is not a valid result", err)
	}
	if strings.Contains(Answer("a\x00b"), "\x00") {
		t.Fatal("NUL kept")
	}
}

func TestConfig(t *testing.T) {
	c, err := ParseConfig([]byte(`{"version":1,"command":["/usr/bin/pi","-p"]}`))
	if err != nil || c.Input != "stdin" || c.ModelAddress != DefaultModelAddress || c.Timeout() != time.Hour {
		t.Fatal(c, err)
	}
	if a, ok := c.Alias("fast"); !ok || a != "fast" {
		t.Fatal(a)
	}
	if _, ok := c.Alias("has space"); ok {
		t.Fatal("invalid alias accepted")
	}
	env := c.Environment("/var/lib/agent", nil)
	if !slices.Contains(env, "HOME=/var/lib/agent") || !slices.Contains(env, "ANTHROPIC_BASE_URL=http://127.0.0.1:8411") ||
		!slices.Contains(env, "AGENTCAPSULE_A2A_URL=http://127.0.0.1:8412") {
		t.Fatal(env)
	}
	s, err := ParseConfig([]byte(`{"version":1,"server":{"command":["/opt/agent/serve"],"a2a_url":"http://127.0.0.1:9000/"}}`))
	if err != nil || s.Server.URL != "http://127.0.0.1:9000/" || s.Server.Ready() != 2*time.Minute || len(s.Command) != 0 {
		t.Fatal(s, err)
	}
	for _, bad := range []string{
		`{"version":2,"command":["/a"]}`,
		`{"version":1,"command":[]}`,
		`{"version":1,"command":["relative"]}`,
		`{"version":1,"command":["/a/../b"]}`,
		`{"version":1,"command":["/a"],"input":"file"}`,
		`{"version":1,"command":["/a"],"timeout_seconds":90000}`,
		`{"version":1,"command":["/a"],"env":{"AGENTCAPSULE_MODEL_URL":"x"}}`,
		`{"version":1,"command":["/a"],"env":{"BAD-NAME":"x"}}`,
		`{"version":1,"command":["/a"],"models":{"gpt":"has space"}}`,
		`{"version":1,"command":["/a"],"model_address":"0.0.0.0:80"}`,
		`{"version":1,"command":["/a"],"model_address":"127.0.0.1:0"}`,
		`{"version":1,"command":["/a"],"unknown":true}`,
		`{"version":1,"command":["/a"]} {}`,
		`{"version":1,"command":["/a"],"a2a_address":"127.0.0.1:8411"}`,
		`{"version":1,"command":["/a"],"a2a_address":"10.0.0.1:8412"}`,
		`{"version":1}`,
		`{"version":1,"command":["/a"],"server":{"command":["/b"],"a2a_url":"http://127.0.0.1:9000"}}`,
		`{"version":1,"input":"argument","server":{"command":["/b"],"a2a_url":"http://127.0.0.1:9000"}}`,
		`{"version":1,"server":{"command":["relative"],"a2a_url":"http://127.0.0.1:9000"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"http://10.0.0.1:9000"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"https://127.0.0.1:9000"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"http://127.0.0.1"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"http://user:pw@127.0.0.1:9000"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"http://127.0.0.1:8412"}}`,
		`{"version":1,"server":{"command":["/b"],"a2a_url":"http://127.0.0.1:9000","ready_seconds":4000}}`,
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Error("accepted", bad)
		}
	}
}
