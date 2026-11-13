//go:build linux

package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// fakePlatform is the host side of the harness's outgoing channel.
type fakePlatform struct {
	mu          sync.Mutex
	llmKeys     []string
	completions []InvocationCompletion
	queries     []DirectoryQuery
}

func (f *fakePlatform) Validate(context.Context) error { return nil }
func (f *fakePlatform) Submit(context.Context, string, Submission) (PlatformReceipt, error) {
	return PlatformReceipt{}, &PlatformError{Code: "unavailable"}
}
func (f *fakePlatform) Reply(context.Context, string, string, Reply) (PlatformReceipt, error) {
	return PlatformReceipt{}, &PlatformError{Code: "unavailable"}
}
func (f *fakePlatform) Search(context.Context, []string) ([]string, error) { return nil, nil }
func (f *fakePlatform) CompleteLLM(_ context.Context, key string, in LLMRequest) (LLMResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.llmKeys = append(f.llmKeys, key)
	return LLMResult{Text: "model answer to: " + in.Messages[0].Content, InputTokens: 3, OutputTokens: 4}, nil
}
func (f *fakePlatform) FindAgents(_ context.Context, q DirectoryQuery) ([]DirectoryAgent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	return []DirectoryAgent{{AgentID: "agt_b", Description: "Summarizes documents.", Skills: []int{10302}, Domains: []int{111}}}, nil
}
func (f *fakePlatform) CompleteInvocation(_ context.Context, _ string, in InvocationCompletion) (CompletionReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completions = append(f.completions, in)
	return CompletionReceipt{OperationID: in.OperationID, State: "SUCCEEDED"}, nil
}

type pythonHarness struct {
	cmd     *exec.Cmd
	control *Client
	path    string
	done    chan error
}

// startPythonHarness runs examples/python-echo the way capsule-init does: the
// boot record on fd 3, a bound control listener on fd 4, a minimal environment.
func startPythonHarness(t *testing.T, dir, data string, id Identity, supervisorUID int, platformSocket string) *pythonHarness {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the Python harness conformance test")
	}
	controlPath := filepath.Join(t.TempDir(), "control.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false) // the child serves this path from its copy
	l.Close()
	boot := map[string]any{"protocol": Version, "identity": id, "data_directory": data, "supervisor_uid": supervisorUID,
		"previous_shutdown": "clean"}
	if platformSocket != "" {
		boot["platform_socket"] = platformSocket
	}
	raw, _ := json.Marshal(boot)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	w.Close()
	cmd := exec.Command(python, "-I", filepath.Join(dir, "harness.py"))
	cmd.ExtraFiles = []*os.File{r, listener}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=" + t.TempDir()}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr // shown if the test fails
	t.Cleanup(func() {
		if t.Failed() && stderr.Len() > 0 {
			t.Log("harness stderr:\n" + stderr.String())
		}
	})
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	listener.Close()
	h := &pythonHarness{cmd: cmd, path: controlPath, done: make(chan error, 1)}
	go func() { h.done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-h.done })
	if h.control, err = NewLocalClient(id, controlPath); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *pythonHarness) stop(t *testing.T) {
	t.Helper()
	if err := h.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-h.done:
		h.done <- err
		if err != nil {
			t.Fatal("the harness did not exit cleanly on SIGTERM", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the harness ignored SIGTERM")
	}
}

func invocationEvent(t *testing.T, agent, eventID, operation, text string) harnessstore.Event {
	t.Helper()
	body, err := json.Marshal(Invocation{Kind: "message.user", OperationID: operation,
		Mandate: InstructionMandate{ID: "mandate-" + operation, MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []TextContent{{Type: "text", Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: eventID, Subjects: []string{"agent/" + agent, "event/" + eventID}, Body: body}
}

func answer(t *testing.T, r harnessstore.Receipt) string {
	t.Helper()
	var m OwnerMessage
	if err := json.Unmarshal(r.Result, &m); err != nil || len(m.Content) != 1 {
		t.Fatal("not a text result", string(r.Result), err)
	}
	return m.Content[0].Text
}

// The Python SDK and the python-echo example speak capsule.v1 to the Go
// supervisor's client exactly like the Go reference harness: negotiation,
// health, exactly-once invocations with replay and conflict detection, fences,
// a deferred answer through the platform channel, a clean exit on SIGTERM,
// durable state across restarts, and refusal of any peer but the supervisor.
func TestPythonHarnessSpeaksTheGuestProtocol(t *testing.T) {
	dir := t.TempDir()
	for src, dst := range map[string]string{"../../sdk/python/agentcapsule_harness.py": "agentcapsule_harness.py",
		"../../examples/python-echo/harness.py": "harness.py"} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, dst), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data := t.TempDir()
	id := Identity{Incarnation: 1, AgentID: "agt_python", Generation: 3, VMID: "0123456789abcdef"}
	platform := &fakePlatform{}
	handler, err := NewPlatformHandler(id, platform)
	if err != nil {
		t.Fatal(err)
	}
	handler.(*platformHandler).localAuth = func(r *http.Request) bool { ok, _ := r.Context().Value(localPeerKey{}).(bool); return ok }
	platformPath := filepath.Join(t.TempDir(), "platform.sock")
	pl, err := net.ListenUnix("unix", &net.UnixAddr{Name: platformPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serveLocal(ctx, pl, uint32(os.Getuid()), handler) }()
	t.Cleanup(func() { cancel(); <-served })

	h := startPythonHarness(t, dir, data, id, os.Getuid(), platformPath)
	call, done := context.WithTimeout(context.Background(), 30*time.Second)
	defer done()
	// The harness needs a moment to start; capsule-init retries health likewise.
	deadline := time.Now().Add(15 * time.Second)
	for h.control.Health(call) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the Python harness never became healthy")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err = h.control.RequireControlContract(call); err != nil {
		t.Fatal("capabilities", err)
	}
	status, err := h.control.HealthStatus(call)
	if err != nil || status.PreviousShutdown != ShutdownClean || status.Identity != id {
		t.Fatal("health", status, err)
	}

	first := invocationEvent(t, id.AgentID, "evt-1", "op-1", "hello")
	r, err := h.control.Invoke(call, first)
	if err != nil || r.Replayed || answer(t, r) != "python echo #1: hello" {
		t.Fatal("first invocation", err, string(r.Result))
	}
	if again, err := h.control.Invoke(call, first); err != nil || !again.Replayed || string(again.Result) != string(r.Result) {
		t.Fatal("a replay was not deduplicated", err)
	}
	if _, err = h.control.Invoke(call, invocationEvent(t, id.AgentID, "evt-1", "op-other", "changed")); !errors.Is(err, harnessstore.ErrConflict) {
		t.Fatal("an event ID reused with another envelope was accepted", err)
	}
	if r, err = h.control.Invoke(call, invocationEvent(t, id.AgentID, "evt-2", "op-2", "again")); err != nil || answer(t, r) != "python echo #2: again" {
		t.Fatal("second invocation", err)
	}

	// A fenced participant blocks any later effect involving it.
	if err = h.control.Fence(call, "agent/agt_revoked"); err != nil {
		t.Fatal(err)
	}
	peer := harnessstore.Event{ID: "evt-peer", Subjects: []string{"agent/" + id.AgentID, "agent/agt_revoked"}, Body: []byte(`{"kind":"request"}`)}
	if _, err = h.control.Send(call, peer); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("an event of a fenced participant was applied", err)
	}
	other := id
	other.Generation++
	if wrong, err := NewLocalClient(other, h.path); err == nil {
		if _, err = wrong.Invoke(call, invocationEvent(t, id.AgentID, "evt-3", "op-3", "x")); err == nil {
			t.Fatal("a request for another boot identity was accepted")
		}
	}

	// Deferred answer: "working" now, the model's answer through the platform later.
	if r, err = h.control.Invoke(call, invocationEvent(t, id.AgentID, "evt-llm", "op-llm", "/llm fast what is a capsule")); err != nil || !IsWorkingResult(r.Result) {
		t.Fatal("a model invocation was not acknowledged as working", err, string(r.Result))
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		platform.mu.Lock()
		n := len(platform.completions)
		platform.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the deferred answer was never posted")
		}
		time.Sleep(50 * time.Millisecond)
	}
	platform.mu.Lock()
	c, keys := platform.completions[0], platform.llmKeys
	platform.mu.Unlock()
	if c.OperationID != "op-llm" || c.Outcome != "completed" || c.Content[0].Text != "model answer to: what is a capsule" ||
		len(keys) != 1 || keys[0] != "llm-evt-llm" {
		t.Fatalf("deferred answer %+v keys %v", c, keys)
	}

	// A Directory search, deferred the same way.
	if r, err = h.control.Invoke(call, invocationEvent(t, id.AgentID, "evt-find", "op-find", "/find 10302 10301")); err != nil || !IsWorkingResult(r.Result) {
		t.Fatal("a search was not acknowledged as working", err, string(r.Result))
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		platform.mu.Lock()
		n := len(platform.completions)
		platform.mu.Unlock()
		if n > 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the search answer was never posted")
		}
		time.Sleep(50 * time.Millisecond)
	}
	platform.mu.Lock()
	c, queries := platform.completions[1], platform.queries
	platform.mu.Unlock()
	if c.OperationID != "op-find" || c.Content[0].Text != "agt_b: Summarizes documents." || len(queries) != 1 ||
		!reflect.DeepEqual(queries[0].Skills, []int{10302, 10301}) {
		t.Fatalf("search answer %+v queries %v", c, queries)
	}

	// SIGTERM ends it cleanly; its state survives a restart.
	h.stop(t)
	h = startPythonHarness(t, dir, data, id, os.Getuid(), platformPath)
	deadline = time.Now().Add(15 * time.Second)
	for h.control.Health(call) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the restarted harness never became healthy")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r, err = h.control.Invoke(call, first); err != nil || !r.Replayed || answer(t, r) != "python echo #1: hello" {
		t.Fatal("a replay after restart changed its answer", err)
	}
	replayed := r
	fourth := invocationEvent(t, id.AgentID, "evt-4", "op-4", "after restart")
	if r, err = h.control.Invoke(call, fourth); err != nil || answer(t, r) != "python echo #3: after restart" {
		t.Fatal("state did not survive the restart", err)
	}
	// A restore inspects the outcomes the store holds, with Go's fingerprints.
	contract, err := h.control.Negotiate(call, []string{Version})
	if err != nil || !contract.Supports(ControlOutcomes) {
		t.Fatal("the Python harness does not offer outcome inspection", contract, err)
	}
	want := map[string][32]byte{}
	var ids []string
	for _, applied := range []struct {
		event  harnessstore.Event
		result []byte
	}{{first, replayed.Result}, {fourth, r.Result}, {peer, nil}} {
		outcome, digest, err := harnessstore.OutcomeFingerprint(id.AgentID, applied.event, applied.result)
		if err != nil {
			t.Fatal(err)
		}
		if applied.result != nil {
			want[outcome] = digest
		}
		ids = append(ids, outcome)
	}
	held, err := h.control.Outcomes(call, ids)
	if err != nil || !reflect.DeepEqual(held, want) {
		t.Fatal("outcomes held by the Python harness", held, err)
	}
	h.stop(t)

	// Only the supervisor's UID may call the harness.
	h = startPythonHarness(t, dir, data, id, os.Getuid()+1, "")
	raw := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", h.path)
	}}}
	deadline = time.Now().Add(15 * time.Second)
	for {
		resp, err := raw.Get("http://harness.local/v1/health")
		if err == nil {
			var out struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized || out.Code != "unauthenticated" {
				t.Fatal("a peer other than the supervisor was served", resp.StatusCode, out.Code)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the harness never answered", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
