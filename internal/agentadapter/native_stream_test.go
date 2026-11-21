//go:build linux

package agentadapter

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/a2aproject/a2a-go/v2/a2a"
)

type nativeForwarder struct {
	forwarder
	finish  chan struct{}
	refusal string
	cut     bool
	key     string
}

func (f *nativeForwarder) ForwardLLMStream(ctx context.Context, key string, request capsuleprotocol.LLMForward) iter.Seq2[capsuleprotocol.LLMStreamFrame, error] {
	return func(yield func(capsuleprotocol.LLMStreamFrame, error) bool) {
		f.key = key
		if f.refusal != "" {
			yield(capsuleprotocol.LLMStreamFrame{}, &capsuleprotocol.PlatformError{Code: f.refusal})
			return
		}
		if !yield(capsuleprotocol.LLMStreamFrame{Type: "start"}, nil) {
			return
		}
		event := func(name, data string) bool {
			return yield(capsuleprotocol.LLMStreamFrame{Type: "event", Event: &capsuleprotocol.LLMStreamEvent{Name: name, Data: json.RawMessage(data)}}, nil)
		}
		if !event("", `{"model":"private-upstream","choices":[{"delta":{"content":"early"}}]}`) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-f.finish:
		}
		if f.cut {
			yield(capsuleprotocol.LLMStreamFrame{Type: "end", Outcome: "outcome_unknown"}, nil)
			return
		}
		if !event("", `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`) {
			return
		}
		yield(capsuleprotocol.LLMStreamFrame{Type: "end", Outcome: "completed"}, nil)
	}
}

func TestModelEndpointFlushesNativeEventsBeforeTheEnd(t *testing.T) {
	for _, cut := range []bool{false, true} {
		f := &nativeForwarder{finish: make(chan struct{}), cut: cut}
		cfg, err := ParseConfig([]byte(`{"version":1,"command":["/bin/true"],"models":{"client":"fast"}}`))
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(&ModelEndpoint{Config: cfg, Platform: f})
		req, err := http.NewRequestWithContext(t.Context(), "POST", srv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"client","stream":true}`))
		if err != nil {
			t.Fatal(err)
		}
		c := &http.Client{Timeout: 5 * time.Second}
		response, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		scan := bufio.NewReader(response.Body)
		first, err := scan.ReadString('\n')
		close(f.finish)
		rest, readErr := io.ReadAll(scan)
		response.Body.Close()
		srv.Close()
		if err != nil || readErr != nil || response.StatusCode != 200 || !strings.Contains(first, `"content":"early"`) || !strings.Contains(first, `"model":"client"`) || strings.Contains(first, "private-upstream") {
			t.Fatal(first, err, readErr)
		}
		if strings.Contains(string(rest), "[DONE]") == cut || strings.Contains(string(rest), "api_error") != cut || strings.Contains(string(rest), "prompt_tokens") || len(f.calls) != 0 {
			t.Fatal("terminal", string(rest), f.calls)
		}
	}
}
func TestModelEndpointFallbackKeepsItsKeyAndRefusals(t *testing.T) {
	cfg, _ := ParseConfig([]byte(`{"version":1,"command":["/bin/true"],"models":{"client":"fast"}}`))
	for _, code := range []string{"unavailable", "quota_exceeded", "outcome_unknown"} {
		f := &nativeForwarder{refusal: code, forwarder: forwarder{answer: `{"choices":[{"message":{"content":"fallback"}}]}`}}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"client","stream":true}`))
		(&ModelEndpoint{Config: cfg, Platform: f}).ServeHTTP(w, req)
		if code == "unavailable" {
			if w.Code != 200 || !strings.Contains(w.Body.String(), "[DONE]") || len(f.keys) != 1 || f.keys[0] != f.key {
				t.Fatal(code, w.Code, f.keys, f.key)
			}
		} else if w.Code < 400 || len(f.keys) != 0 {
			t.Fatal(code, w.Code, f.keys)
		}
	}
}

func TestCommandRunnerDeliversProgressAcrossUTF8Boundaries(t *testing.T) {
	home := t.TempDir()
	cfg := Config{TimeoutSeconds: 5, Command: []string{"/bin/sh", "-c", `printf 'first'; while test ! -e continue; do sleep 0.02; done; printf 'last'`}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var seen strings.Builder
	result := CommandRunner(cfg, home)(ctx, Job{ID: "example", Delta: func(text string) {
		seen.WriteString(text)
		if seen.String() == "first" {
			if err := os.WriteFile(filepath.Join(home, "continue"), nil, 0600); err != nil {
				t.Error(err)
			}
		}
	}})
	if !result.Completed || result.Text != "firstlast" || seen.String() != result.Text {
		t.Fatal(result, seen.String())
	}
	seen.Reset()
	writer := &stdoutProgress{delta: func(s string) { seen.WriteString(s) }}
	for _, c := range []byte("a😃\x00b") {
		_, _ = writer.Write([]byte{c})
	}
	writer.flush()
	if seen.String() != "a😃b" {
		t.Fatal(seen.String())
	}
}

func TestA2AStreamingAndResubscriptionUseTheSameTask(t *testing.T) {
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, j Job) string {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c, _, err := l.client(bounded, "b")
		if err != nil {
			t.Error(err)
			return ""
		}
		var id a2a.TaskID
		for event, err := range c.SendStreamingMessage(bounded, &a2a.SendMessageRequest{Message: text("ask")}) {
			if err != nil {
				t.Error(err)
				return ""
			}
			task, ok := event.(*a2a.Task)
			if !ok {
				t.Errorf("initial event %T", event)
				return ""
			}
			id = task.ID
			break
		}
		var stages []string
		for event, err := range c.SubscribeToTask(bounded, &a2a.SubscribeToTaskRequest{ID: id}) {
			if err != nil {
				t.Error(err)
				return ""
			}
			switch e := event.(type) {
			case *a2a.Task:
				if e.ID != id {
					t.Error("wrong task", e.ID)
				}
				stages = append(stages, "snapshot")
				l.peers.set(string(id), "PROCESSING")
			case *a2a.TaskStatusUpdateEvent:
				if e.Status.State == a2a.TaskStateWorking {
					stages = append(stages, "working")
					l.peers.mu.Lock()
					l.peers.replies[string(id)] = &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "answer"}}}
					l.peers.mu.Unlock()
					l.peers.set(string(id), "REPLIED")
				}
				if e.Status.State == a2a.TaskStateCompleted {
					stages = append(stages, "completed")
				}
			case *a2a.TaskArtifactUpdateEvent:
				if !e.LastChunk || e.Artifact.Parts[0].Content != a2a.Text("answer") {
					t.Error("artifact", e)
				}
				stages = append(stages, "reply")
			}
		}
		if got := strings.Join(stages, ","); got != "snapshot,working,reply,completed" {
			t.Error("events", got)
		}
		return "done"
	})
	l.deliver(invocation(t, "e1", "test"))
	l.drain()
}
