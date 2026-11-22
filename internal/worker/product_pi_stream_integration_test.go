//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
)

// Forward real provider SSE bytes. Hold the provider stream after its first
// text event until the public API client observes Pi's output from the VM.
func TestProductPiStreamsBeforeTheProviderFinishes(t *testing.T) {
	pkg, base, model := os.Getenv("AGENTCAPSULE_KVM_PI_HARNESS"), os.Getenv("AGENTCAPSULE_KVM_PI_MODEL_URL"), os.Getenv("AGENTCAPSULE_KVM_PI_MODEL")
	if pkg == "" || base == "" || model == "" {
		t.Fatal("verify-product-guest.py --pi-harness and --pi-model-url are required")
	}
	l := newRegistryLab(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	h, err := pgnotify.New(l.store.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	hubCtx, stopHub := context.WithCancel(ctx)
	hubDone := make(chan struct{})
	go func() { defer close(hubDone); _ = h.Run(hubCtx) }()
	defer func() { stopHub(); <-hubDone }()
	if err = l.worker.EnableOutputStreams(DefaultOutputStreams, h); err != nil {
		t.Fatal(err)
	}
	if err = l.handler.StartEventStreams(ctx, 8); err != nil {
		t.Fatal(err)
	}

	first := make(chan time.Time, 1)
	released := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(released) }) }
	defer unblock()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(base, "/")+"/chat/completions", r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if key := os.Getenv("AGENTCAPSULE_KVM_PI_API_KEY"); key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			t.Errorf("provider HTTP %d", res.StatusCode)
			w.WriteHeader(res.StatusCode)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		scan := bufio.NewScanner(res.Body)
		scan.Buffer(make([]byte, 4096), 1<<20)
		hold, observed := false, false
		for scan.Scan() {
			line := scan.Text()
			if !observed && strings.HasPrefix(line, "data:") {
				var chunk struct {
					Choices []struct{ Delta struct{ Content string } }
				}
				if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &chunk) == nil && len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
					first <- time.Now()
					hold, observed = true, true
				}
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return
			}
			if line == "" {
				w.(http.Flusher).Flush()
				if hold {
					select {
					case <-released:
					case <-r.Context().Done():
						return
					case <-time.After(20 * time.Second):
						t.Error("Pi failed to emit the first provider fragment before completion")
						return
					}
					hold = false
				}
			}
		}
		if err := scan.Err(); err != nil && r.Context().Err() == nil {
			t.Error(err)
		}
	}))
	defer func() { unblock(); upstream.CloseClientConnections(); upstream.Close() }()
	svc, err := llmservice.New(l.accounts, llmgateway.NewForTests(llmgateway.Config{MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var provider controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "observed-stream", Kind: "openai_compatible", BaseURL: upstream.URL, AuthMode: "none"}, 201, &provider)
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "pi-model", ProviderID: provider.ID, UpstreamModel: model}, 201, nil)
	ref := l.importPackage(pkg, "acme/pi-agent", "1.0.0")
	agent := l.createWith("pi-stream", "pi-agent", "1.0.0", 1024).AgentID
	l.bootsFrom(agent, ref, 1)
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "pi-stream", map[string]any{"content": []map[string]string{{"type": "text", "text": "In one sentence, describe a bicycle. Use no tools."}}}, 202, &inv)
	req, err := http.NewRequestWithContext(ctx, "GET", l.server.URL+"/v1/invocations/"+inv.ID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+l.user())
	c := *l.server.Client()
	c.Timeout = 0
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("subscriber HTTP status", resp.StatusCode)
	}
	type observed struct {
		latency time.Duration
		deltas  int
		text    strings.Builder
		final   json.RawMessage
		err     error
	}
	done := make(chan *observed, 1)
	go func() {
		o := &observed{}
		defer func() { unblock(); done <- o }()
		scan := bufio.NewScanner(resp.Body)
		var event string
		for scan.Scan() {
			line := scan.Text()
			if s, ok := strings.CutPrefix(line, "event: "); ok {
				event = s
			}
			data, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				continue
			}
			switch event {
			case "delta":
				var delta struct{ Text string }
				if err := json.Unmarshal([]byte(data), &delta); err != nil {
					o.err = err
					return
				}
				if o.deltas == 0 {
					select {
					case start := <-first:
						o.latency = time.Since(start)
					case <-ctx.Done():
						o.err = ctx.Err()
						return
					}
					unblock()
				}
				o.deltas++
				o.text.WriteString(delta.Text)
			case "end":
				var e struct{ Result json.RawMessage }
				o.err = json.Unmarshal([]byte(data), &e)
				o.final = e.Result
				return
			}
		}
		o.err = errors.Join(errors.New("subscription ended before the result"), scan.Err())
	}()
	var outcome *observed
	l.awaitFor("Pi emits during an open model stream and files its result", true, 4*time.Minute, func() bool {
		select {
		case outcome = <-done:
			return true
		default:
			return false
		}
	})
	var final map[string]any
	var inline map[string]any
	b := l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil)
	if outcome.err != nil || outcome.deltas < 1 || json.Unmarshal(outcome.final, &inline) != nil || json.Unmarshal(b, &final) != nil {
		t.Fatal("invalid stream or result", outcome.err, outcome.deltas)
	}
	a, _ := json.Marshal(final)
	v, _ := json.Marshal(inline)
	var result struct{ Content []struct{ Text string } }
	if !bytes.Equal(a, v) || json.Unmarshal(b, &result) != nil || len(result.Content) != 1 || result.Content[0].Text != outcome.text.String() {
		t.Fatal("streamed text, end and /result diverged")
	}
	t.Logf("provider text to first public SSE delta: %s; %d output deltas", outcome.latency, outcome.deltas)
	if outcome.latency >= time.Second {
		t.Fatal("first delta exceeded one second")
	}
}
