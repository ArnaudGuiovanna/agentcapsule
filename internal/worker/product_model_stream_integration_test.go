//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
)

// The first text must make the round trip through capsule-init and the guest
// before the provider is allowed to end its response, 290 seconds after opening.
func TestProductWorkerCarriesALongModelStreamToTheGuest(t *testing.T) {
	l := newRegistryLab(t)
	hub, err := pgnotify.New(l.store.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = hub.Run(ctx) }()
	t.Cleanup(func() { stop(); <-done })
	if err := l.worker.EnableOutputStreams(DefaultOutputStreams, hub); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	received := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := func(text string) {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", text)
			w.(http.Flusher).Flush()
		}
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		timer := time.NewTimer(290 * time.Second)
		defer timer.Stop()
		chunk("first")
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				chunk(".")
			case <-timer.C:
				select {
				case <-received:
				case <-r.Context().Done():
					return
				}
				chunk("last")
				fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":37}}\n\ndata: [DONE]\n\n")
				return
			}
		}
	}))
	t.Cleanup(func() { provider.CloseClientConnections(); provider.Close() })
	svc, err := llmservice.New(l.accounts, llmgateway.NewForTests(llmgateway.Config{MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "slow-model", Kind: "openai_compatible", BaseURL: provider.URL, Secret: "test-secret"}, 201, &p)
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "slow", ProviderID: p.ID, UpstreamModel: "model"}, 201, nil)
	l.publishManifest("1.0.0", "opt/model-stream", &[]string{capability.LLMInvoke, capability.StreamOutput})
	agent := l.create("slow-stream", "1.0.0").AgentID
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "long", map[string]any{"content": []map[string]string{{"type": "text", "text": "/llm-stream slow test"}}, "work_timeout_seconds": 600}, 202, &inv)
	l.await("the guest received and relayed first text", true, func() bool {
		var exists bool
		if err := l.db.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM invocation_stream_chunks WHERE operation_id=$1)", inv.ID).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	})
	close(received)
	l.awaitFor("completion of the 290-second provider stream", true, 6*time.Minute, func() bool {
		var state string
		if err := l.db.QueryRow(t.Context(), "SELECT status FROM platform_operations WHERE id=$1", inv.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		switch state {
		case "FAILED", "EXPIRED", "CANCELED":
			t.Fatal("ended before completion", state)
		}
		return state == "SUCCEEDED"
	})
	answer := string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
	if !strings.Contains(answer, "first.") || !strings.Contains(answer, ".last") || calls.Load() != 1 {
		t.Fatal("incomplete answer or repeated provider request", answer, calls.Load())
	}
	var settled int
	if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM llm_usage WHERE agent_id=$1 AND state='settled' AND input_tokens=7 AND output_tokens=37", agent).Scan(&settled); err != nil || settled != 1 {
		t.Fatal("model call settlement", settled, err)
	}
}

func TestProductWorkerBoundsModelStreamsAtSixteen(t *testing.T) {
	l := newRegistryLab(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"held\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer func() { upstream.CloseClientConnections(); upstream.Close() }()
	svc, err := llmservice.New(l.accounts, llmgateway.NewForTests(llmgateway.Config{MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	// The VM's 16 slots are under test, not the service's limit of calls in
	// flight per agent (8 by default).
	svc.LimitCallsPerAgent(16)
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "held-streams", Kind: "openai_compatible", BaseURL: upstream.URL, AuthMode: "none"}, 201, &p)
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "slots", ProviderID: p.ID, UpstreamModel: "held"}, 201, nil)
	l.publishManifest("1.0.0", "opt/model-slots", &[]string{capability.LLMInvoke}, "model-stream-slots")
	agent := l.create("slot-probe", "1.0.0").AgentID
	answer := l.askContent(agent, "slots", []capsuleprotocol.ContentPart{{Type: "text", Text: "/llm slots check"}})
	if len(answer) != 1 || answer[0].Text != "503 unavailable" || calls.Load() != 16 {
		t.Fatal("guest observation", answer, "provider calls", calls.Load())
	}
}
