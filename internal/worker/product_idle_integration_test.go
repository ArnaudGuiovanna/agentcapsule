//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// onlyCapacity accepts a pass whose only failures are jobs that wait in the
// capacity queue (ADR 017), never one that also hides another failure.
func onlyCapacity(err error) bool {
	if err == runtime.ErrCapacity {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyCapacity(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyCapacity(wrapped.Unwrap())
	}
	return false
}

// awaitQueued is await for stages where work may wait for a VM slot: a pass
// whose only failures are jobs waiting in the capacity queue is no failure.
func (l *productPeerLab) awaitQueued(stage string, check func() bool) {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(l.t.Context(), 2*time.Minute)
	defer cancel()
	opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
	for !check() {
		if err := l.worker.DispatchPass(ctx, opts, 90*time.Second); err != nil && !onlyCapacity(err) {
			l.t.Fatal(stage, "worker dispatch", err)
		}
		select {
		case <-ctx.Done():
			l.t.Fatal(stage, "did not reach expected state", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// heldModel is an organization's model provider whose calls wait until the
// test releases them.
type heldModel struct {
	calls   atomic.Int32
	release chan struct{}
	once    sync.Once
}

func (m *heldModel) open() { m.once.Do(func() { close(m.release) }) }

// enableHeldModel serves the alias "fast" of the lab's organization from a
// provider that holds each call until open.
func (l *registryLab) enableHeldModel() *heldModel {
	t := l.t
	t.Helper()
	m := &heldModel{release: make(chan struct{})}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Messages) != 1 || r.Header.Get("Authorization") != "Bearer kvm-model-secret" {
			http.Error(w, "bad request", 400)
			return
		}
		m.calls.Add(1)
		select {
		case <-m.release:
		case <-r.Context().Done():
			return
		}
		answer, _ := json.Marshal("model answer to: " + req.Messages[0].Content)
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"content":%s},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`, answer)
	}))
	t.Cleanup(provider.Close)
	t.Cleanup(m.open) // runs first: a held call ends before the server closes
	svc, err := controlplane.NewLLMService(l.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 4 * time.Minute, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "held-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "host"}, 201, nil)
	return m
}

// On a host with one VM slot, work wakes a stopped agent without anyone
// asking (EVT-002), and the idle loop never stops an agent whose work is not
// done (EVT-010):
//   - an invocation for the stopped agent a boots it: a reads STOPPED, then
//     READY with its invocation "working" (the code has no BUSY state: a
//     working agent is READY with a working invocation), and no wake
//     command was given;
//   - the idle loop, ten minutes past a's idle timeout, does not put a to
//     sleep while its invocation works on a model call;
//   - an invocation for the stopped agent b waits for the slot: b reads
//     QUEUED (ADR 017) while a computes, and a is not stopped for it;
//   - once a's model call ends, b takes a's slot, reads READY and answers;
//   - the idle loop then stops b, which has nothing left to do.
func TestProductWorkerWakesQueuesAndKeepsAWorkingAgentAwake(t *testing.T) {
	labRuntimeOptions = func(o *runtime.FirecrackerOptions) { o.MaxActive = 1 }
	t.Cleanup(func() { labRuntimeOptions = nil })
	l := newRegistryLab(t)
	model := l.enableHeldModel()
	a := l.createOn("busy-a", "reference", "1.0.0").AgentID
	l.lifecycle(a, "sleep", "busy-a-sleep")
	b := l.createOn("queued-b", "reference", "1.0.0").AgentID
	l.lifecycle(b, "sleep", "queued-b-sleep")
	l.runs(0)
	l.request(l.owner(), "POST", "/v1/agents/"+a+"/idle-policy", "busy-a-idle", map[string]int{"idle_timeout_seconds": 60}, 200, nil)
	operations := func(agent, kind string) int {
		t.Helper()
		var n int
		if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM platform_operations WHERE agent_id=$1 AND kind=$2", agent, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	state := func(id string) string {
		t.Helper()
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State
	}
	observe := func(agent string, seen *[]string) string {
		t.Helper()
		s := l.agentState(agent)
		if len(*seen) == 0 || (*seen)[len(*seen)-1] != s {
			*seen = append(*seen, s)
		}
		return s
	}
	pass := func(stage string) {
		t.Helper()
		opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
		if err := l.worker.DispatchPass(t.Context(), opts, 90*time.Second); err != nil {
			t.Fatal(stage, "worker dispatch", err)
		}
	}

	t.Log("stage: work arrives for the stopped agent a: it wakes unattended, READY with its invocation working")
	wakesA := operations(a, "wake")
	var seenA []string
	if observe(a, &seenA) != "STOPPED" {
		t.Fatal("a is not stopped", seenA)
	}
	held := l.invoke(a, "held", "/llm fast hold this call")
	l.await("a working on its model call", true, func() bool {
		return observe(a, &seenA) == "READY" && state(held) == "working" && model.calls.Load() == 1
	})
	for _, s := range seenA {
		if s != "STOPPED" && s != "STARTING" && s != "READY" {
			t.Fatal("a went through another state", seenA)
		}
	}
	if operations(a, "wake") != wakesA {
		t.Fatal("a wake command was given")
	}
	runA := l.runs(1)[a]

	t.Log("stage: the idle loop, past a's idle timeout, does not stop a while its invocation works")
	now := time.Now()
	if _, err := l.store.ScheduleIdleSleeps(t.Context(), "local", &now, 8); err != nil {
		t.Fatal(err)
	}
	later := now.Add(10 * time.Minute)
	if n, err := l.store.ScheduleIdleSleeps(t.Context(), "local", &later, 8); err != nil || n != 0 {
		t.Fatal("the idle loop put a working agent to sleep", n, err)
	}
	sleepsA := operations(a, "sleep")
	for range 3 {
		pass("idle loop while a works")
	}
	if run, ok := l.runs(1)[a]; !ok || run.ID != runA.ID || operations(a, "sleep") != sleepsA || state(held) != "working" || l.agentState(a) != "READY" {
		t.Fatal("a was stopped, or its work ended, during the idle loop")
	}

	t.Log("stage: work for the stopped agent b waits for the slot: b is QUEUED while a computes")
	wakesB := operations(b, "wake")
	seenB := []string{}
	if observe(b, &seenB) != "STOPPED" {
		t.Fatal("b is not stopped", seenB)
	}
	queued := l.invoke(b, "queued", "waits for a slot")
	l.awaitQueued("b waiting for a's slot", func() bool { return observe(b, &seenB) == "QUEUED" })
	if run, ok := l.runs(1)[a]; !ok || run.ID != runA.ID {
		t.Fatal("a computing VM was stopped for queued work")
	}
	if got := state(queued); got != "accepted" || state(held) != "working" {
		t.Fatal("the queued invocation, or a's work", got)
	}

	t.Log("stage: once a's model call ends, b takes the slot, reads READY and answers")
	model.open()
	l.awaitQueued("b's answer once a is done", func() bool {
		observe(b, &seenB)
		return l.answered(held, "model answer to: hold this call") && l.answered(queued, "waits for a slot")
	})
	if observe(b, &seenB) != "READY" || slices.Index(seenB, "QUEUED") < 0 || slices.Index(seenB, "QUEUED") > slices.Index(seenB, "READY") {
		t.Fatal("b's states", strings.Join(seenB, " -> "))
	}
	if _, ok := l.runs(1)[b]; !ok {
		t.Fatal("b does not run in a's slot")
	}
	if operations(b, "wake") != wakesB {
		t.Fatal("a wake command was given to b")
	}
	t.Log("a:", strings.Join(seenA, " -> "), "; b:", strings.Join(seenB, " -> "))

	t.Log("stage: the idle loop stops b once it has nothing to do")
	l.request(l.owner(), "POST", "/v1/agents/"+b+"/idle-policy", "queued-b-idle", map[string]int{"idle_timeout_seconds": 60}, 200, nil)
	sleepsB := operations(b, "sleep")
	now = time.Now()
	if _, err := l.store.ScheduleIdleSleeps(t.Context(), "local", &now, 8); err != nil {
		t.Fatal(err)
	}
	later = now.Add(10 * time.Minute)
	if n, err := l.store.ScheduleIdleSleeps(t.Context(), "local", &later, 8); err != nil || n != 1 {
		t.Fatal("the idle loop did not stop the idle agent", n, err)
	}
	l.await("b put to sleep by its idle policy", true, func() bool { return l.agentState(b) == "STOPPED" })
	l.runs(0)
	if operations(b, "sleep") != sleepsB+1 {
		t.Fatal("b's sleep is not the idle policy's one")
	}
}
