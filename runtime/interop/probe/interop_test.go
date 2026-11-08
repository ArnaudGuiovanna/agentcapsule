// Package interopprobe qualifies pinned upstream libraries independently of the
// control plane. These are synthetic inputs; no tenant data or secrets are used.
package interopprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	directory "github.com/agntcy/dir/client"
	"github.com/agntcy/oasf-sdk/pkg/decoder"
	slim "github.com/agntcy/slim-bindings-go/v3"
)

// This uses the upstream server and client over real loopback HTTP, not a mock
// transport. The task store is intentionally upstream's in-memory default.
func TestA2AJSONRPCTaskRoundTrip(t *testing.T) {
	if a2a.Version != "1.0" {
		t.Fatalf("wire version changed: %s", a2a.Version)
	}
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			for _, event := range []a2a.Event{
				a2a.NewSubmittedTask(ec, ec.Message),
				a2a.NewStatusUpdateEvent(ec, a2a.TaskStateWorking, nil),
				a2a.NewArtifactEvent(ec, a2a.NewTextPart("synthetic review complete")),
				a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil),
			} {
				if !yield(event, nil) {
					return
				}
			}
		}
	})
	mux := http.NewServeMux()
	handler := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor))
	var mu sync.Mutex
	var requests []map[string]any
	var responses []map[string]any
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			t.Error(err)
			http.Error(w, "read failed", 400)
			return
		}
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			http.Error(w, "invalid JSON", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		var response map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Error(err)
		}
		mu.Lock()
		requests = append(requests, request)
		responses = append(responses, response)
		mu.Unlock()
		for key, values := range recorder.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	card := &a2a.AgentCard{
		Name: "Synthetic interop probe", Description: "Local qualification only", Version: "0.1.0",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(server.URL+"/invoke", a2a.TransportProtocolJSONRPC)},
		DefaultInputModes:   []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"},
		Skills: []a2a.AgentSkill{{ID: "document-review", Name: "Synthetic review", Description: "Synthetic text only", Tags: []string{"test"}}},
	}
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	resolved, err := agentcard.DefaultResolver.Resolve(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Capabilities.Streaming || len(resolved.SupportedInterfaces) != 1 {
		t.Fatal("unexpected advertised profile")
	}
	client, err := a2aclient.NewFromCard(ctx, resolved)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("synthetic document"))})
	if err != nil {
		t.Fatal(err)
	}
	task, ok := result.(*a2a.Task)
	if !ok {
		t.Fatalf("expected Task, got %T", result)
	}
	if task.ID == "" || task.ContextID == "" || task.Status.State != a2a.TaskStateCompleted || len(task.Artifacts) != 1 {
		t.Fatalf("incomplete task: %#v", task)
	}
	if len(task.Artifacts[0].Parts) != 1 || task.Artifacts[0].Parts[0].Content != a2a.Text("synthetic review complete") {
		t.Fatal("artifact did not survive wire roundtrip")
	}
	retrieved, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.ID != task.ID || retrieved.Status.State != a2a.TaskStateCompleted {
		t.Fatal("GetTask mismatch")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("expected two HTTP requests, got %d", len(requests))
	}
	for i, method := range []string{"SendMessage", "GetTask"} {
		if requests[i]["jsonrpc"] != "2.0" || requests[i]["method"] != method {
			t.Fatalf("wire method %d: %#v", i, requests[i])
		}
		if requests[i]["id"] != responses[i]["id"] || responses[i]["error"] != nil {
			t.Fatal("JSON-RPC response correlation failed")
		}
	}
	t.Log("A2A wire=1.0 JSON-RPC SendMessage/GetTask; completed task and artifact verified")
}

func TestOASFVersionedDecoding(t *testing.T) {
	// Decoding verifies representation compatibility, NOT schema/taxonomy validation.
	raw := []byte(`{"schema_version":"1.1.0","name":"Synthetic interop probe","version":"0.1.0","description":"Synthetic data only"}`)
	record, err := decoder.JsonToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decoder.DecodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetV1() == nil || decoded.GetV1().GetName() != "Synthetic interop probe" {
		t.Fatal("OASF v1 representation mismatch")
	}
	bad, err := decoder.JsonToProto([]byte(`{"schema_version":"2.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.DecodeRecord(bad); err == nil {
		t.Fatal("unsupported major version accepted")
	}
	t.Log("OASF 1.1.0 SDK decoding verified; schema validation requires OASF server and was not executed")
}

func TestDirectoryClientBuildAndConfiguration(t *testing.T) {
	// NewClient is lazy: no RPC, server availability or auth success is asserted.
	client, err := directory.New(t.Context(), directory.WithConfig(&directory.Config{ServerAddress: "127.0.0.1:1"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.New(t.Context(), directory.WithConfig(&directory.Config{ServerAddress: "127.0.0.1:1", AuthMode: "invalid-probe-mode"})); err == nil {
		t.Fatal("invalid auth mode accepted")
	}
	t.Log("Directory SDK build and configuration checked; no Directory server/RPC executed")
}

func TestSLIMNativeABI(t *testing.T) {
	// The FFI v3.3.9 reexports core v3.4.6; GetVersion reports the core crate.
	if slim.GetVersion() != "3.4.6" {
		t.Fatalf("wrong native version: %s", slim.GetVersion())
	}
	info := slim.GetBuildInfo()
	if info.Version != "3.4.6" || info.Profile != "release" || info.BuildDate == "" {
		t.Fatalf("unexpected native build metadata: %#v", info)
	}
	// The official binary has an empty GitSha. Artifact identity is checked by
	// the runner's pinned archive/library SHA256, not inferred from this field.
	name := slim.NewName("interop", "local", "synthetic-agent")
	defer name.Destroy()
	if !reflect.DeepEqual(name.Components(), []string{"interop", "local", "synthetic-agent"}) {
		t.Fatal("native name roundtrip failed")
	}
	if _, err := slim.NewConfigFromJson(`{"endpoint":"http://127.0.0.1:46357","tls":{"insecure":true}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := slim.NewConfigFromJson(`not-json`); err == nil {
		t.Fatal("native parser accepted invalid input")
	}
	t.Logf("SLIM native ABI version=%s git=%s profile=%s; no node or message exchange executed", info.Version, info.GitSha, info.Profile)
}
