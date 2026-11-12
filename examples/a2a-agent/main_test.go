package main

import (
	"context"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/agentadapter"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// peers stands for the adapter's endpoint: agent b's card at /agents/b and its
// JSON-RPC endpoint at the same URL.
func peers(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	b := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			question := string(ec.Message.Parts[0].Content.(a2a.Text))
			for _, e := range []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message), a2a.NewStatusUpdateEvent(ec, a2a.TaskStateWorking, nil),
				a2a.NewArtifactEvent(ec, a2a.NewTextPart("b heard "+question)), a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil)} {
				if !yield(e, nil) {
					return
				}
			}
		}
	})
	card := a2asrv.NewStaticAgentCardHandler(&a2a.AgentCard{Name: "b", Version: "1",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(server.URL+"/agents/b", a2a.TransportProtocolJSONRPC)},
		DefaultInputModes:   []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"}})
	rpc := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(b))
	mux.HandleFunc("/agents/b", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			card.ServeHTTP(w, r)
			return
		}
		rpc.ServeHTTP(w, r)
	})
	return server
}

// say sends text to the agent with the official client and returns the text
// of the completed task.
func say(t *testing.T, url, text string) string {
	t.Helper()
	card, err := agentcard.DefaultResolver.Resolve(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	client, err := a2aclient.NewFromCard(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SendMessage(t.Context(), &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(text))})
	if err != nil {
		t.Fatal(err)
	}
	task, ok := result.(*a2a.Task)
	if !ok || task.Status.State != a2a.TaskStateCompleted || len(task.Artifacts) != 1 {
		t.Fatalf("%#v", result)
	}
	return string(task.Artifacts[0].Parts[0].Content.(a2a.Text))
}

func TestTheAgentAnswersAndAsksAnotherAgent(t *testing.T) {
	registry := peers(t)
	mux := http.NewServeMux()
	agent := httptest.NewServer(mux)
	defer agent.Close()
	mux.Handle("/", newAgent(agent.URL, registry.URL))
	if got := say(t, agent.URL, "hello there"); got != "echo: hello there" {
		t.Fatal(got)
	}
	if got := say(t, agent.URL, "ask b what is the time?"); got != "b answered: b heard what is the time?" {
		t.Fatal(got)
	}
	if got := say(t, agent.URL, "ask c anything"); !strings.HasPrefix(got, "could not ask c: ") {
		t.Fatal(got)
	}
	if got := say(t, agent.URL, "ask b"); !strings.HasPrefix(got, "could not ask b: usage") {
		t.Fatal(got)
	}
}

// The adapter accepts the configuration shipped in the package: it runs the
// agent as a server on the address the agent listens on.
func TestTheAdapterConfiguration(t *testing.T) {
	cfg, err := agentadapter.LoadConfig("adapter.json")
	if err != nil || cfg.Server == nil || cfg.Server.URL != "http://127.0.0.1:9100" ||
		strings.Join(cfg.Server.Command, " ") != "/opt/agent/a2a-agent -listen 127.0.0.1:9100" {
		t.Fatal(cfg, err)
	}
}
