// Command a2a-agent is a small agent written against the official A2A Go SDK
// (github.com/a2aproject/a2a-go/v2). It knows nothing about Agent Capsule: it
// serves A2A on the address it is given and, when asked to, calls another A2A
// agent whose card it finds under the URL in AGENTCAPSULE_A2A_URL, as it would
// under any registry of A2A agents.
//
//	a2a-agent -listen 127.0.0.1:9100
//
// A message "ask <agent> <question>" sends the question to that agent and
// answers with its reply. "find <skill> <question>" first lists the agents
// offering that OASF skill (<AGENTCAPSULE_A2A_URL>/agents?skill=<skill>) and
// asks the first one. Any other message is answered with its own text.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to serve A2A on")
	flag.Parse()
	server := &http.Server{Addr: *listen, Handler: newAgent("http://"+*listen, os.Getenv("AGENTCAPSULE_A2A_URL")), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// newAgent serves the agent's card and its JSON-RPC endpoint at self; peers
// is where other agents' cards are, at <peers>/agents/<id>.
func newAgent(self, peers string) http.Handler {
	card := &a2a.AgentCard{
		Name:                "a2a-agent",
		Description:         "Answers with the text it receives, or asks another agent.",
		Version:             "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(self, a2a.TransportProtocolJSONRPC)},
		DefaultInputModes:   []string{"text/plain"},
		DefaultOutputModes:  []string{"text/plain"},
		Skills: []a2a.AgentSkill{
			{ID: "echo", Name: "Echo", Description: "Answers with the text it receives.", Tags: []string{"text"}},
			{ID: "ask", Name: "Ask another agent", Description: "ask <agent> <question>: asks that agent and answers with its reply.", Tags: []string{"text"}},
			{ID: "find", Name: "Find and ask an agent", Description: "find <OASF skill> <question>: asks the first agent offering that skill.", Tags: []string{"text"}},
		},
	}
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor(peers))))
	return mux
}

func executor(peers string) a2asrv.AgentExecutor {
	return a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) || !yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateWorking, nil), nil) {
				return
			}
			text := ""
			for _, p := range ec.Message.Parts {
				if t, ok := p.Content.(a2a.Text); ok {
					text += string(t)
				}
			}
			answer := "echo: " + text
			switch verb, rest, _ := strings.Cut(text, " "); verb {
			case "ask":
				agent, question, _ := strings.Cut(rest, " ")
				reply, err := ask(ctx, peers, agent, question)
				if err != nil {
					answer = fmt.Sprintf("could not ask %s: %v", agent, err)
				} else {
					answer = agent + " answered: " + reply
				}
			case "find":
				skill, question, _ := strings.Cut(rest, " ")
				agent, reply, err := find(ctx, peers, skill, question)
				switch {
				case err != nil:
					answer = fmt.Sprintf("could not find an agent offering skill %s: %v", skill, err)
				case agent == "":
					answer = "no agent offers skill " + skill
				default:
					answer = agent + " answered: " + reply
				}
			}
			if yield(a2a.NewArtifactEvent(ec, a2a.NewTextPart(answer)), nil) {
				yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
			}
		}
	})
}

// ask sends question to agent and returns the text of its reply. It does not
// hold the call open while the other agent works: it sends the message, then
// follows the task until it ends.
func ask(ctx context.Context, peers, agent, question string) (string, error) {
	if peers == "" || agent == "" || question == "" {
		return "", errors.New("usage: ask <agent> <question>, with AGENTCAPSULE_A2A_URL set")
	}
	card, err := agentcard.DefaultResolver.Resolve(ctx, strings.TrimRight(peers, "/")+"/agents/"+agent)
	if err != nil {
		return "", err
	}
	return askCard(ctx, card, question)
}

// find lists the agents offering skill, as a registry of A2A agents would,
// and asks the first one. It returns "" and no error when none does.
func find(ctx context.Context, peers, skill, question string) (string, string, error) {
	if peers == "" || skill == "" || question == "" {
		return "", "", errors.New("usage: find <skill> <question>, with AGENTCAPSULE_A2A_URL set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(peers, "/")+"/agents?skill="+skill, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("the registry answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var list struct {
		Agents []*a2a.AgentCard `json:"agents"`
	}
	if err = json.Unmarshal(body, &list); err != nil {
		return "", "", err
	}
	if len(list.Agents) == 0 {
		return "", "", nil
	}
	card := list.Agents[0]
	reply, err := askCard(ctx, card, question)
	return card.Name, reply, err
}

// askCard sends question to the agent the card describes and returns the text
// of its reply.
func askCard(ctx context.Context, card *a2a.AgentCard, question string) (string, error) {
	client, err := a2aclient.NewFromCard(ctx, card)
	if err != nil {
		return "", err
	}
	defer client.Destroy()
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(question)),
		Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
	if err != nil {
		return "", err
	}
	var task *a2a.Task
	switch r := result.(type) {
	case *a2a.Message:
		return text(r.Parts), nil
	case *a2a.Task:
		task = r
	default:
		return "", errors.New("unexpected answer")
	}
	for !task.Status.State.Terminal() {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if task, err = client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID}); err != nil {
			return "", err
		}
	}
	if task.Status.State != a2a.TaskStateCompleted {
		return "", fmt.Errorf("the task ended %s", task.Status.State)
	}
	var parts a2a.ContentParts
	for _, a := range task.Artifacts {
		parts = append(parts, a.Parts...)
	}
	return text(parts), nil
}

func text(parts a2a.ContentParts) string {
	var out []string
	for _, p := range parts {
		if t, ok := p.Content.(a2a.Text); ok {
			out = append(out, string(t))
		}
	}
	return strings.Join(out, "\n")
}
