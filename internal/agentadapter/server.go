package agentadapter

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
)

// Readiness tells whether the agent's server accepts connections.
type Readiness interface {
	// WaitReady returns once the server accepts connections, or the error
	// that ends the wait.
	WaitReady(context.Context) error
}

// ServerRunner sends each job to an agent that serves A2A: the job's text is
// one message, and the task's text artifacts are the answer. The message ID
// is derived from the job, so a job run again after a restart sends the same
// message. A task that ends in any state but completed, or that asks for
// input, is a failed run.
func ServerRunner(cfg Config, server Readiness) Runner {
	return func(ctx context.Context, job Job) Output {
		ctx, cancel := context.WithTimeout(ctx, cfg.Timeout())
		defer cancel()
		ready, stop := context.WithTimeout(ctx, cfg.Server.Ready())
		err := server.WaitReady(ready)
		stop()
		if err != nil {
			return Output{}
		}
		// The adapter calls the configured address, never one taken from the
		// agent's card.
		client, err := a2aclient.NewFromEndpoints(ctx, []*a2a.AgentInterface{a2a.NewAgentInterface(cfg.Server.URL, a2a.TransportProtocolJSONRPC)})
		if err != nil {
			return Output{}
		}
		defer client.Destroy()
		m := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(job.Text))
		m.ID = "agentcapsule-" + job.ID
		result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: m, Config: &a2a.SendMessageConfig{ReturnImmediately: true}})
		if err != nil {
			return Output{}
		}
		var task *a2a.Task
		switch r := result.(type) {
		case *a2a.Message:
			return answerOf(r.Parts, nil)
		case *a2a.Task:
			task = r
		default:
			return Output{}
		}
		poll := time.NewTicker(500 * time.Millisecond)
		defer poll.Stop()
		for !task.Status.State.Terminal() {
			if task.Status.State == a2a.TaskStateInputRequired || task.Status.State == a2a.TaskStateAuthRequired {
				// No one can answer it here: end the task rather than leave it waiting.
				_, _ = client.CancelTask(ctx, &a2a.CancelTaskRequest{ID: task.ID})
				return Output{}
			}
			select {
			case <-ctx.Done():
				return Output{}
			case <-poll.C:
			}
			next, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
			if err != nil {
				if errors.Is(err, a2a.ErrTaskNotFound) {
					return Output{} // the server lost it, typically by restarting
				}
				continue // transient: ask again
			}
			task = next
		}
		if task.Status.State != a2a.TaskStateCompleted {
			return Output{}
		}
		var artifacts a2a.ContentParts
		for _, a := range task.Artifacts {
			artifacts = append(artifacts, a.Parts...)
		}
		var status a2a.ContentParts
		if task.Status.Message != nil {
			status = task.Status.Message.Parts
		}
		return answerOf(artifacts, status)
	}
}

// answerOf keeps the text of the parts, or of fallback when they hold none.
func answerOf(parts, fallback a2a.ContentParts) Output {
	texts := func(parts a2a.ContentParts) []string {
		var out []string
		for _, p := range parts {
			if t, ok := p.Content.(a2a.Text); ok {
				out = append(out, string(t))
			}
		}
		return out
	}
	text := texts(parts)
	if len(text) == 0 {
		text = texts(fallback)
	}
	return Output{Completed: true, Text: strings.Join(text, "\n\n")}
}
