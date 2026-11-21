package agentadapter

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aevent"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
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
		if len(job.Content) > 0 {
			// Text parts as text, JSON parts as A2A data parts.
			if m.Parts, err = toParts(job.Content); err != nil {
				return Output{}
			}
		}
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
		// Subscribe to the submitted task where the server supports it. If a
		// stream disconnects, resume polling that same task without resubmission.
		if job.Delta != nil && !task.Status.State.Terminal() {
			for event, err := range client.SubscribeToTask(ctx, &a2a.SubscribeToTaskRequest{ID: task.ID}) {
				if err != nil {
					break
				}
				updated, err := a2aevent.ApplyShallowUpdate(task, event)
				if err != nil {
					break
				}
				task = updated
				if a, ok := event.(*a2a.TaskArtifactUpdateEvent); ok && a.Artifact != nil {
					for _, part := range a.Artifact.Parts {
						if v, ok := part.Content.(a2a.Text); ok {
							job.Delta(string(v))
						}
					}
				}
				if task.Status.State.Terminal() || task.Status.State == a2a.TaskStateInputRequired || task.Status.State == a2a.TaskStateAuthRequired {
					break
				}
			}
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

// answerOf keeps the text and data parts of parts, or of fallback when they
// hold none. Data parts become JSON parts; other parts are dropped.
func answerOf(parts, fallback a2a.ContentParts) Output {
	content := fromParts(parts)
	if len(content) == 0 {
		content = fromParts(fallback)
	}
	out := Output{Completed: true, Text: joined(content)}
	if capsuleprotocol.HasJSON(content) {
		out.Content = content
	}
	return out
}

// fromParts keeps the text parts and the data parts, as JSON parts.
func fromParts(parts a2a.ContentParts) []capsuleprotocol.ContentPart {
	var out []capsuleprotocol.ContentPart
	for _, p := range parts {
		switch v := p.Content.(type) {
		case a2a.Text:
			out = append(out, capsuleprotocol.ContentPart{Type: "text", Text: string(v)})
		case a2a.Data:
			if b, err := json.Marshal(v.Value); err == nil && v.Value != nil {
				out = append(out, capsuleprotocol.ContentPart{Type: "json", JSON: capsuleprotocol.JSONValue(b)})
			}
		}
	}
	return out
}

// toParts gives text parts as A2A text parts and JSON parts as data parts.
func toParts(content []capsuleprotocol.ContentPart) (a2a.ContentParts, error) {
	out := make(a2a.ContentParts, 0, len(content))
	for _, c := range content {
		if c.Type != "json" {
			out = append(out, a2a.NewTextPart(c.Text))
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(c.JSON), &v); err != nil {
			return nil, err
		}
		out = append(out, a2a.NewDataPart(v))
	}
	return out, nil
}
