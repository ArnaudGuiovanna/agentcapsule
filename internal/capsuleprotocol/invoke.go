package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type OwnerMessage struct {
	Content []TextContent `json:"content"`
}

func (m OwnerMessage) Validate() error {
	if len(m.Content) < 1 || len(m.Content) > 32 {
		return ErrProtocol
	}
	n := 0
	for _, c := range m.Content {
		if c.Type != "text" || !utf8.ValidString(c.Text) || strings.TrimSpace(c.Text) == "" || strings.ContainsRune(c.Text, 0) {
			return ErrProtocol
		}
		n += len(c.Text)
	}
	if n > 32*1024 {
		return ErrProtocol
	}
	return nil
}

type InstructionMandate struct {
	ID               string    `json:"id"`
	MaxAgentRequests int       `json:"max_agent_requests"`
	ExpiresAt        time.Time `json:"expires_at"`
}
type Invocation struct {
	Kind        string             `json:"kind"`
	OperationID string             `json:"operation_id"`
	Mandate     InstructionMandate `json:"mandate"`
	Content     []TextContent      `json:"content"`
	// Attachments are opaque references to files the requester uploaded for this
	// invocation. The guest reads them through the platform bridge, only while the
	// invocation runs. Absent when there are none.
	Attachments []AttachmentRef `json:"attachments,omitempty"`
}

// DecodeInvocation validates a host-authored instruction, never an inter-agent
// payload. The envelope and its mandate remain identical across retries. The
// guest clock is not authorization; expiry is checked by the control plane.
func DecodeInvocation(e harnessstore.Event, agent string) (Invocation, error) {
	var in Invocation
	if len(e.Subjects) != 2 || !slices.Contains(e.Subjects, "agent/"+agent) || !slices.Contains(e.Subjects, "event/"+e.ID) {
		return in, ErrProtocol
	}
	if err := decode(bytes.NewReader(e.Body), &in); err != nil {
		return in, err
	}
	if in.Kind != "message.user" || in.OperationID == "" || len(in.OperationID) > 100 || in.Mandate.ID == "" || len(in.Mandate.ID) > 100 ||
		in.Mandate.MaxAgentRequests < 1 || in.Mandate.MaxAgentRequests > 3 || in.Mandate.ExpiresAt.IsZero() {
		return in, ErrProtocol
	}
	if len(in.Attachments) > MaxInvocationAttachments {
		return in, ErrProtocol
	}
	seen := map[string]bool{}
	for _, a := range in.Attachments {
		if err := a.Validate(); err != nil {
			return in, err
		}
		if seen[a.ID] {
			return in, ErrProtocol
		}
		seen[a.ID] = true
	}
	return in, (OwnerMessage{Content: in.Content}).Validate()
}

func isInvocation(e harnessstore.Event) bool {
	var kind struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(e.Body, &kind) == nil && kind.Kind == "message.user"
}

func (c *Client) Invoke(ctx context.Context, e harnessstore.Event) (harnessstore.Receipt, error) {
	if !validEvent(c.identity, e) {
		return harnessstore.Receipt{}, ErrProtocol
	}
	if _, err := DecodeInvocation(e, c.identity.AgentID); err != nil {
		return harnessstore.Receipt{}, err
	}
	r, err := c.call(ctx, "/v1/invoke", &request{Event: &e})
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	if r.Receipt == nil || len(r.Receipt.Result) > MaxContentBytes || !json.Valid(r.Receipt.Result) {
		return harnessstore.Receipt{}, ErrProtocol
	}
	return *r.Receipt, nil
}
