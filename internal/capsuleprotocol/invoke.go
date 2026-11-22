package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type OwnerMessage = wire.OwnerMessage
type InstructionMandate = wire.InstructionMandate
type Invocation = wire.Invocation

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
