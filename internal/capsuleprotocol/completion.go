package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

// An instruction is delivered under an exclusive host admission turn: the
// guest's own platform calls (attachments, model, peers) wait until that turn
// ends. A harness that needs the platform to do the work therefore answers the
// delivery with WorkingResult, and posts the outcome later with
// CompleteInvocation. Delivery is final either way; only the result is deferred.

// WorkingResult is the exact acknowledgment of an invocation accepted for later
// completion. Any other JSON result is the final answer, as before.
func WorkingResult() []byte { return []byte(`{"status":"working"}`) }

// IsWorkingResult recognizes WorkingResult and nothing else: no extra field,
// no trailing value.
func IsWorkingResult(b []byte) bool {
	var v struct {
		Status string `json:"status"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Status != "working" {
		return false
	}
	var rest any
	return errors.Is(d.Decode(&rest), io.EOF)
}

// InvocationCompletion is the later outcome of a "working" invocation. A
// completed one carries the answer the requester will read; a failed one says
// only that the agent gave up.
type InvocationCompletion struct {
	OperationID string        `json:"operation_id"`
	Outcome     string        `json:"outcome"`
	Content     []TextContent `json:"content,omitempty"`
}

func (c InvocationCompletion) Validate() error {
	if c.OperationID == "" || len(c.OperationID) > 100 {
		return ErrProtocol
	}
	switch c.Outcome {
	case "completed":
		return OwnerMessage{Content: c.Content}.Validate()
	case "failed":
		if len(c.Content) != 0 {
			return ErrProtocol
		}
		return nil
	}
	return ErrProtocol
}

type CompletionReceipt struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Replayed    bool   `json:"replayed,omitempty"`
}

// InvocationAPI is optional on a PlatformAPI, like the other bridges.
type InvocationAPI interface {
	CompleteInvocation(context.Context, string, InvocationCompletion) (CompletionReceipt, error)
}

// CompleteInvocation posts the outcome once. Retrying with the same key and the
// same body replays the receipt; any other attempt is refused.
func (p *PlatformClient) CompleteInvocation(ctx context.Context, key string, in InvocationCompletion) (CompletionReceipt, error) {
	if err := in.Validate(); err != nil {
		return CompletionReceipt{}, err
	}
	r, err := p.call(ctx, "/v1/invocations/complete", &platformRequest{Key: key, Completion: &in})
	if err != nil {
		return CompletionReceipt{}, err
	}
	if r.Completion == nil || r.Completion.OperationID != in.OperationID {
		return CompletionReceipt{}, ErrProtocol
	}
	return *r.Completion, nil
}
