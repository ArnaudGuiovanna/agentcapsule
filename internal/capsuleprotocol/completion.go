package capsuleprotocol

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
)

type InvocationCompletion = wire.InvocationCompletion
type CompletionReceipt = wire.CompletionReceipt

func WorkingResult() []byte { return wire.WorkingResult() }

func IsWorkingResult(b []byte) bool { return wire.IsWorkingResult(b) }

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
