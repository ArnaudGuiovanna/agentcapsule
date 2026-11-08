//go:build linux

package worker

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type platformAPI struct {
	store       *controlplane.Store
	host        *runtime.FirecrackerHost
	caller      controlplane.VMCaller
	transit     func() *controlplane.Transit
	llm         func() *controlplane.LLMService
	authority   *restoreauthority.Catalog
	incarnation uint64
}

// withApplication checks the current boot's negotiated contract under host
// admission before entering the authority/SQL gates for the effect. Control's
// physical census may first read authority/SQL; no such lock remains held when
// the probe starts, and no effect transaction has begun.
// The callback only touches PostgreSQL and never reacquires a host/root lock.
// These remote effects are not entries in the guest's recoverable data history.
func (a platformAPI) withApplication(ctx context.Context, fn func(context.Context) error) error {
	return a.host.WithApplication(ctx, func(ctx context.Context) error {
		client, err := a.host.Control(ctx, a.caller.AgentID)
		if err != nil {
			return err
		}
		identity := client.Identity()
		if identity.AgentID != a.caller.AgentID || identity.Generation != a.caller.Generation ||
			identity.VMID != a.caller.VMID || identity.Incarnation != a.incarnation || identity.FenceOnly {
			return controlplane.ErrPlacement
		}
		return a.withIdentity(ctx, fn)
	})
}

func (a platformAPI) withIdentity(ctx context.Context, fn func(context.Context) error) error {
	if a.authority == nil {
		return fn(ctx) // explicit legacy/probe fixture
	}
	e, err := a.store.VolumeEnrollment(ctx, a.caller.AgentID, a.caller.HostID)
	if err != nil {
		return err
	}
	if e.Incarnation != a.incarnation {
		return restoreauthority.ErrStale
	}
	return a.authority.WithBinding(ctx, enrollmentBinding(e), func() error { return fn(ctx) })
}

func platformError(err error) error {
	if err == nil {
		return nil
	}
	code := "unavailable"
	switch {
	case errors.Is(err, controlplane.ErrInput):
		code = "invalid"
	case errors.Is(err, controlplane.ErrPlacement), errors.Is(err, restoreauthority.ErrStale), errors.Is(err, restoreauthority.ErrSealed),
		errors.Is(err, runtime.ErrNoVM), errors.Is(err, runtime.ErrGeneration), errors.Is(err, capsuleprotocol.ErrIdentity):
		code = "unauthorized"
	case errors.Is(err, controlplane.ErrNotFound):
		code = "not_found"
	case errors.Is(err, controlplane.ErrMandate):
		code = "mandate"
	case errors.Is(err, controlplane.ErrConflict):
		code = "conflict"
	case errors.Is(err, controlplane.ErrExpired):
		code = "expired"
	case errors.Is(err, controlplane.ErrTransition):
		code = "transition"
	case errors.Is(err, controlplane.ErrCommitUnknown):
		code = "commit_unknown"
	case errors.Is(err, controlplane.ErrForbidden):
		code = "unauthorized"
	case errors.Is(err, controlplane.ErrBudgetExceeded):
		code = "quota_exceeded"
	case errors.Is(err, llmgateway.ErrRateLimited):
		code = "rate_limited"
	case errors.Is(err, llmgateway.ErrRejected):
		code = "rejected"
	case errors.Is(err, llmgateway.ErrOutcomeUnknown):
		code = "outcome_unknown"
	case errors.Is(err, controlplane.ErrLLMAlreadyProcessed):
		code = "conflict"
	case errors.Is(err, llmgateway.ErrInvalid):
		code = "invalid"
	}
	return &capsuleprotocol.PlatformError{Code: code}
}
func receipt(r controlplane.Receipt) capsuleprotocol.PlatformReceipt {
	return capsuleprotocol.PlatformReceipt{RequestID: r.RequestID, State: string(r.State), Replayed: r.Replayed}
}
func (a platformAPI) Validate(ctx context.Context) error {
	return platformError(a.withApplication(ctx, func(ctx context.Context) error { return a.store.ValidateVMCaller(ctx, a.caller) }))
}
func (a platformAPI) Submit(ctx context.Context, key string, input capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	var r controlplane.Receipt
	err := a.withApplication(ctx, func(ctx context.Context) error {
		var err error
		if a.transit != nil {
			if t := a.transit(); t != nil {
				r, err = t.SubmitFromVM(ctx, a.caller, key, input)
				return err
			}
		}
		if input.Payload != nil {
			return controlplane.ErrTransitKey
		}
		if input.Subject != "" || input.CorrelationID != "" {
			return controlplane.ErrInput
		}
		r, err = a.store.SubmitFromVM(ctx, a.caller, key, controlplane.Submission{RecipientAgentID: input.RecipientAgentID, MandateID: input.MandateID, PayloadRef: input.PayloadRef, PayloadHash: input.PayloadHash, ExpiresAt: input.ExpiresAt})
		return err
	})
	return receipt(r), platformError(err)
}
func (a platformAPI) Reply(ctx context.Context, requestID, key string, input capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	var r controlplane.Receipt
	err := a.withApplication(ctx, func(ctx context.Context) error {
		var err error
		if a.transit != nil {
			if t := a.transit(); t != nil {
				r, err = t.ReplyFromVM(ctx, a.caller, requestID, key, input)
				return err
			}
		}
		if input.Payload != nil {
			return controlplane.ErrTransitKey
		}
		r, err = a.store.ReplyFromVM(ctx, a.caller, requestID, key, controlplane.Reply{Outcome: input.Outcome, PayloadRef: input.PayloadRef, PayloadHash: input.PayloadHash})
		return err
	})
	return receipt(r), platformError(err)
}
func (a platformAPI) Search(ctx context.Context, candidates []string) ([]string, error) {
	var r []string
	err := a.withApplication(ctx, func(ctx context.Context) error {
		var err error
		r, err = a.store.SearchDirectoryFromVM(ctx, a.caller, candidates)
		return err
	})
	return r, platformError(err)
}

func (a platformAPI) PostOwner(ctx context.Context, key string, input capsuleprotocol.OwnerPost) (capsuleprotocol.OwnerPostReceipt, error) {
	var result capsuleprotocol.OwnerPostReceipt
	err := a.withApplication(ctx, func(ctx context.Context) error {
		if a.transit == nil {
			return controlplane.ErrTransitKey
		}
		transit := a.transit()
		if transit == nil {
			return controlplane.ErrTransitKey
		}
		var err error
		result, err = transit.PostOwnerFromVM(ctx, a.caller, key, input)
		return err
	})
	return result, platformError(err)
}

// ReadAttachment serves one decrypted segment of a file sent with the invocation
// the capsule is running. Like the other effects it is decided under host
// admission and only touches PostgreSQL.
func (a platformAPI) ReadAttachment(ctx context.Context, id string, index int) (capsuleprotocol.AttachmentSegment, error) {
	var seg capsuleprotocol.AttachmentSegment
	err := a.withApplication(ctx, func(ctx context.Context) error {
		if a.transit == nil {
			return controlplane.ErrTransitKey
		}
		transit := a.transit()
		if transit == nil {
			return controlplane.ErrTransitKey
		}
		var err error
		seg, err = transit.ReadAttachmentFromVM(ctx, a.caller, id, index)
		return err
	})
	return seg, platformError(err)
}

// CompleteInvocation records the later outcome of an invocation the capsule
// acknowledged "working". It runs under the shared admission like any other
// guest effect, after the exclusive delivery turn has ended.
func (a platformAPI) CompleteInvocation(ctx context.Context, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	var out capsuleprotocol.CompletionReceipt
	err := a.withApplication(ctx, func(ctx context.Context) error {
		if a.transit == nil {
			return controlplane.ErrTransitKey
		}
		transit := a.transit()
		if transit == nil {
			return controlplane.ErrTransitKey
		}
		var err error
		out, err = transit.CompleteInvocationFromVM(ctx, a.caller, key, in)
		return err
	})
	return out, platformError(err)
}

// CompleteLLM serves a model call from the running capsule. Placement and
// reservation happen under host admission; the provider call itself does not, so
// a slow model never delays a wake, sleep or delete.
func (a platformAPI) CompleteLLM(ctx context.Context, key string, in capsuleprotocol.LLMRequest) (capsuleprotocol.LLMResult, error) {
	if a.llm == nil {
		return capsuleprotocol.LLMResult{}, platformError(controlplane.ErrUnavailable)
	}
	svc := a.llm()
	if svc == nil {
		return capsuleprotocol.LLMResult{}, platformError(controlplane.ErrUnavailable)
	}
	q := llmgateway.Request{MaxTokens: in.MaxTokens, Temperature: in.Temperature}
	for _, m := range in.Messages {
		q.Messages = append(q.Messages, llmgateway.Message{Role: m.Role, Content: m.Content})
	}
	res, err := svc.CallFromVM(ctx, a.caller, key, in.Alias, q, a.withApplication)
	if err != nil {
		return capsuleprotocol.LLMResult{}, platformError(err)
	}
	return capsuleprotocol.LLMResult{Text: res.Text, FinishReason: res.FinishReason,
		InputTokens: res.Usage.InputTokens, OutputTokens: res.Usage.OutputTokens, SoftExceeded: res.SoftBudgetExceeded}, nil
}

// Close releases this worker's platform listeners, leaving VMMs available for a
// replacement worker. Store ownership remains with the caller.
func (w *Placements) Close() { w.host.Close() }
