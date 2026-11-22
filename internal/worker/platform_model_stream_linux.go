//go:build linux

package worker

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
)

func (a platformAPI) modelStream(ctx context.Context, call string, send func(capsuleprotocol.LLMStreamFrame) error,
	invoke func(context.Context, *llmservice.Service) (llmservice.StreamEnd, error)) (err error) {
	ctx, endSpan := a.trace(ctx, call, "", "")
	defer func() { endSpan(err) }()
	if a.llm == nil {
		return platformError(controlplane.ErrUnavailable)
	}
	svc := a.llm()
	if svc == nil {
		return platformError(controlplane.ErrUnavailable)
	}
	if a.streamTelemetry != nil {
		stop := a.streamTelemetry().track("llm")
		defer stop()
	}
	end, err := invoke(ctx, svc)
	if err != nil {
		return platformError(err)
	}
	frame := capsuleprotocol.LLMStreamFrame{Type: "end", Outcome: end.Outcome}
	if end.Outcome == llmservice.StreamCompleted {
		frame.InputTokens, frame.OutputTokens, frame.SoftExceeded = &end.Usage.InputTokens, &end.Usage.OutputTokens, &end.SoftBudgetExceeded
		if call == "llm_complete" {
			frame.FinishReason = end.FinishReason
		}
	}
	return send(frame)
}

func (a platformAPI) ForwardLLMStream(ctx context.Context, key string, in capsuleprotocol.LLMForward, send func(capsuleprotocol.LLMStreamFrame) error) error {
	return a.modelStream(ctx, "llm_forward", send, func(ctx context.Context, svc *llmservice.Service) (llmservice.StreamEnd, error) {
		return svc.ForwardStreamFromVM(ctx, a.caller, key, in.Alias, in.Dialect, in.Body, a.withApplication, func(e llmgateway.Event) error {
			return send(capsuleprotocol.LLMStreamFrame{Type: "event", Event: &capsuleprotocol.LLMStreamEvent{Name: e.Name, Data: e.Data}})
		})
	})
}

func (a platformAPI) CompleteLLMStream(ctx context.Context, key string, in capsuleprotocol.LLMRequest, send func(capsuleprotocol.LLMStreamFrame) error) error {
	return a.modelStream(ctx, "llm_complete", send, func(ctx context.Context, svc *llmservice.Service) (llmservice.StreamEnd, error) {
		return svc.CompleteStreamFromVM(ctx, a.caller, key, in.Alias, gatewayRequest(in), a.withApplication, func(text string) error {
			return send(capsuleprotocol.LLMStreamFrame{Type: "text", Text: text})
		})
	})
}
