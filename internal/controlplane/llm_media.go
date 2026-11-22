package controlplane

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// Embeddings, transcription and OCR from a running capsule (ADR 023 §12).
// Each follows the rules of CallFromVM: placement check and reservation under
// the host's admission, the provider called outside it, then one outcome:
// settled at the provider's figures (or at the reservation when it reports
// none), unknown after a cut, or released. A request key already settled
// never calls the provider again.

// EmbedResult is a provider's embeddings for a capsule.
type EmbedResult struct {
	llmgateway.EmbedResponse
	SoftBudgetExceeded bool
}

// TranscribeResult is a provider's transcript for a capsule. Its
// DurationSeconds is the settled duration.
type TranscribeResult struct {
	llmgateway.TranscribeResponse
	SoftBudgetExceeded bool
}

// OCRResult is a provider's recognized pages for a capsule. Its
// PagesProcessed is the settled page count.
type OCRResult struct {
	llmgateway.OCRResponse
	SoftBudgetExceeded bool
}

// EmbedFromVM reserves the input's size / 3 tokens and settles the provider's
// prompt tokens.
func (s *LLMService) EmbedFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmgateway.EmbedRequest,
	admission func(context.Context, func(context.Context) error) error) (EmbedResult, error) {
	if !q.Valid() {
		return EmbedResult{}, llmgateway.ErrInvalid
	}
	reserved := llmAmounts{Operation: LLMEmbed, Input: q.ReservedTokens()}
	hold, err := s.admitOperationFromVM(ctx, caller, requestKey, alias, reserved, admission)
	if err != nil {
		return EmbedResult{}, err
	}
	var out llmgateway.EmbedResponse
	err = s.settleOperation(ctx, hold, reserved, func(route llmgateway.Route) (llmAmounts, error) {
		var err error
		out, err = s.gateway.Embed(ctx, route, q)
		used := llmAmounts{Operation: LLMEmbed, Input: out.Usage.InputTokens}
		if used.Input == 0 {
			used.Input = reserved.Input
			out.Usage.InputTokens = reserved.Input
		}
		return used, err
	})
	if err != nil {
		return EmbedResult{}, err
	}
	return EmbedResult{EmbedResponse: out, SoftBudgetExceeded: hold.res.SoftExceeded}, nil
}

// TranscribeFromVM reserves the declared duration and settles the provider's.
func (s *LLMService) TranscribeFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmgateway.TranscribeRequest,
	admission func(context.Context, func(context.Context) error) error) (TranscribeResult, error) {
	if !q.Valid() {
		return TranscribeResult{}, llmgateway.ErrInvalid
	}
	reserved := llmAmounts{Operation: LLMTranscribe, AudioSeconds: int64(q.DurationSeconds)}
	hold, err := s.admitOperationFromVM(ctx, caller, requestKey, alias, reserved, admission)
	if err != nil {
		return TranscribeResult{}, err
	}
	var out llmgateway.TranscribeResponse
	err = s.settleOperation(ctx, hold, reserved, func(route llmgateway.Route) (llmAmounts, error) {
		var err error
		out, err = s.gateway.Transcribe(ctx, route, q)
		if out.DurationSeconds == 0 {
			out.DurationSeconds = reserved.AudioSeconds
		}
		return llmAmounts{Operation: LLMTranscribe, AudioSeconds: out.DurationSeconds}, err
	})
	if err != nil {
		return TranscribeResult{}, err
	}
	return TranscribeResult{TranscribeResponse: out, SoftBudgetExceeded: hold.res.SoftExceeded}, nil
}

// OCRFromVM reserves the declared pages and settles the provider's.
func (s *LLMService) OCRFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmgateway.OCRRequest,
	admission func(context.Context, func(context.Context) error) error) (OCRResult, error) {
	if !q.Valid() {
		return OCRResult{}, llmgateway.ErrInvalid
	}
	reserved := llmAmounts{Operation: LLMOCR, Pages: int64(q.Pages)}
	hold, err := s.admitOperationFromVM(ctx, caller, requestKey, alias, reserved, admission)
	if err != nil {
		return OCRResult{}, err
	}
	var out llmgateway.OCRResponse
	err = s.settleOperation(ctx, hold, reserved, func(route llmgateway.Route) (llmAmounts, error) {
		var err error
		out, err = s.gateway.OCR(ctx, route, q)
		if out.PagesProcessed == 0 {
			out.PagesProcessed = reserved.Pages
		}
		return llmAmounts{Operation: LLMOCR, Pages: out.PagesProcessed}, err
	})
	if err != nil {
		return OCRResult{}, err
	}
	return OCRResult{OCRResponse: out, SoftBudgetExceeded: hold.res.SoftExceeded}, nil
}

// admitOperationFromVM is admitFromVM for an operation whose amounts do not
// depend on the alias: the placement check, the request key's guard, the
// agent's calls in flight and the reservation, as for a chat call (audit
// finding L-07).
func (s *LLMService) admitOperationFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmAmounts,
	admission func(context.Context, func(context.Context) error) error) (llmHold, error) {
	return s.admitFromVM(ctx, caller, requestKey, alias, func(LLMRoute) (llmAmounts, error) { return q, nil }, admission)
}

// settleOperation is settle for any operation: one provider call and its
// single outcome, recorded in the call's units.
func (s *LLMService) settleOperation(ctx context.Context, h llmHold, reserved llmAmounts, call func(llmgateway.Route) (llmAmounts, error)) error {
	defer h.release()
	route := h.route
	used, callErr := call(h.gatewayRoute())
	bk := context.WithoutCancel(ctx)
	event := LLMCallEvent{Provider: route.Kind, Operation: reserved.Operation, SoftBudgets: h.res.SoftBudgets}
	switch {
	case callErr == nil:
		cost, err := s.accounts.settleLLMCall(bk, h.tenantID, h.res.ID, used)
		if err != nil {
			return err
		}
		event.Outcome, event.InputTokens, event.OutputTokens = "settled", used.Input, used.Output
		event.AudioSeconds, event.Pages = used.AudioSeconds, used.Pages
		if cost != nil {
			event.CostMicro = *cost
		}
	case errors.Is(callErr, llmgateway.ErrOutcomeUnknown):
		_ = s.accounts.MarkLLMUnknown(bk, h.tenantID, h.res.ID)
		event.Outcome = "unknown"
	default:
		_ = s.accounts.ReleaseLLM(bk, h.tenantID, h.res.ID)
		event.Outcome = "released"
	}
	s.observe(event)
	return callErr
}
