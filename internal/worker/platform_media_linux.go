//go:build linux

package worker

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
)

// Embeddings, transcription and OCR from the running capsule (ADR 023 §12),
// with the admission rules of CompleteLLM: placement and reservation under
// host admission, the provider call outside it.

func (a platformAPI) mediaService() *llmservice.Service {
	if a.llm == nil {
		return nil
	}
	return a.llm()
}

func (a platformAPI) EmbedLLM(ctx context.Context, key string, in capsuleprotocol.LLMEmbed) (_ capsuleprotocol.LLMEmbedResult, err error) {
	ctx, end := a.trace(ctx, "llm_embed", "", "")
	defer func() { end(err) }()
	svc := a.mediaService()
	if svc == nil {
		return capsuleprotocol.LLMEmbedResult{}, platformError(controlplane.ErrUnavailable)
	}
	res, err := svc.EmbedFromVM(ctx, a.caller, key, in.Alias, llmgateway.EmbedRequest{Input: in.Input}, a.withApplication)
	if err != nil {
		return capsuleprotocol.LLMEmbedResult{}, platformError(err)
	}
	return capsuleprotocol.LLMEmbedResult{Embeddings: res.Embeddings, Dimensions: res.Dimensions, InputTokens: res.Usage.InputTokens,
		SoftExceeded: res.SoftBudgetExceeded}, nil
}

func (a platformAPI) TranscribeLLM(ctx context.Context, key string, in capsuleprotocol.LLMTranscribe) (_ capsuleprotocol.LLMTranscribeResult, err error) {
	ctx, end := a.trace(ctx, "llm_transcribe", "", "")
	defer func() { end(err) }()
	svc := a.mediaService()
	if svc == nil {
		return capsuleprotocol.LLMTranscribeResult{}, platformError(controlplane.ErrUnavailable)
	}
	q := llmgateway.TranscribeRequest{Audio: in.Audio, Format: in.Format, DurationSeconds: in.DurationSeconds, Language: in.Language, Prompt: in.Prompt}
	res, err := svc.TranscribeFromVM(ctx, a.caller, key, in.Alias, q, a.withApplication)
	if err != nil {
		return capsuleprotocol.LLMTranscribeResult{}, platformError(err)
	}
	out := capsuleprotocol.LLMTranscribeResult{Text: res.Text, Segments: []capsuleprotocol.LLMSegment{}, DurationSeconds: res.DurationSeconds,
		SoftExceeded: res.SoftBudgetExceeded}
	for _, s := range res.Segments {
		out.Segments = append(out.Segments, capsuleprotocol.LLMSegment{Start: s.Start, End: s.End, Text: s.Text})
	}
	return out, nil
}

func (a platformAPI) OCRLLM(ctx context.Context, key string, in capsuleprotocol.LLMOCR) (_ capsuleprotocol.LLMOCRResult, err error) {
	ctx, end := a.trace(ctx, "llm_ocr", "", "")
	defer func() { end(err) }()
	svc := a.mediaService()
	if svc == nil {
		return capsuleprotocol.LLMOCRResult{}, platformError(controlplane.ErrUnavailable)
	}
	res, err := svc.OCRFromVM(ctx, a.caller, key, in.Alias, llmgateway.OCRRequest{Document: in.Document, MediaType: in.MediaType, Pages: in.Pages}, a.withApplication)
	if err != nil {
		return capsuleprotocol.LLMOCRResult{}, platformError(err)
	}
	out := capsuleprotocol.LLMOCRResult{Pages: []capsuleprotocol.LLMOCRPage{}, PagesProcessed: res.PagesProcessed, SoftExceeded: res.SoftBudgetExceeded}
	for _, p := range res.Pages {
		out.Pages = append(out.Pages, capsuleprotocol.LLMOCRPage{Index: p.Index, Markdown: p.Markdown})
	}
	return out, nil
}

var _ capsuleprotocol.LLMMediaAPI = platformAPI{}
