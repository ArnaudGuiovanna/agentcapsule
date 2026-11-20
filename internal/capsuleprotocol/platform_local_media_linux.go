//go:build linux

package capsuleprotocol

import "context"

// The guest's relay carries embeddings, transcription and OCR to the host as
// it carries the other model calls: typed, under the boot's identity.
func (r remotePlatform) EmbedLLM(ctx context.Context, key string, in LLMEmbed) (LLMEmbedResult, error) {
	return r.client.EmbedLLM(ctx, key, in)
}
func (r remotePlatform) TranscribeLLM(ctx context.Context, key string, in LLMTranscribe) (LLMTranscribeResult, error) {
	return r.client.TranscribeLLM(ctx, key, in)
}
func (r remotePlatform) OCRLLM(ctx context.Context, key string, in LLMOCR) (LLMOCRResult, error) {
	return r.client.OCRLLM(ctx, key, in)
}

var _ LLMMediaAPI = remotePlatform{}
