package capsuleprotocol

import (
	"context"
	"unicode/utf8"
)

// Embeddings, transcription and OCR on the platform channel (ADR 023 §12).
// As for /v1/llm/complete, the guest names only its organization's alias; the
// host resolves the provider and meters the call. Each request and its answer
// fit the channel's message: the media is at most 700 KiB once decoded, and
// the caller splits longer audio and documents.
const (
	MaxLLMMediaBytes      = 700 << 10
	MaxLLMEmbedInputs     = 64
	MaxLLMEmbedInputBytes = 32 << 10
	MaxLLMAudioSeconds    = 600
	MaxLLMOCRPages        = 8
	MaxLLMPromptRunes     = 1024
)

var (
	llmAudioFormats  = map[string]bool{"mp3": true, "wav": true, "flac": true, "ogg": true, "m4a": true, "webm": true}
	llmDocumentTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true, "application/pdf": true}
)

// LLMEmbed asks for one vector per input string.
type LLMEmbed struct {
	Alias string   `json:"alias"`
	Input []string `json:"input"`
}

func (e LLMEmbed) Validate() error {
	if !validAlias(e.Alias) || len(e.Input) < 1 || len(e.Input) > MaxLLMEmbedInputs {
		return ErrProtocol
	}
	total := 0
	for _, s := range e.Input {
		if s == "" || len(s) > MaxLLMEmbedInputBytes || !utf8.ValidString(s) {
			return ErrProtocol
		}
		total += len(s)
	}
	if total > MaxLLMForwardBytes {
		return ErrProtocol
	}
	return nil
}

// LLMEmbedResult holds one little-endian float32 vector per input, in the
// order of the input (base64 in JSON), and the settled input tokens.
type LLMEmbedResult struct {
	Embeddings   [][]byte `json:"embeddings"`
	Dimensions   int      `json:"dimensions"`
	InputTokens  int64    `json:"input_tokens"`
	SoftExceeded bool     `json:"soft_budget_exceeded,omitempty"`
}

func (r LLMEmbedResult) valid(inputs int) bool {
	if len(r.Embeddings) != inputs || r.Dimensions < 1 || r.InputTokens < 0 {
		return false
	}
	for _, v := range r.Embeddings {
		if len(v) != 4*r.Dimensions {
			return false
		}
	}
	return true
}

// LLMTranscribe is one audio segment (base64 in JSON) and its declared
// duration in seconds.
type LLMTranscribe struct {
	Alias           string `json:"alias"`
	Audio           []byte `json:"audio"`
	Format          string `json:"format"`
	DurationSeconds int    `json:"duration_seconds"`
	Language        string `json:"language,omitempty"`
	Prompt          string `json:"prompt,omitempty"`
}

func (t LLMTranscribe) Validate() error {
	language := t.Language == "" || len(t.Language) == 2 && t.Language[0] >= 'a' && t.Language[0] <= 'z' && t.Language[1] >= 'a' && t.Language[1] <= 'z'
	if !validAlias(t.Alias) || !llmAudioFormats[t.Format] || len(t.Audio) < 1 || len(t.Audio) > MaxLLMMediaBytes ||
		t.DurationSeconds < 1 || t.DurationSeconds > MaxLLMAudioSeconds || !language || !utf8.ValidString(t.Prompt) || utf8.RuneCountInString(t.Prompt) > MaxLLMPromptRunes {
		return ErrProtocol
	}
	return nil
}

// LLMSegment is a part of a transcript with its time stamps, in seconds.
type LLMSegment struct {
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Text  string  `json:"text"`
}

// LLMTranscribeResult is the transcript and the settled duration, in seconds.
type LLMTranscribeResult struct {
	Text            string       `json:"text"`
	Segments        []LLMSegment `json:"segments"`
	DurationSeconds int64        `json:"duration_seconds"`
	SoftExceeded    bool         `json:"soft_budget_exceeded,omitempty"`
}

// LLMOCR is one image or PDF (base64 in JSON) and its declared page count.
type LLMOCR struct {
	Alias     string `json:"alias"`
	Document  []byte `json:"document"`
	MediaType string `json:"media_type"`
	Pages     int    `json:"pages"`
}

func (o LLMOCR) Validate() error {
	if !validAlias(o.Alias) || !llmDocumentTypes[o.MediaType] || len(o.Document) < 1 || len(o.Document) > MaxLLMMediaBytes ||
		o.Pages < 1 || o.Pages > MaxLLMOCRPages {
		return ErrProtocol
	}
	return nil
}

// LLMOCRPage is one recognized page, as Markdown.
type LLMOCRPage struct {
	Index    int    `json:"index"`
	Markdown string `json:"markdown"`
}

// LLMOCRResult is the recognized pages and the settled page count.
type LLMOCRResult struct {
	Pages          []LLMOCRPage `json:"pages"`
	PagesProcessed int64        `json:"pages_processed"`
	SoftExceeded   bool         `json:"soft_budget_exceeded,omitempty"`
}

// LLMMediaAPI is optional on a PlatformAPI, like LLMAPI: an adapter that does
// not offer these routes answers "unavailable".
type LLMMediaAPI interface {
	EmbedLLM(context.Context, string, LLMEmbed) (LLMEmbedResult, error)
	TranscribeLLM(context.Context, string, LLMTranscribe) (LLMTranscribeResult, error)
	OCRLLM(context.Context, string, LLMOCR) (LLMOCRResult, error)
}

func llmMediaRoute(path string) bool {
	return path == "/v1/llm/embed" || path == "/v1/llm/transcribe" || path == "/v1/llm/ocr"
}

// serveLLMMedia serves the three routes for the platform handler. A refusal
// is a PlatformError: invalid (400) for a request outside the route's bounds,
// unavailable (503) when the adapter does not offer the route.
func (p *platformHandler) serveLLMMedia(ctx context.Context, path string, in *platformRequest, out *platformResponse) error {
	invalid := &PlatformError{Code: "invalid"}
	if in.Key == "" || len(in.Key) > 200 || in.LLM != nil || in.Forward != nil || in.Attachment != nil || in.Completion != nil || in.OwnerMessage != nil ||
		in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Query != nil || in.AgentID != "" {
		return invalid
	}
	api, ok := p.api.(LLMMediaAPI)
	switch path {
	case "/v1/llm/embed":
		if in.Embed == nil || in.Embed.Validate() != nil {
			return invalid
		}
		if !ok {
			return &PlatformError{Code: "unavailable"}
		}
		r, err := api.EmbedLLM(ctx, in.Key, *in.Embed)
		if err == nil {
			out.EmbedResult = &r
		}
		return err
	case "/v1/llm/transcribe":
		if in.Transcribe == nil || in.Transcribe.Validate() != nil {
			return invalid
		}
		if !ok {
			return &PlatformError{Code: "unavailable"}
		}
		r, err := api.TranscribeLLM(ctx, in.Key, *in.Transcribe)
		if err == nil {
			out.TranscribeResult = &r
		}
		return err
	default:
		if in.OCR == nil || in.OCR.Validate() != nil {
			return invalid
		}
		if !ok {
			return &PlatformError{Code: "unavailable"}
		}
		r, err := api.OCRLLM(ctx, in.Key, *in.OCR)
		if err == nil {
			out.OCRResult = &r
		}
		return err
	}
}

// EmbedLLM asks the organization's embedding model for one vector per input.
func (p *PlatformClient) EmbedLLM(ctx context.Context, key string, in LLMEmbed) (LLMEmbedResult, error) {
	if err := in.Validate(); err != nil {
		return LLMEmbedResult{}, err
	}
	r, err := p.callWithTimeout(ctx, "/v1/llm/embed", &platformRequest{Key: key, Embed: &in}, llmClientTimeout)
	if err != nil {
		return LLMEmbedResult{}, err
	}
	if r.EmbedResult == nil || !r.EmbedResult.valid(len(in.Input)) {
		return LLMEmbedResult{}, ErrProtocol
	}
	return *r.EmbedResult, nil
}

// TranscribeLLM transcribes one audio segment with the organization's model.
func (p *PlatformClient) TranscribeLLM(ctx context.Context, key string, in LLMTranscribe) (LLMTranscribeResult, error) {
	if err := in.Validate(); err != nil {
		return LLMTranscribeResult{}, err
	}
	r, err := p.callWithTimeout(ctx, "/v1/llm/transcribe", &platformRequest{Key: key, Transcribe: &in}, llmClientTimeout)
	if err != nil {
		return LLMTranscribeResult{}, err
	}
	if r.TranscribeResult == nil || r.TranscribeResult.DurationSeconds < 0 {
		return LLMTranscribeResult{}, ErrProtocol
	}
	return *r.TranscribeResult, nil
}

// OCRLLM recognizes the pages of one image or PDF with the organization's
// model.
func (p *PlatformClient) OCRLLM(ctx context.Context, key string, in LLMOCR) (LLMOCRResult, error) {
	if err := in.Validate(); err != nil {
		return LLMOCRResult{}, err
	}
	r, err := p.callWithTimeout(ctx, "/v1/llm/ocr", &platformRequest{Key: key, OCR: &in}, llmClientTimeout)
	if err != nil {
		return LLMOCRResult{}, err
	}
	if r.OCRResult == nil || r.OCRResult.PagesProcessed < 0 {
		return LLMOCRResult{}, ErrProtocol
	}
	return *r.OCRResult, nil
}
