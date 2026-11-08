package capsuleprotocol

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

// LLM bridge limits. The tenant, agent, provider, credentials and budget scope
// never appear in these payloads: they come from the authenticated channel and
// the control plane. The guest names only a tenant-defined model alias.
const (
	MaxLLMMessages   = 64
	MaxLLMBytes      = 256 * 1024
	MaxLLMOutputCap  = 32768
	LLMCallTimeout   = 120 * time.Second
	llmClientTimeout = LLMCallTimeout + 10*time.Second
)

type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMRequest struct {
	Alias       string       `json:"alias"`
	Messages    []LLMMessage `json:"messages"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Temperature *float64     `json:"temperature,omitempty"`
}

func (r LLMRequest) Validate() error {
	if r.Alias == "" || len(r.Alias) > 100 || strings.ContainsAny(r.Alias, " \t\r\n\x00") || !utf8.ValidString(r.Alias) {
		return ErrProtocol
	}
	if len(r.Messages) < 1 || len(r.Messages) > MaxLLMMessages || r.MaxTokens < 0 || r.MaxTokens > MaxLLMOutputCap {
		return ErrProtocol
	}
	if r.Temperature != nil && (*r.Temperature < 0 || *r.Temperature > 2) {
		return ErrProtocol
	}
	n := 0
	for _, m := range r.Messages {
		if (m.Role != "system" && m.Role != "user" && m.Role != "assistant") || !utf8.ValidString(m.Content) ||
			strings.TrimSpace(m.Content) == "" || strings.ContainsRune(m.Content, 0) {
			return ErrProtocol
		}
		n += len(m.Content)
	}
	if n > MaxLLMBytes {
		return ErrProtocol
	}
	return nil
}

// LLMResult carries the completion and the provider-reported usage. A soft budget
// overrun is a warning, never a refusal.
type LLMResult struct {
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason,omitempty"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	SoftExceeded bool   `json:"soft_budget_exceeded,omitempty"`
}

// LLMAPI is optional on a PlatformAPI, like OwnerMessageAPI: an adapter that does
// not offer the bridge answers "unavailable".
type LLMAPI interface {
	CompleteLLM(context.Context, string, LLMRequest) (LLMResult, error)
}

func (p *PlatformClient) CompleteLLM(ctx context.Context, key string, in LLMRequest) (LLMResult, error) {
	r, err := p.callWithTimeout(ctx, "/v1/llm/complete", &platformRequest{Key: key, LLM: &in}, llmClientTimeout)
	if err != nil {
		return LLMResult{}, err
	}
	if r.LLMResult == nil {
		return LLMResult{}, ErrProtocol
	}
	return *r.LLMResult, nil
}
