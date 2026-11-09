package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
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
	LLMCallTimeout   = 300 * time.Second
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

func validAlias(alias string) bool {
	return alias != "" && len(alias) <= 100 && !strings.ContainsAny(alias, " \t\r\n\x00") && utf8.ValidString(alias)
}

func (r LLMRequest) Validate() error {
	if !validAlias(r.Alias) {
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

// LLMForward is an agent's native model request, as its own SDK wrote it for the
// model endpoint inside the VM: dialect "openai" (Chat Completions) or
// "anthropic" (Messages). Alias is the model name it used. The host replaces the
// model and adds the credential; it checks the body (no stream, one choice,
// bounded output) before anything reaches the provider.
type LLMForward struct {
	Alias   string          `json:"alias"`
	Dialect string          `json:"dialect"`
	Body    json.RawMessage `json:"body"`
}

// MaxLLMForwardBytes bounds a forwarded request and its answer so that each fits
// the platform channel's envelope.
const MaxLLMForwardBytes = 960 << 10

func (f LLMForward) Validate() error {
	body := bytes.TrimSpace(f.Body)
	if !validAlias(f.Alias) || (f.Dialect != "openai" && f.Dialect != "anthropic") ||
		len(body) < 2 || len(body) > MaxLLMForwardBytes || body[0] != '{' || !json.Valid(body) {
		return ErrProtocol
	}
	return nil
}

// LLMForwardResult is the provider's JSON answer, unchanged, with the usage the
// platform settled.
type LLMForwardResult struct {
	Body         json.RawMessage `json:"body"`
	InputTokens  int64           `json:"input_tokens"`
	OutputTokens int64           `json:"output_tokens"`
	SoftExceeded bool            `json:"soft_budget_exceeded,omitempty"`
}

// LLMForwardAPI is optional on a PlatformAPI, like LLMAPI.
type LLMForwardAPI interface {
	ForwardLLM(context.Context, string, LLMForward) (LLMForwardResult, error)
}

func (p *PlatformClient) ForwardLLM(ctx context.Context, key string, in LLMForward) (LLMForwardResult, error) {
	if err := in.Validate(); err != nil {
		return LLMForwardResult{}, err
	}
	r, err := p.callWithTimeout(ctx, "/v1/llm/forward", &platformRequest{Key: key, Forward: &in}, llmClientTimeout)
	if err != nil {
		return LLMForwardResult{}, err
	}
	if r.Forwarded == nil || !json.Valid(r.Forwarded.Body) {
		return LLMForwardResult{}, ErrProtocol
	}
	return *r.Forwarded, nil
}
