// Package llmgateway calls tenant-configured LLM providers on behalf of agents.
// It never logs prompts, completions or credentials, never promises an external
// call happened exactly once, and reports provider failures as typed errors so a
// caller can decide without restarting a VM. It connects only to public
// addresses, checked after DNS resolution, unless the operator allows an
// internal one, and never follows a redirect.
package llmgateway

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

type Message struct {
	Role    string `json:"role"` // system, user or assistant
	Content string `json:"content"`
}

type Request struct {
	Messages    []Message
	MaxTokens   int
	Temperature *float64
}

type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type Response struct {
	Text         string
	FinishReason string
	Usage        Usage
}

// Route is one resolved upstream. Secret stays in memory.
type Route struct {
	AuthMode                             string
	Kind, BaseURL, UpstreamModel, Secret string
	// Key identifies the breaker bucket, normally "tenant/provider".
	Key string
}

// The empty mode preserves callers created before explicit authentication modes.
func (r Route) validAuth() bool {
	return (r.AuthMode == "" || r.AuthMode == "secret") && r.Secret != "" || r.AuthMode == "none" && r.Secret == ""
}
func (r Route) headers() map[string]string {
	h := map[string]string{}
	if r.Kind == "anthropic" {
		h["anthropic-version"] = "2023-06-01"
	}
	if r.AuthMode != "none" {
		if r.Kind == "anthropic" {
			h["x-api-key"] = r.Secret
		} else {
			h["Authorization"] = "Bearer " + r.Secret
		}
	}
	return h
}

var (
	ErrInvalid = errors.New("llm request is invalid")
	// ErrUnavailable: the provider could not be reached or answered 5xx after the
	// bounded retries, or its breaker is open.
	ErrUnavailable = errors.New("llm provider unavailable")
	// ErrRateLimited carries the provider's refusal; the caller may back off.
	ErrRateLimited = errors.New("llm provider rate limited")
	// ErrRejected is a definite upstream refusal (4xx other than 429): the
	// credential, model or request is wrong. It is not retried.
	ErrRejected = errors.New("llm provider rejected the request")
	// ErrOutcomeUnknown means the request may have been processed (timeout after
	// send). Accounting must treat the cost as uncertain, not as zero.
	ErrOutcomeUnknown = errors.New("llm call outcome is unknown")
)

type Config struct {
	Timeout      time.Duration // per attempt
	MaxAttempts  int           // total, >= 1
	Backoff      time.Duration // base, doubled per retry
	FailureLimit int           // consecutive failures that open a breaker
	OpenFor      time.Duration
	MaxResponse  int64
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
	// RequireHTTPS refuses a provider whose URL is not https, before any
	// request (production, docs/adr/010-transport-security-and-preflight.md).
	RequireHTTPS bool
	// AllowInternal lists the internal provider addresses the operator
	// allows. Empty, the default: the gateway connects to public addresses
	// only, checked after DNS resolution (ADR 010).
	AllowInternal Allowlist
	// A stream's bounds (ADR 022), in place of Timeout: up to the provider's
	// first byte, per attempt (60 s); between two of its events, a comment
	// line included (60 s); in total, retries included (300 s, the platform
	// channel's capsuleprotocol.LLMCallTimeout).
	StreamFirstByte, StreamIdle, StreamTotal time.Duration
}

type Gateway struct {
	cfg      Config
	http     *http.Client
	mu       sync.Mutex
	breakers map[string]*breaker
}

type breaker struct {
	failures  int
	openUntil time.Time
	probing   bool
}

func New(c Config) *Gateway { return newGateway(c, TestOptions{}) }

func newGateway(c Config, t TestOptions) *Gateway {
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.MaxAttempts < 1 {
		c.MaxAttempts = 2
	}
	if c.Backoff <= 0 {
		c.Backoff = 250 * time.Millisecond
	}
	if c.FailureLimit < 1 {
		c.FailureLimit = 5
	}
	if c.OpenFor <= 0 {
		c.OpenFor = 30 * time.Second
	}
	if c.MaxResponse <= 0 {
		c.MaxResponse = 4 << 20
	}
	c.StreamFirstByte = cmp.Or(max(c.StreamFirstByte, 0), 60*time.Second)
	c.StreamIdle = cmp.Or(max(c.StreamIdle, 0), 60*time.Second)
	c.StreamTotal = cmp.Or(max(c.StreamTotal, 0), 300*time.Second)
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &Gateway{cfg: c, http: newClient(c.AllowInternal, t), breakers: map[string]*breaker{}}
}

func (g *Gateway) admit(key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.breakers[key]
	if b == nil || b.failures < g.cfg.FailureLimit {
		return nil
	}
	if g.cfg.Now().Before(b.openUntil) || b.probing {
		return ErrUnavailable
	}
	b.probing = true // half-open: exactly one probe
	return nil
}

func (g *Gateway) record(key string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.breakers[key]
	if b == nil {
		b = &breaker{}
		g.breakers[key] = b
	}
	b.probing = false
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= g.cfg.FailureLimit {
		b.openUntil = g.cfg.Now().Add(g.cfg.OpenFor)
	}
}

func (r Request) valid() bool {
	if len(r.Messages) == 0 || len(r.Messages) > 1000 || r.MaxTokens < 0 || r.MaxTokens > 1_000_000 {
		return false
	}
	if r.Temperature != nil && (*r.Temperature < 0 || *r.Temperature > 2) {
		return false
	}
	for _, m := range r.Messages {
		if (m.Role != "system" && m.Role != "user" && m.Role != "assistant") || m.Content == "" {
			return false
		}
	}
	return true
}

// Complete performs one logical call: at most MaxAttempts upstream requests,
// retrying only before the provider has accepted work (connection failure, 429,
// 5xx). A timeout after the request was sent is reported as ErrOutcomeUnknown
// and is not retried, since a retry could be billed twice.
func (g *Gateway) Complete(ctx context.Context, route Route, req Request) (out Response, err error) {
	ctx, span := startCall(ctx, "complete", route)
	defer func() { endCall(span, out.Usage, err) }()
	if !req.valid() || !route.validAuth() || route.UpstreamModel == "" {
		return Response{}, ErrInvalid
	}
	var build func(Route, Request) (string, []byte, map[string]string, error)
	var parse func([]byte) (Response, error)
	switch route.Kind {
	case "openai_compatible":
		build, parse = buildOpenAI, parseOpenAI
	case "anthropic":
		build, parse = buildAnthropic, parseAnthropic
	default:
		return Response{}, ErrInvalid
	}
	target, body, headers, err := build(route, req)
	if err != nil {
		return Response{}, err
	}
	var parsed Response
	err = g.exchange(ctx, route.Key, target, body, headers, func(raw []byte) (err error) {
		parsed, err = parse(raw)
		return err
	})
	if err != nil {
		return Response{}, err
	}
	return parsed, nil
}

// exchange is one logical upstream call with the bounded retries and the
// breaker of Complete. parse runs on a 2xx body; its failure means the provider
// did work the gateway cannot account for, hence ErrOutcomeUnknown.
func (g *Gateway) exchange(ctx context.Context, breakerKey, target string, body []byte, headers map[string]string, parse func([]byte) error) error {
	if g.cfg.RequireHTTPS && !strings.HasPrefix(target, "https://") {
		return ErrRejected // the configuration is wrong; nothing is sent
	}
	if err := g.admit(breakerKey); err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < g.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err := g.cfg.Sleep(ctx, g.cfg.Backoff<<(attempt-1)); err != nil {
				g.record(breakerKey, true) // release a half-open probe; not a provider fault
				return err
			}
		}
		telemetry.SpanFrom(ctx).Int("agentcapsule.llm.attempts", int64(attempt+1))
		retry, err := g.once(ctx, target, body, headers, parse)
		switch {
		case err == nil:
			g.record(breakerKey, true)
			return nil
		case errors.Is(err, ErrRejected):
			g.record(breakerKey, true) // the provider is healthy; the request was wrong
			return err
		}
		last = err
		if !retry {
			break
		}
	}
	g.record(breakerKey, false)
	return last
}

func (g *Gateway) once(ctx context.Context, target string, body []byte, headers map[string]string, parse func([]byte) error) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, ErrInvalid
	}
	hr.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	resp, err := g.http.Do(hr)
	if err != nil {
		if errors.Is(err, ErrAddressRefused) {
			return false, ErrAddressRefused // nothing was sent
		}
		if ctx.Err() != nil || isTimeout(err) {
			// Sent, answer never seen: do not retry, do not claim zero cost.
			return false, ErrOutcomeUnknown
		}
		return true, ErrUnavailable // could not connect; nothing was accepted
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponse+1))
	if err != nil || int64(len(raw)) > g.cfg.MaxResponse {
		return false, ErrOutcomeUnknown
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true, ErrRateLimited
	case resp.StatusCode >= 500:
		return true, ErrUnavailable
	case resp.StatusCode >= 300:
		// A redirect is never followed: the provider's key would go to
		// another address. It is not an answer either, so the URL is wrong.
		return false, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
	if err = parse(raw); err != nil {
		return false, ErrOutcomeUnknown
	}
	return false, nil
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func join(base, path string) string { return strings.TrimRight(base, "/") + path }

// ---- OpenAI-compatible ----

func buildOpenAI(r Route, q Request) (string, []byte, map[string]string, error) {
	payload := map[string]any{"model": r.UpstreamModel, "messages": q.Messages}
	if q.MaxTokens > 0 {
		payload["max_tokens"] = q.MaxTokens
	}
	if q.Temperature != nil {
		payload["temperature"] = *q.Temperature
	}
	b, err := json.Marshal(payload)
	return join(r.BaseURL, "/chat/completions"), b, r.headers(), err
}

func parseOpenAI(raw []byte) (Response, error) {
	var v struct {
		Choices []struct {
			Message      struct{ Content string } `json:"message"`
			FinishReason string                   `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int64 `json:"prompt_tokens"`
			Completion int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Choices) == 0 {
		return Response{}, ErrInvalid
	}
	return Response{Text: v.Choices[0].Message.Content, FinishReason: v.Choices[0].FinishReason, Usage: Usage{v.Usage.Prompt, v.Usage.Completion}}, nil
}

// ---- Anthropic native ----

func buildAnthropic(r Route, q Request) (string, []byte, map[string]string, error) {
	var system []string
	msgs := []Message{}
	for _, m := range q.Messages {
		if m.Role == "system" {
			system = append(system, m.Content)
			continue
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return "", nil, nil, ErrInvalid
	}
	max := q.MaxTokens
	if max == 0 {
		max = 1024 // the native API requires an explicit bound
	}
	payload := map[string]any{"model": r.UpstreamModel, "messages": msgs, "max_tokens": max}
	if len(system) > 0 {
		payload["system"] = strings.Join(system, "\n\n")
	}
	if q.Temperature != nil {
		payload["temperature"] = *q.Temperature
	}
	b, err := json.Marshal(payload)
	return join(r.BaseURL, "/v1/messages"), b, r.headers(), err
}

func parseAnthropic(raw []byte) (Response, error) {
	var v struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			In  int64 `json:"input_tokens"`
			Out int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Content) == 0 {
		return Response{}, ErrInvalid
	}
	var text strings.Builder
	for _, c := range v.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	return Response{Text: text.String(), FinishReason: v.StopReason, Usage: Usage{v.Usage.In, v.Usage.Out}}, nil
}
