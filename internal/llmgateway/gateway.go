// Package llmgateway calls tenant-configured LLM providers on behalf of agents.
// It never logs prompts, completions or credentials, never promises an external
// call happened exactly once, and reports provider failures as typed errors so a
// caller can decide without restarting a VM.
package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
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
	Kind, BaseURL, UpstreamModel, Secret string
	// Key identifies the breaker bucket, normally "tenant/provider".
	Key string
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
	HTTP         *http.Client
	Timeout      time.Duration // per attempt
	MaxAttempts  int           // total, >= 1
	Backoff      time.Duration // base, doubled per retry
	FailureLimit int           // consecutive failures that open a breaker
	OpenFor      time.Duration
	MaxResponse  int64
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

type Gateway struct {
	cfg      Config
	mu       sync.Mutex
	breakers map[string]*breaker
}

type breaker struct {
	failures  int
	openUntil time.Time
	probing   bool
}

func New(c Config) *Gateway {
	if c.HTTP == nil {
		c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
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
	return &Gateway{cfg: c, breakers: map[string]*breaker{}}
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
func (g *Gateway) Complete(ctx context.Context, route Route, req Request) (Response, error) {
	if !req.valid() || route.Secret == "" || route.UpstreamModel == "" {
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
	if err = g.admit(route.Key); err != nil {
		return Response{}, err
	}
	var last error
	for attempt := 0; attempt < g.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err = g.cfg.Sleep(ctx, g.cfg.Backoff<<(attempt-1)); err != nil {
				g.record(route.Key, true) // release a half-open probe; not a provider fault
				return Response{}, err
			}
		}
		out, retry, err := g.once(ctx, target, body, headers, parse)
		switch {
		case err == nil:
			g.record(route.Key, true)
			return out, nil
		case errors.Is(err, ErrRejected):
			g.record(route.Key, true) // the provider is healthy; the request was wrong
			return Response{}, err
		}
		last = err
		if !retry {
			break
		}
	}
	g.record(route.Key, false)
	return Response{}, last
}

func (g *Gateway) once(ctx context.Context, target string, body []byte, headers map[string]string, parse func([]byte) (Response, error)) (Response, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Response{}, false, ErrInvalid
	}
	hr.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	resp, err := g.cfg.HTTP.Do(hr)
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			// Sent, answer never seen: do not retry, do not claim zero cost.
			return Response{}, false, ErrOutcomeUnknown
		}
		return Response{}, true, ErrUnavailable // could not connect; nothing was accepted
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponse+1))
	if err != nil || int64(len(raw)) > g.cfg.MaxResponse {
		return Response{}, false, ErrOutcomeUnknown
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return Response{}, true, ErrRateLimited
	case resp.StatusCode >= 500:
		return Response{}, true, ErrUnavailable
	case resp.StatusCode >= 400:
		return Response{}, false, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
	out, err := parse(raw)
	if err != nil {
		return Response{}, false, ErrOutcomeUnknown
	}
	return out, false, nil
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
	return join(r.BaseURL, "/chat/completions"), b, map[string]string{"Authorization": "Bearer " + r.Secret}, err
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
	return join(r.BaseURL, "/v1/messages"), b, map[string]string{"x-api-key": r.Secret, "anthropic-version": "2023-06-01"}, err
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
