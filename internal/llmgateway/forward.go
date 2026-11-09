package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// Dialects an agent may speak to the model endpoint inside its VM. A request is
// forwarded only to a provider of the same kind: the body is the agent's own
// native request (tools, images, response formats pass through untouched); the
// gateway replaces the model and the credential, never the content.
const (
	DialectOpenAI    = "openai"    // Chat Completions, to an openai_compatible provider
	DialectAnthropic = "anthropic" // Messages, to an anthropic provider
)

// MaxForwardBytes bounds a forwarded request and its answer: both cross the
// VM's platform channel inside a 1 MiB envelope.
const MaxForwardBytes = 960 << 10

// maxForwardOutput bounds an explicit output cap, as Request.valid does.
const maxForwardOutput = 1_000_000

// ErrDialect: the alias's provider does not speak the agent's API.
var ErrDialect = errors.New("llm provider does not speak this dialect")

// ForwardResponse is the provider's 2xx JSON answer, unchanged, and the usage it
// reported. Streaming is never requested upstream.
type ForwardResponse struct {
	Body  []byte
	Usage Usage
}

// ForwardOutputCap returns the output cap a forwarded request declares (0 when
// it declares none), after the checks Forward applies. Accounting reserves
// budget from it before anything reaches the provider.
func ForwardOutputCap(dialect string, body []byte) (int, error) {
	_, max, err := forwardFields(dialect, body)
	return max, err
}

// Forward sends an agent's native request to its alias's provider: same retries,
// breaker and outcome rules as Complete.
func (g *Gateway) Forward(ctx context.Context, route Route, dialect string, body []byte) (ForwardResponse, error) {
	if route.Secret == "" || route.UpstreamModel == "" {
		return ForwardResponse{}, ErrInvalid
	}
	fields, _, err := forwardFields(dialect, body)
	if err != nil {
		return ForwardResponse{}, err
	}
	var target string
	var headers map[string]string
	switch {
	case dialect == DialectOpenAI && route.Kind == "openai_compatible":
		target, headers = join(route.BaseURL, "/chat/completions"), map[string]string{"Authorization": "Bearer " + route.Secret}
	case dialect == DialectAnthropic && route.Kind == "anthropic":
		target, headers = join(route.BaseURL, "/v1/messages"), map[string]string{"x-api-key": route.Secret, "anthropic-version": "2023-06-01"}
	default:
		return ForwardResponse{}, ErrDialect
	}
	model, err := json.Marshal(route.UpstreamModel)
	if err != nil {
		return ForwardResponse{}, ErrInvalid
	}
	fields["model"] = model
	prepared, err := json.Marshal(fields)
	if err != nil || len(prepared) > MaxForwardBytes+len(model) {
		return ForwardResponse{}, ErrInvalid
	}
	var out ForwardResponse
	err = g.exchange(ctx, route.Key, target, prepared, headers, func(raw []byte) error {
		if len(raw) > MaxForwardBytes {
			return ErrInvalid
		}
		usage, err := forwardUsage(dialect, raw)
		if err != nil {
			return err
		}
		out = ForwardResponse{Body: raw, Usage: usage}
		return nil
	})
	if err != nil {
		return ForwardResponse{}, err
	}
	return out, nil
}

// forwardFields parses and checks a forwarded request. The agent chooses its
// messages, tools and options; it cannot ask for a stream (the answer must be
// accounted as a whole), for several choices (billed several times), or exceed
// the output bound. Its model name is replaced by the alias's upstream model.
func forwardFields(dialect string, body []byte) (map[string]json.RawMessage, int, error) {
	if (dialect != DialectOpenAI && dialect != DialectAnthropic) || len(body) == 0 || len(body) > MaxForwardBytes {
		return nil, 0, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return nil, 0, ErrInvalid
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(fields["messages"], &messages); err != nil || len(messages) == 0 {
		return nil, 0, ErrInvalid
	}
	if s, ok := fields["stream"]; ok && !bytes.Equal(bytes.TrimSpace(s), []byte("false")) && !bytes.Equal(bytes.TrimSpace(s), []byte("null")) {
		return nil, 0, ErrInvalid
	}
	delete(fields, "stream")
	delete(fields, "stream_options")
	caps := []string{"max_tokens"}
	if dialect == DialectOpenAI {
		caps = append(caps, "max_completion_tokens")
		if n, ok := fields["n"]; ok {
			var v *int
			if json.Unmarshal(n, &v) != nil || (v != nil && *v != 1) {
				return nil, 0, ErrInvalid
			}
		}
	}
	max := 0
	for _, name := range caps {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		var v *int
		if json.Unmarshal(raw, &v) != nil {
			return nil, 0, ErrInvalid
		}
		if v == nil {
			continue
		}
		if *v < 1 || *v > maxForwardOutput {
			return nil, 0, ErrInvalid
		}
		max = *v
	}
	if dialect == DialectAnthropic && max == 0 {
		return nil, 0, ErrInvalid // the Messages API requires an explicit bound
	}
	return fields, max, nil
}

// forwardUsage reads the provider-reported usage of an answer. Anthropic counts
// cached input separately; it is input all the same.
func forwardUsage(dialect string, raw []byte) (Usage, error) {
	if dialect == DialectOpenAI {
		var v struct {
			Choices []json.RawMessage `json:"choices"`
			Usage   struct {
				Prompt     int64 `json:"prompt_tokens"`
				Completion int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &v); err != nil || len(v.Choices) == 0 || v.Usage.Prompt < 0 || v.Usage.Completion < 0 {
			return Usage{}, ErrInvalid
		}
		return Usage{v.Usage.Prompt, v.Usage.Completion}, nil
	}
	var v struct {
		Content []json.RawMessage `json:"content"`
		Usage   struct {
			In          int64 `json:"input_tokens"`
			CacheCreate int64 `json:"cache_creation_input_tokens"`
			CacheRead   int64 `json:"cache_read_input_tokens"`
			Out         int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Content == nil || v.Usage.In < 0 || v.Usage.CacheCreate < 0 || v.Usage.CacheRead < 0 || v.Usage.Out < 0 {
		return Usage{}, ErrInvalid
	}
	return Usage{v.Usage.In + v.Usage.CacheCreate + v.Usage.CacheRead, v.Usage.Out}, nil
}
