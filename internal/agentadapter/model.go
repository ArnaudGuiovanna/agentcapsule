package agentadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// Forwarder is the platform call behind the model endpoint.
type Forwarder interface {
	ForwardLLM(context.Context, string, capsuleprotocol.LLMForward) (capsuleprotocol.LLMForwardResult, error)
}

// ModelEndpoint answers the agent's own SDK as if it were the OpenAI Chat
// Completions or Anthropic Messages API. Each request is forwarded once, under
// a fresh key, to the platform; a stream is requested by the agent but never
// from the provider, so the endpoint replays the complete answer as one stream.
type ModelEndpoint struct {
	Config   Config
	Platform Forwarder
}

func (m *ModelEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var dialect string
	switch r.URL.Path {
	case "/v1/chat/completions", "/chat/completions":
		dialect = "openai"
	case "/v1/messages", "/messages":
		dialect = "anthropic"
	case "/v1/models", "/models":
		if r.Method != http.MethodGet {
			modelError(w, "openai", http.StatusMethodNotAllowed, "invalid_request_error", "Use GET.")
			return
		}
		m.models(w)
		return
	default:
		modelError(w, "openai", http.StatusNotFound, "not_found_error", "This endpoint serves /v1/chat/completions and /v1/messages.")
		return
	}
	if r.Method != http.MethodPost {
		modelError(w, dialect, http.StatusMethodNotAllowed, "invalid_request_error", "Use POST.")
		return
	}
	if m.Platform == nil {
		modelError(w, dialect, http.StatusServiceUnavailable, "api_error", "The platform channel is unavailable.")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, capsuleprotocol.MaxLLMForwardBytes))
	if err != nil {
		modelError(w, dialect, http.StatusRequestEntityTooLarge, "request_too_large", fmt.Sprintf("Requests are limited to %d bytes.", capsuleprotocol.MaxLLMForwardBytes))
		return
	}
	var fields map[string]json.RawMessage
	var model string
	if json.Unmarshal(body, &fields) != nil || fields == nil || json.Unmarshal(fields["model"], &model) != nil || model == "" {
		modelError(w, dialect, http.StatusBadRequest, "invalid_request_error", "The body must be a JSON object naming a model.")
		return
	}
	alias, ok := m.Config.Alias(model)
	if !ok {
		modelError(w, dialect, http.StatusNotFound, "not_found_error", "Unknown model "+model+".")
		return
	}
	stream := isTrue(fields["stream"])
	var options struct {
		IncludeUsage bool `json:"include_usage"`
	}
	_ = json.Unmarshal(fields["stream_options"], &options)
	delete(fields, "stream")
	delete(fields, "stream_options")
	forwarded, err := json.Marshal(fields)
	if err != nil {
		modelError(w, dialect, http.StatusBadRequest, "invalid_request_error", "The body could not be read.")
		return
	}
	res, err := m.Platform.ForwardLLM(r.Context(), newKey(), capsuleprotocol.LLMForward{Alias: alias, Dialect: dialect, Body: forwarded})
	if err != nil {
		status, kind, message := explain(err, alias)
		modelError(w, dialect, status, kind, message)
		return
	}
	// The agent sees the model name it asked for, not the provider's.
	var answer map[string]json.RawMessage
	if json.Unmarshal(res.Body, &answer) != nil || answer == nil {
		modelError(w, dialect, http.StatusBadGateway, "api_error", "The provider's answer could not be read.")
		return
	}
	answer["model"], _ = json.Marshal(model)
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	// Headers are sent: a write error leaves the client a truncated stream.
	if dialect == "openai" {
		_ = openAIStream(w, answer, options.IncludeUsage)
	} else {
		_ = anthropicStream(w, answer)
	}
}

func (m *ModelEndpoint) models(w http.ResponseWriter) {
	names := map[string]bool{}
	for name := range m.Config.Models {
		names[name] = true
	}
	if m.Config.DefaultModel != "" {
		names[m.Config.DefaultModel] = true
	}
	type entry struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	list := []entry{}
	for name := range names {
		list = append(list, entry{ID: name, Object: "model", OwnedBy: "agentcapsule"})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": list})
}

func isTrue(raw json.RawMessage) bool {
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "mdl_" + hex.EncodeToString(b)
}

// explain turns a platform outcome into the status and message an SDK expects.
func explain(err error, alias string) (int, string, string) {
	var remote *capsuleprotocol.PlatformError
	if !errors.As(err, &remote) {
		return http.StatusBadGateway, "api_error", "The platform could not be reached."
	}
	switch remote.Code {
	case "not_found":
		return http.StatusNotFound, "not_found_error", "The organization has no active model alias " + alias + "."
	case "dialect":
		return http.StatusBadRequest, "invalid_request_error", "The model alias " + alias + " is served by a provider that speaks the other API (OpenAI Chat Completions or Anthropic Messages)."
	case "invalid":
		return http.StatusBadRequest, "invalid_request_error", "The request was refused: it must not ask for several choices, and it must bound its output (Anthropic) to at most 1,000,000 tokens."
	case "quota_exceeded":
		return http.StatusTooManyRequests, "rate_limit_error", "The organization's token budget for this agent or model is exhausted."
	case "rate_limited":
		return http.StatusTooManyRequests, "rate_limit_error", "The provider is rate limiting; retry later."
	case "rejected":
		return http.StatusBadRequest, "invalid_request_error", "The provider refused the request."
	case "outcome_unknown":
		return http.StatusGatewayTimeout, "api_error", "The provider did not answer in time; the request may have been processed."
	case "unauthorized":
		return http.StatusForbidden, "permission_error", "This agent may not call models now."
	}
	return http.StatusServiceUnavailable, "api_error", "The model service is unavailable; retry later."
}

func modelError(w http.ResponseWriter, dialect string, status int, kind, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if dialect == "anthropic" {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": message}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": message, "type": kind, "code": nil}})
}

func sse(w io.Writer, event string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if event != "" {
		buf.WriteString("event: " + event + "\n")
	}
	buf.WriteString("data: ")
	buf.Write(b)
	buf.WriteString("\n\n")
	if _, err = w.Write(buf.Bytes()); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// openAIStream replays a chat completion as chunks: each choice's message as
// one delta, then its finish reason, then the usage when asked, then [DONE].
func openAIStream(w io.Writer, answer map[string]json.RawMessage, includeUsage bool) error {
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(answer["choices"], &choices); err != nil {
		return err
	}
	head := map[string]json.RawMessage{"object": json.RawMessage(`"chat.completion.chunk"`)}
	for _, k := range []string{"id", "created", "model", "system_fingerprint", "service_tier"} {
		if v, ok := answer[k]; ok {
			head[k] = v
		}
	}
	if _, ok := head["created"]; !ok {
		head["created"], _ = json.Marshal(time.Now().Unix())
	}
	chunk := func(choices any, usage json.RawMessage) map[string]any {
		out := map[string]any{"choices": choices}
		for k, v := range head {
			out[k] = v
		}
		if usage != nil {
			out["usage"] = usage
		}
		return out
	}
	for i, c := range choices {
		var message map[string]json.RawMessage
		_ = json.Unmarshal(c["message"], &message)
		if message == nil {
			message = map[string]json.RawMessage{}
		}
		// Streamed tool calls carry their position.
		if raw, ok := message["tool_calls"]; ok {
			var calls []map[string]json.RawMessage
			if json.Unmarshal(raw, &calls) == nil {
				for n := range calls {
					calls[n]["index"], _ = json.Marshal(n)
				}
				message["tool_calls"], _ = json.Marshal(calls)
			}
		}
		index := c["index"]
		if index == nil {
			index, _ = json.Marshal(i)
		}
		if err := sse(w, "", chunk([]any{map[string]any{"index": index, "delta": message, "finish_reason": nil}}, nil)); err != nil {
			return err
		}
		finish := c["finish_reason"]
		if finish == nil {
			finish = json.RawMessage(`"stop"`)
		}
		if err := sse(w, "", chunk([]any{map[string]any{"index": index, "delta": map[string]any{}, "finish_reason": finish}}, nil)); err != nil {
			return err
		}
	}
	if includeUsage && answer["usage"] != nil {
		if err := sse(w, "", chunk([]any{}, answer["usage"])); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "data: [DONE]\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return err
}

// anthropicStream replays a message as the Messages API's event sequence: each
// content block whole, in one delta.
func anthropicStream(w io.Writer, answer map[string]json.RawMessage) error {
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(answer["content"], &blocks); err != nil {
		return err
	}
	var usage map[string]json.RawMessage
	_ = json.Unmarshal(answer["usage"], &usage)
	start := map[string]json.RawMessage{}
	for k, v := range answer {
		start[k] = v
	}
	start["content"] = json.RawMessage(`[]`)
	start["stop_reason"] = json.RawMessage(`null`)
	start["stop_sequence"] = json.RawMessage(`null`)
	startUsage := map[string]json.RawMessage{"output_tokens": json.RawMessage(`0`)}
	for k, v := range usage {
		if k != "output_tokens" {
			startUsage[k] = v
		}
	}
	start["usage"], _ = json.Marshal(startUsage)
	if err := sse(w, "message_start", map[string]any{"type": "message_start", "message": start}); err != nil {
		return err
	}
	for i, block := range blocks {
		var kind string
		_ = json.Unmarshal(block["type"], &kind)
		first := map[string]json.RawMessage{}
		for k, v := range block {
			first[k] = v
		}
		var delta map[string]any
		switch kind {
		case "text":
			first["text"] = json.RawMessage(`""`)
			delta = map[string]any{"type": "text_delta", "text": block["text"]}
		case "tool_use", "server_tool_use":
			first["input"] = json.RawMessage(`{}`)
			input := block["input"]
			if input == nil {
				input = json.RawMessage(`{}`)
			}
			delta = map[string]any{"type": "input_json_delta", "partial_json": string(input)}
		case "thinking":
			first["thinking"] = json.RawMessage(`""`)
			delete(first, "signature")
			delta = map[string]any{"type": "thinking_delta", "thinking": block["thinking"]}
		}
		if err := sse(w, "content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": first}); err != nil {
			return err
		}
		if delta != nil {
			if err := sse(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": delta}); err != nil {
				return err
			}
		}
		if sig, ok := block["signature"]; ok && kind == "thinking" {
			if err := sse(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "signature_delta", "signature": sig}}); err != nil {
				return err
			}
		}
		if err := sse(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": i}); err != nil {
			return err
		}
	}
	// A missing field is a nil RawMessage, which encodes as null.
	stop := map[string]any{"stop_reason": answer["stop_reason"], "stop_sequence": answer["stop_sequence"]}
	out := usage["output_tokens"]
	if out == nil {
		out = json.RawMessage(`0`)
	}
	if err := sse(w, "message_delta", map[string]any{"type": "message_delta", "delta": stop, "usage": map[string]any{"output_tokens": out}}); err != nil {
		return err
	}
	return sse(w, "message_stop", map[string]any{"type": "message_stop"})
}
