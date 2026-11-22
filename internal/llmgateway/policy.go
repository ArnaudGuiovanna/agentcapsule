package llmgateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
)

// RequestPolicy is what an alias lets a call ask of its provider (audit
// findings S-11 and S-13). A forwarded request keeps the agent's body, but
// only its dialect's plain fields pass by default: the client's own tools
// (functions and custom tools), messages, sampling and format options. A
// tool the provider runs itself (web search or fetch, code execution, file
// search, computer use, an MCP connector) and an option that changes the
// price of a call or keeps data at the provider (a service tier, a stored or
// background response, audio output, a vendor extension) are refused before
// anything is reserved, unless the organization names them here.
type RequestPolicy struct {
	// AllowedFields are top-level fields of a forwarded request allowed
	// beside the dialect's plain ones (service_tier, store, web_search_options,
	// mcp_servers, top_k...).
	AllowedFields []string
	// AllowedToolTypes are tool types allowed beside the client's own
	// (web_search_20250305, code_interpreter, mcp...).
	AllowedToolTypes []string
	// MaxOutputTokens is the output cap of a call that declares none: it is
	// written into the request and reserved. 0: the route's default,
	// DefaultForwardOutput or DefaultCompleteOutput.
	MaxOutputTokens int
	// OutputCapField is the field an openai_compatible provider reads that
	// cap from: "max_tokens" (the default, which local servers such as Ollama
	// read) or "max_completion_tokens" (which OpenAI's reasoning models
	// require). An anthropic provider reads max_tokens.
	OutputCapField string
}

// ErrFeatureDenied refuses, before any reservation, a forwarded request that
// uses a top-level field or a tool type its alias does not allow.
var ErrFeatureDenied = errors.New("llm request uses a field or a tool type its alias does not allow")

// Bounds and defaults of a request policy.
const (
	// MaxPolicyNames bounds each list of a policy.
	MaxPolicyNames = 32
	// DefaultForwardOutput and DefaultCompleteOutput are the output caps of
	// a call that declares none on an alias without MaxOutputTokens.
	DefaultForwardOutput  = 4096
	DefaultCompleteOutput = 1024
	// ImageInputTokens and DocumentInputTokens are reserved for each image,
	// and each document, that the provider fetches itself (by URL or by a
	// file of the provider's): the body holds a reference, not the content.
	// An image costs at most about 1,600 tokens at Anthropic and 3,800 at
	// OpenAI; a document, up to the 100 pages a hosted API takes at about
	// 3,000 tokens each.
	ImageInputTokens    = 4096
	DocumentInputTokens = 300_000
)

var policyName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidPolicyName is the syntax of a field or tool type a policy names.
func ValidPolicyName(s string) bool { return policyName.MatchString(s) }

// gatewayFields are the fields the gateway itself rules on: no policy can
// allow them.
var gatewayFields = []string{"model", "messages", "stream", "stream_options", "n", "max_tokens", "max_completion_tokens"}

// GatewayField reports whether a field is the gateway's own.
func GatewayField(s string) bool { return slices.Contains(gatewayFields, s) }

// plainFields are the top-level fields every alias accepts, per dialect:
// what the call costs is its tokens, which the output cap bounds and the
// provider reports.
var plainFields = map[string][]string{
	DialectOpenAI: {"model", "messages", "stream", "stream_options", "n", "max_tokens", "max_completion_tokens",
		"temperature", "top_p", "stop", "seed", "frequency_penalty", "presence_penalty", "logit_bias", "logprobs", "top_logprobs",
		"response_format", "tools", "tool_choice", "parallel_tool_calls", "functions", "function_call", "user", "reasoning_effort",
		"verbosity", "prompt_cache_key", "safety_identifier"},
	DialectAnthropic: {"model", "messages", "stream", "max_tokens", "system", "temperature", "top_p", "top_k", "stop_sequences",
		"tools", "tool_choice", "metadata", "thinking", "output_config"},
}

// neutralValues are the values of a denied field that change nothing: the
// provider's own default. JSON null is neutral for every field, and dropped.
var neutralValues = map[string]map[string][]string{
	DialectOpenAI:    {"store": {"false"}, "service_tier": {`"auto"`, `"default"`}},
	DialectAnthropic: {"service_tier": {`"auto"`, `"standard_only"`}},
}

// clientToolTypes are the tools the agent runs itself. An Anthropic tool
// without a type is the client's too.
var clientToolTypes = []string{"function", "custom"}

func (p RequestPolicy) outputCap(declared, fallback int) int {
	switch {
	case declared > 0:
		return declared
	case p.MaxOutputTokens > 0:
		return p.MaxOutputTokens
	}
	return fallback
}

// capField is the field an openai_compatible provider reads the cap from.
func (p RequestPolicy) capField() string {
	if p.OutputCapField == "max_completion_tokens" {
		return p.OutputCapField
	}
	return "max_tokens"
}

// CompleteOutputCap is the output cap of a text request: its own, else the
// policy's, else DefaultCompleteOutput. The request sent to the provider
// carries it, and the accounting reserves it.
func CompleteOutputCap(p RequestPolicy, q Request) int {
	return p.outputCap(q.MaxTokens, DefaultCompleteOutput)
}

// check applies the policy to a forwarded request's fields: a field neither
// plain nor allowed passes only with a neutral value (null is dropped), and
// each tool must be the client's own or of an allowed type.
func (p RequestPolicy) check(dialect string, fields map[string]json.RawMessage) error {
	for name, raw := range fields {
		if slices.Contains(plainFields[dialect], name) || slices.Contains(p.AllowedFields, name) {
			continue
		}
		value := bytes.TrimSpace(raw)
		switch {
		case bytes.Equal(value, []byte("null")):
			delete(fields, name)
		case !slices.Contains(neutralValues[dialect][name], string(value)):
			return ErrFeatureDenied
		}
	}
	// OpenAI's legacy functions are the client's own: only tools are typed.
	raw, ok := fields["tools"]
	if !ok {
		return nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return ErrInvalid
	}
	for _, tool := range tools {
		var v map[string]json.RawMessage
		if err := json.Unmarshal(tool, &v); err != nil || v == nil {
			return ErrInvalid
		}
		var kind *string
		if t, ok := v["type"]; ok && json.Unmarshal(t, &kind) != nil {
			return ErrFeatureDenied
		}
		switch {
		case kind == nil && dialect == DialectAnthropic,
			kind != nil && (slices.Contains(clientToolTypes, *kind) || slices.Contains(p.AllowedToolTypes, *kind)):
		default:
			return ErrFeatureDenied
		}
	}
	return nil
}

// ForwardPlan is what the accounting reserves for a forwarded request: its
// estimated input and the output cap the provider is held to.
type ForwardPlan struct {
	Input, Output int64
}

// PlanForward checks a forwarded request against its alias's policy and
// returns what to reserve for it, before anything reaches the provider. It
// refuses what Forward (stream false) or ForwardStream (stream true) would
// refuse for the request itself.
func PlanForward(p RequestPolicy, dialect string, body []byte, stream bool) (ForwardPlan, error) {
	_, plan, err := prepareForward(p, dialect, body, stream)
	return plan, err
}

// prepareForward parses a forwarded request, applies the policy, and holds the
// request to the output cap it is reserved for: its own, else the policy's,
// else the default. The cap is written in the one field the provider reads
// (the policy's for an openai_compatible provider), whichever field the
// agent's SDK used: a server that reads only max_tokens would otherwise
// ignore a max_completion_tokens, and write past the reservation.
func prepareForward(p RequestPolicy, dialect string, body []byte, stream bool) (map[string]json.RawMessage, ForwardPlan, error) {
	fields, declared, err := forwardFields(dialect, body, stream)
	if err != nil {
		return nil, ForwardPlan{}, err
	}
	if err = p.check(dialect, fields); err != nil {
		return nil, ForwardPlan{}, err
	}
	output := p.outputCap(declared, DefaultForwardOutput)
	field := "max_tokens"
	if dialect == DialectOpenAI {
		field = p.capField()
	}
	delete(fields, "max_tokens")
	delete(fields, "max_completion_tokens")
	fields[field] = mustMarshal(output)
	images, documents := mediaReferences(fields)
	return fields, ForwardPlan{Input: EstimateTokens(body) + images*ImageInputTokens + documents*DocumentInputTokens, Output: int64(output)}, nil
}

func mustMarshal(n int) json.RawMessage {
	b, _ := json.Marshal(n)
	return b
}

// EstimateTokens is the reservation of a text, or of a request's body: one
// token per three ASCII bytes and one per other byte, plus one. Text in
// another script (CJK, emoji) has more tokens per byte than English. It is
// an estimate, not a bound: a text of single characters split by spaces has
// about one token per two bytes.
func EstimateTokens(text []byte) int64 {
	var c tokenCount
	c.add(string(text))
	return c.estimate()
}

// tokenCount counts the bytes of texts for EstimateTokens.
type tokenCount struct{ ascii, other int64 }

func (c *tokenCount) add(text string) {
	for i := 0; i < len(text); i++ {
		if text[i] < 0x80 {
			c.ascii++
		} else {
			c.other++
		}
	}
}

func (c tokenCount) estimate() int64 { return c.ascii/3 + c.other + 1 }

// mediaReferences counts the images and the documents a request's messages
// reference without carrying them: an image or a file by URL or by a file id
// of the provider. Inline media (base64, data URLs) are in the body, which
// the estimate counts.
func mediaReferences(fields map[string]json.RawMessage) (images, documents int64) {
	for _, name := range []string{"messages", "system"} {
		var v any
		if raw, ok := fields[name]; !ok || json.Unmarshal(raw, &v) != nil {
			continue
		}
		walkJSON(v, func(o map[string]any) {
			kind, _ := o["type"].(string)
			switch kind {
			case "image_url": // OpenAI: {"image_url": {"url": ...}} or {"image_url": "..."}
				url, _ := o["image_url"].(string)
				if inner, ok := o["image_url"].(map[string]any); ok {
					url, _ = inner["url"].(string)
				}
				if !strings.HasPrefix(url, "data:") {
					images++
				}
			case "file": // OpenAI: {"file": {"file_id": ...}} or inline file_data
				if f, ok := o["file"].(map[string]any); ok && f["file_data"] == nil {
					documents++
				}
			case "image", "document": // Anthropic: a source of type url or file
				if s, ok := o["source"].(map[string]any); ok && (s["type"] == "url" || s["type"] == "file") {
					if kind == "image" {
						images++
					} else {
						documents++
					}
				}
			case "container_upload": // Anthropic: a file of the provider's
				documents++
			}
		})
	}
	return images, documents
}

func walkJSON(v any, visit func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		visit(x)
		for _, child := range x {
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range x {
			walkJSON(child, visit)
		}
	}
}
