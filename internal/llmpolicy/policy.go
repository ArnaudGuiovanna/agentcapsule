// Package llmpolicy is what an alias allows a model call, as the LLM gateway
// (internal/llmgateway), which enforces it, and the control plane
// (internal/controlplane), which stores it, both read it: the request policy,
// the syntax of the names it lists, the fields the gateway keeps for itself,
// and the refusal of an operation the alias's provider does not serve. It
// imports the standard library only, so that the control plane needs no part
// of the gateway (v0.1.0 audit, finding A-02).
package llmpolicy

import (
	"errors"
	"regexp"
	"slices"
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
	// DefaultForwardOutput or DefaultCompleteOutput (internal/llmgateway).
	MaxOutputTokens int
	// OutputCapField is the field an openai_compatible provider reads that
	// cap from: "max_tokens" (the default, which local servers such as Ollama
	// read) or "max_completion_tokens" (which OpenAI's reasoning models
	// require). An anthropic provider reads max_tokens.
	OutputCapField string
}

// MaxPolicyNames bounds each list of a policy.
const MaxPolicyNames = 32

var policyName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidPolicyName is the syntax of a field or tool type a policy names.
func ValidPolicyName(s string) bool { return policyName.MatchString(s) }

// gatewayFields are the fields the gateway itself rules on: no policy can
// allow them.
var gatewayFields = []string{"model", "messages", "stream", "stream_options", "n", "max_tokens", "max_completion_tokens"}

// GatewayField reports whether a field is the gateway's own.
func GatewayField(s string) bool { return slices.Contains(gatewayFields, s) }

// ErrUnsupported: the alias's provider kind does not serve this operation
// (only an openai_compatible provider serves embeddings, transcription and
// OCR). The alias's operations are checked before this, when it is set.
var ErrUnsupported = errors.New("llm provider does not serve this operation")
