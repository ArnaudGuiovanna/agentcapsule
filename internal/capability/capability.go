// Package capability names what an agent may ask the platform for over its
// platform channel, beyond answering the work delivered to it (CAP-01, ADR 016).
//
// A harness requests capabilities in harness.yaml. An organization and each of
// its agents allow some. The effective set of a running agent is their
// intersection: harness ∩ organization ∩ agent (product.md §3). This package
// holds only the vocabulary and set operations; it reads nothing.
package capability

import (
	"errors"
	"slices"
	"strings"
)

const (
	// LLMInvoke: call the organization's models (/v1/llm/complete, /v1/llm/forward).
	LLMInvoke = "llm.invoke"
	// AgentsDelegate: send requests to other agents and follow them
	// (/v1/agent-requests, /v1/agent-requests/{id}/status).
	AgentsDelegate = "agents.delegate"
	// AgentsDiscover: search and describe the organization's agents
	// (/v1/directory/find, /v1/directory/search, /v1/directory/agent).
	AgentsDiscover = "agents.discover"
)

// Known returns every capability, sorted.
func Known() []string { return []string{AgentsDelegate, AgentsDiscover, LLMInvoke} }

// ErrUnknown: a set names a capability this platform does not know, or one twice.
var ErrUnknown = errors.New("unknown or repeated capability")

// ValidSet accepts known names, each at most once. An empty set is valid.
func ValidSet(names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if !slices.Contains(Known(), n) || seen[n] {
			return ErrUnknown
		}
		seen[n] = true
	}
	return nil
}

// Intersect returns the names present in every set, sorted, never nil.
func Intersect(sets ...[]string) []string {
	out := []string{}
	for _, n := range Known() {
		in := true
		for _, s := range sets {
			if !slices.Contains(s, n) {
				in = false
				break
			}
		}
		if in {
			out = append(out, n)
		}
	}
	return out
}

// ForRoute is the capability a platform channel route needs, or "" when it
// needs none: health, answering delivered work (replies, completions, owner
// messages) and reading an invocation's own files.
func ForRoute(path string) string {
	switch path {
	case "/v1/llm/complete", "/v1/llm/forward":
		return LLMInvoke
	case "/v1/agent-requests":
		return AgentsDelegate
	case "/v1/directory/find", "/v1/directory/search", "/v1/directory/agent":
		return AgentsDiscover
	}
	if strings.HasPrefix(path, "/v1/agent-requests/") && strings.HasSuffix(path, "/status") {
		return AgentsDelegate
	}
	return ""
}
