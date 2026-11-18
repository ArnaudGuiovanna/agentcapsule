package capsuleprotocol

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

// gatedPlatform is a host whose agent may only use allowed capabilities.
type gatedPlatform struct {
	platformFake
	mu      sync.Mutex
	allowed []string
	asked   []string
}

func (g *gatedPlatform) RequireCapability(_ context.Context, name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, name)
	if !slices.Contains(g.allowed, name) {
		return &PlatformError{Code: "capability_denied"}
	}
	return nil
}
func (g *gatedPlatform) CompleteLLM(context.Context, string, LLMRequest) (LLMResult, error) {
	g.calls.Add(1)
	return LLMResult{Text: "answer"}, nil
}

// The host checks the capability a route needs before the call reaches the
// effect, and refuses with the typed code capability_denied. Routes that
// answer delivered work need no capability.
func TestPlatformChannelEnforcesCapabilities(t *testing.T) {
	api := &gatedPlatform{allowed: []string{"agents.delegate"}}
	c, _, _, _ := platformFixtureFor(t, api)
	_, err := c.CompleteLLM(t.Context(), "k", LLMRequest{Alias: "default", Messages: []LLMMessage{{Role: "user", Content: "hi"}}})
	var denied *PlatformError
	if !errors.As(err, &denied) || denied.Code != "capability_denied" || api.calls.Load() != 0 {
		t.Fatal("model call without llm.invoke", err, api.calls.Load())
	}
	if _, err = c.Search(t.Context(), []string{"b"}); !errors.As(err, &denied) || denied.Code != "capability_denied" {
		t.Fatal("search without agents.discover", err)
	}
	if r, err := c.Submit(t.Context(), "one", Submission{RecipientAgentID: "b"}); err != nil || r.RequestID != "request" {
		t.Fatal("allowed submission", r, err)
	}
	if _, err = c.Reply(t.Context(), "request", "r", Reply{Outcome: "completed"}); err != nil {
		t.Fatal("a reply needs no capability", err)
	}
	api.mu.Lock()
	asked := slices.Clone(api.asked)
	api.mu.Unlock()
	if !slices.Equal(asked, []string{"llm.invoke", "agents.discover", "agents.delegate"}) {
		t.Fatal("capabilities checked", asked)
	}
	api.mu.Lock()
	api.allowed = append(api.allowed, "llm.invoke")
	api.mu.Unlock()
	if r, err := c.CompleteLLM(t.Context(), "k", LLMRequest{Alias: "default", Messages: []LLMMessage{{Role: "user", Content: "hi"}}}); err != nil || r.Text != "answer" {
		t.Fatal("allowed model call", r, err)
	}
}
