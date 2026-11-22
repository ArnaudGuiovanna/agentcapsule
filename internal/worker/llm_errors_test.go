//go:build linux

package worker

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

func TestModelBridgeErrorsCrossAsEnumeratedCodesOnly(t *testing.T) {
	for want, err := range map[string]error{
		"quota_exceeded":  controlplane.ErrBudgetExceeded,
		"rate_limited":    llmgateway.ErrRateLimited,
		"rejected":        llmgateway.ErrRejected,
		"outcome_unknown": llmgateway.ErrOutcomeUnknown,
		"conflict":        controlplane.ErrLLMAlreadyProcessed,
		"invalid":         llmgateway.ErrInvalid,
		"unauthorized":    controlplane.ErrForbidden,
		"not_found":       controlplane.ErrNotFound,
		"unavailable":     llmgateway.ErrUnavailable,
		// The alias's request policy and the agent's calls in flight (v0.1.0
		// audit, S-11 and S-13).
		"feature_denied":      llmgateway.ErrFeatureDenied,
		"concurrency_limited": controlplane.ErrLLMConcurrency,
	} {
		wrapped := fmt.Errorf("provider said sk-live-secret: %w", err)
		var pe *capsuleprotocol.PlatformError
		if got := platformError(wrapped); !errors.As(got, &pe) || pe.Code != want || got.Error() != "capsule platform: "+want {
			t.Fatalf("%v -> %v, want %s", err, got, want)
		}
	}
}

// A policy refusal keeps the codes the guest knows: an alias not granted to
// the agent is unauthorized, a hard budget in tokens or cost, or a hard cost
// budget on an unpriced alias, is quota_exceeded.
func TestModelBridgeRefusalsCrossAsKnownCodes(t *testing.T) {
	for _, c := range []struct {
		reason, want string
	}{{"alias_access", "unauthorized"}, {"budget_tokens", "quota_exceeded"}, {"budget_cost", "quota_exceeded"}, {"unpriced", "quota_exceeded"}} {
		var pe *capsuleprotocol.PlatformError
		if got := platformError(&controlplane.LLMRefusal{Reason: c.reason, Period: "day", Scope: "agent"}); !errors.As(got, &pe) || pe.Code != c.want {
			t.Fatalf("%s -> %v, want %s", c.reason, got, c.want)
		}
	}
}

func TestModelBridgeIsUnavailableUntilEnabled(t *testing.T) {
	api := platformAPI{}
	_, err := api.CompleteLLM(t.Context(), "k", capsuleprotocol.LLMRequest{Alias: "fast", Messages: []capsuleprotocol.LLMMessage{{Role: "user", Content: "x"}}})
	var pe *capsuleprotocol.PlatformError
	if !errors.As(err, &pe) || pe.Code != "unavailable" {
		t.Fatal(err)
	}
}
