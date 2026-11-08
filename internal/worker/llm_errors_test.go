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
	} {
		wrapped := fmt.Errorf("provider said sk-live-secret: %w", err)
		var pe *capsuleprotocol.PlatformError
		if got := platformError(wrapped); !errors.As(got, &pe) || pe.Code != want || got.Error() != "capsule platform: "+want {
			t.Fatalf("%v -> %v, want %s", err, got, want)
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
