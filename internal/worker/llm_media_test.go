//go:build linux

package worker

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// An alias that does not declare a route's operation, or a provider that
// cannot serve it, reaches the guest as unsupported, never as a budget or
// authorization refusal.
func TestUnsupportedOperationCrossesAsItsOwnCode(t *testing.T) {
	for _, err := range []error{&controlplane.LLMRefusal{Reason: "unsupported"}, llmgateway.ErrUnsupported} {
		var pe *capsuleprotocol.PlatformError
		if got := platformError(err); !errors.As(got, &pe) || pe.Code != "unsupported" {
			t.Fatal(err, got)
		}
	}
}

func TestMediaBridgeIsUnavailableUntilEnabled(t *testing.T) {
	api := platformAPI{}
	var pe *capsuleprotocol.PlatformError
	_, err1 := api.EmbedLLM(t.Context(), "k", capsuleprotocol.LLMEmbed{Alias: "e", Input: []string{"x"}})
	_, err2 := api.TranscribeLLM(t.Context(), "k", capsuleprotocol.LLMTranscribe{Alias: "v", Audio: []byte("a"), Format: "mp3", DurationSeconds: 1})
	_, err3 := api.OCRLLM(t.Context(), "k", capsuleprotocol.LLMOCR{Alias: "o", Document: []byte("a"), MediaType: "image/png", Pages: 1})
	for _, err := range []error{err1, err2, err3} {
		if !errors.As(err, &pe) || pe.Code != "unavailable" {
			t.Fatal(err)
		}
	}
}

// The guest checks the bounds the host applies: both sides agree.
func TestGuestAndHostShareTheMediaBounds(t *testing.T) {
	if capsuleprotocol.MaxLLMMediaBytes != llmgateway.MaxMediaBytes || capsuleprotocol.MaxLLMEmbedInputs != llmgateway.MaxEmbedInputs ||
		capsuleprotocol.MaxLLMEmbedInputBytes != llmgateway.MaxEmbedInputBytes || capsuleprotocol.MaxLLMAudioSeconds != llmgateway.MaxAudioSeconds ||
		capsuleprotocol.MaxLLMOCRPages != llmgateway.MaxOCRPages || capsuleprotocol.MaxLLMPromptRunes != llmgateway.MaxPromptRunes ||
		capsuleprotocol.MaxLLMForwardBytes != llmgateway.MaxForwardBytes {
		t.Fatal("the guest's and the host's bounds differ")
	}
	// The largest request fits the channel's message.
	if 4*((capsuleprotocol.MaxLLMMediaBytes+2)/3)+4*capsuleprotocol.MaxLLMPromptRunes+4096 > capsuleprotocol.MaxMessageBytes {
		t.Fatal("a transcription request at its bounds does not fit the channel")
	}
}

func TestMediaMetricsCountSecondsAndPagesByProviderKind(t *testing.T) {
	registry := telemetry.NewRegistry()
	var logs bytes.Buffer
	vocabulary := map[string][]string{"event": LLMEvents()}
	for k, v := range LLMEventCodes() {
		vocabulary[k] = v
	}
	m := NewLLMTelemetry(registry, telemetry.NewLogger(&logs, vocabulary), func(context.Context) (int64, error) { return 0, nil })
	m.ObserveLLM(controlplane.LLMCallEvent{Provider: "openai_compatible", Operation: "transcribe", Outcome: "settled", AudioSeconds: 288, CostMicro: 28_800})
	m.ObserveLLM(controlplane.LLMCallEvent{Provider: "openai_compatible", Operation: "ocr", Outcome: "settled", Pages: 3})
	m.ObserveLLM(controlplane.LLMCallEvent{Provider: "openai_compatible", Operation: "embed", Outcome: "settled", InputTokens: 9})
	m.ObserveLLM(controlplane.LLMCallEvent{Provider: "openai_compatible", Outcome: "refused", Reason: "unsupported"})
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`agentcapsule_llm_audio_seconds_total{provider="openai_compatible"} 288`,
		`agentcapsule_llm_ocr_pages_total{provider="openai_compatible"} 3`,
		`agentcapsule_llm_tokens_total{provider="openai_compatible",direction="input"} 9`,
		`agentcapsule_llm_estimated_cost_micro_total{provider="openai_compatible"} 28800`,
		`agentcapsule_llm_calls_total{provider="openai_compatible",outcome="settled"} 3`,
		`agentcapsule_llm_refusals_total{reason="unsupported"} 1`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Fatal("missing", want, "\n", body)
		}
	}
	if !strings.Contains(logs.String(), `"event":"llm_call_refused","reason":"unsupported"}`) {
		t.Fatal(logs.String())
	}
}
