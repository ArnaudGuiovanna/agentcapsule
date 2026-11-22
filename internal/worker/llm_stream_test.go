//go:build linux

package worker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// A provider stream has its own bounds (ADR 022): up to the first byte and
// between two events, 60 s by default, each settable from 5 s to 290 s in
// the llm section; in total, the platform channel's call bound. A value out
// of bounds stops the worker before it opens anything.
func TestLLMConfigBoundsAProviderStream(t *testing.T) {
	c, err := (&ServiceLLM{}).gatewayConfig(false)
	if err != nil || c.StreamFirstByte != 60*time.Second || c.StreamIdle != 60*time.Second || c.StreamTotal != capsuleprotocol.LLMCallTimeout {
		t.Fatal("defaults", c.StreamFirstByte, c.StreamIdle, c.StreamTotal, err)
	}
	c, err = (&ServiceLLM{StreamFirstByteTimeout: "5s", StreamIdleTimeout: "290s"}).gatewayConfig(false)
	if err != nil || c.StreamFirstByte != 5*time.Second || c.StreamIdle != 290*time.Second {
		t.Fatal("bounds", c.StreamFirstByte, c.StreamIdle, err)
	}
	for _, bad := range []ServiceLLM{{StreamFirstByteTimeout: "4s"}, {StreamFirstByteTimeout: "291s"}, {StreamIdleTimeout: "4.9s"},
		{StreamIdleTimeout: "5m"}, {StreamIdleTimeout: "60"}, {StreamFirstByteTimeout: "-60s"}} {
		if _, err = bad.gatewayConfig(false); err == nil {
			t.Fatal(bad, "accepted")
		}
		bad.ReceiptKey = "/nonexistent/receipt.key"
		if _, err = (ServiceConfig{LLM: &bad}).OpenLLM(nil, true); err == nil || errors.Is(err, llmgateway.ErrAllowlist) {
			t.Fatal(bad, "opened:", err)
		}
	}
	cfg, err := decodeServiceConfig(strings.NewReader(workerBase + `,"llm":{"receipt_key":"/k","stream_first_byte_timeout":"30s","stream_idle_timeout":"45s"}}`))
	if err != nil || cfg.LLM.StreamFirstByteTimeout != "30s" || cfg.LLM.StreamIdleTimeout != "45s" {
		t.Fatal("the llm section's stream keys", err)
	}
}

// The time to a stream's first provider event is a histogram with no label.
func TestTheFirstEventOfAStreamIsTimed(t *testing.T) {
	registry := telemetry.NewRegistry()
	m := NewLLMTelemetry(registry, telemetry.NewLogger(&strings.Builder{}, nil), func(context.Context) (int64, error) { return 0, nil })
	var _ llmservice.StreamObserver = m
	m.ObserveFirstEvent(300 * time.Millisecond)
	m.ObserveFirstEvent(90 * time.Second)
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`agentcapsule_llm_stream_first_event_seconds_bucket{le="0.1"} 0`,
		`agentcapsule_llm_stream_first_event_seconds_bucket{le="0.5"} 1`,
		`agentcapsule_llm_stream_first_event_seconds_bucket{le="60"} 1`,
		`agentcapsule_llm_stream_first_event_seconds_bucket{le="+Inf"} 2`,
		`agentcapsule_llm_stream_first_event_seconds_count 2`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in\n%s", want, body)
		}
	}
}
