//go:build linux && cgo

package authorityclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

type spanSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *spanSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// Each call to the authority service is a client span of the trace it runs
// in (OPR-3): its operation and outcome, the service's error code for a
// refusal, and for a hold whether it was granted. The work done under a
// hold is the hold's child. No store, volume or subject reaches a span.
func TestAuthorityCallsAreSpans(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	var sink spanSink
	tracer, err := telemetry.NewTracer(&sink, "agentcapsule-worker", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithTracer(t.Context(), tracer)
	work := telemetry.NewSpanType("test.work", telemetry.SpanInternal, telemetry.SpanAttributes{})
	if _, err = c.Lookup(ctx, "store-planted"); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	b, err := c.Register(ctx, "store-planted", "volume-planted")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.HoldBinding(ctx, b, func(ctx context.Context) error {
		_, span := work.Start(ctx)
		span.End()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tracer.Close()
	out := sink.b.String()
	if strings.Contains(out, "planted") {
		t.Fatal("an identifier reached a span", out)
	}
	for _, want := range []string{`"name":"authority.call","kind":3`,
		`{"key":"agentcapsule.authority.op","value":{"stringValue":"lookup"}},{"key":"agentcapsule.outcome","value":{"stringValue":"stale"}}`,
		`{"key":"agentcapsule.authority.op","value":{"stringValue":"register"}},{"key":"agentcapsule.outcome","value":{"stringValue":"ok"}}`,
		`{"key":"agentcapsule.authority.op","value":{"stringValue":"hold_binding"}},{"key":"agentcapsule.outcome","value":{"stringValue":"ok"}},{"key":"agentcapsule.authority.held","value":{"stringValue":"yes"}}`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in\n%s", want, out)
		}
	}
	// The work under the hold names the hold's span as its parent.
	var hold, child string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var batch struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []struct {
						SpanID       string `json:"spanId"`
						ParentSpanID string `json:"parentSpanId"`
						Name         string `json:"name"`
						Attributes   []struct {
							Value struct {
								StringValue string `json:"stringValue"`
							} `json:"value"`
						} `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(line), &batch); err != nil {
			t.Fatal(err)
		}
		for _, s := range batch.ResourceSpans[0].ScopeSpans[0].Spans {
			if s.Name == "test.work" {
				child = s.ParentSpanID
			}
			if s.Name == "authority.call" && s.Attributes[0].Value.StringValue == "hold_binding" {
				hold = s.SpanID
			}
		}
	}
	if hold == "" || child != hold {
		t.Fatal("the work under the hold is not its child", out)
	}
}
