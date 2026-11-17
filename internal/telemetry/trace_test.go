package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// otlpLine mirrors the OTLP/JSON ExportTraceServiceRequest: a field the
// tracer writes outside the protocol fails the decoding.
type otlpLine struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpAttribute `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpAttribute struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string `json:"stringValue,omitempty"`
		IntValue    *string `json:"intValue,omitempty"`
	} `json:"value"`
}

type otlpSpan struct {
	TraceID      string          `json:"traceId"`
	SpanID       string          `json:"spanId"`
	ParentSpanID string          `json:"parentSpanId"`
	Name         string          `json:"name"`
	Kind         int             `json:"kind"`
	Start        string          `json:"startTimeUnixNano"`
	End          string          `json:"endTimeUnixNano"`
	Attributes   []otlpAttribute `json:"attributes"`
	Status       struct {
		Code int `json:"code"`
	} `json:"status"`
	service string
}

func (s otlpSpan) attribute(key string) string {
	for _, a := range s.Attributes {
		if a.Key == key {
			if a.Value.StringValue != nil {
				return *a.Value.StringValue
			}
			if a.Value.IntValue != nil {
				return *a.Value.IntValue
			}
		}
	}
	return ""
}

// decodeSpans reads OTLP/JSON lines strictly.
func decodeSpans(t *testing.T, raw []byte) []otlpSpan {
	t.Helper()
	var out []otlpSpan
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(nil, 16<<20)
	for scanner.Scan() {
		d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		d.DisallowUnknownFields()
		var line otlpLine
		if err := d.Decode(&line); err != nil {
			t.Fatalf("not an OTLP/JSON line: %v\n%s", err, scanner.Bytes())
		}
		for _, r := range line.ResourceSpans {
			if len(r.Resource.Attributes) != 1 || r.Resource.Attributes[0].Key != "service.name" || r.Resource.Attributes[0].Value.StringValue == nil {
				t.Fatal("the resource names its service only", r.Resource.Attributes)
			}
			for _, scope := range r.ScopeSpans {
				if scope.Scope.Name != "agentcapsule" {
					t.Fatal("scope", scope.Scope.Name)
				}
				for _, s := range scope.Spans {
					s.service = *r.Resource.Attributes[0].Value.StringValue
					out = append(out, s)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// syncBuffer is a writer the test reads while the tracer writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.b.Bytes())
}

var testKey = bytes.Repeat([]byte{0x5a}, 32)

const testRequest = "0123456789abcdef0123456789abcdef"

// Spans are OTLP/JSON lines a collector reads: W3C-sized hex IDs, the kind,
// nanosecond times as strings, typed attributes, and the status. A request's
// span is the root of its trace, whose ID is the request ID; the worker joins
// that trace with nothing but the request ID, as a child of the request's
// span.
func TestSpansAreOTLPJSONLinesThatFollowARequest(t *testing.T) {
	var out syncBuffer
	tracer, err := NewTracer(&out, "agentcapsule-api", testKey)
	if err != nil {
		t.Fatal(err)
	}
	request := NewSpanType("api.request", SpanServer, SpanAttributes{Codes: []Label{{"http.route", []string{"/v1/agents/{id}/invocations"}}},
		Ints: []string{"http.response.status_code"}})
	admit := NewSpanType("invocation.admit", SpanInternal, SpanAttributes{IDs: []string{"agentcapsule.agent"}})
	job := NewSpanType("worker.job", SpanConsumer, SpanAttributes{Codes: []Label{{"agentcapsule.job.kind", []string{"delivery"}}}})

	ctx, root := request.StartRequest(context.Background(), tracer, testRequest)
	root.Code("http.route", "/v1/agents/{id}/invocations")
	root.Int("http.response.status_code", 202)
	_, child := admit.Start(ctx)
	child.ID("agentcapsule.agent", "agt_planted")
	child.Fail()
	child.End()
	root.End()
	// Another process, later: only the request ID went through PostgreSQL.
	worker := ContinueTrace(context.Background(), tracer, testRequest)
	wctx, j := job.Start(worker)
	j.Code("agentcapsule.job.kind", "delivery")
	_, nested := admit.Start(wctx)
	nested.End()
	j.End()
	// Work no request started begins its own trace.
	_, alone := job.Start(ContinueTrace(context.Background(), tracer, ""))
	alone.End()
	tracer.Close()

	spans := decodeSpans(t, out.Bytes())
	if len(spans) != 5 {
		t.Fatal("spans written", len(spans))
	}
	byName := map[string][]otlpSpan{}
	for _, s := range spans {
		if len(s.TraceID) != 32 || len(s.SpanID) != 16 || s.service != "agentcapsule-api" || s.Start == "" || s.End < s.Start {
			t.Fatal("span shape", s)
		}
		if _, err := hex.DecodeString(s.TraceID + s.SpanID + s.ParentSpanID); err != nil || strings.ToLower(s.TraceID) != s.TraceID {
			t.Fatal("IDs are lowercase hex", s)
		}
		byName[s.Name] = append(byName[s.Name], s)
	}
	trace, _ := parseTraceID(testRequest)
	rootID := RootSpanID(trace)
	r := byName["api.request"][0]
	if r.TraceID != testRequest || r.SpanID != hex.EncodeToString(rootID[:]) || r.ParentSpanID != "" || r.Kind != int(SpanServer) {
		t.Fatal("the request's span is the root of the request's trace", r)
	}
	if r.attribute("http.route") != "/v1/agents/{id}/invocations" || r.attribute("http.response.status_code") != "202" || r.Status.Code != 0 {
		t.Fatal("request attributes", r)
	}
	a := byName["invocation.admit"]
	if a[0].ParentSpanID != r.SpanID || a[0].TraceID != testRequest || a[0].Status.Code != 2 {
		t.Fatal("a child of the request, failed", a[0])
	}
	if got := a[0].attribute("agentcapsule.agent"); got != Pseudonym(testKey, "agt_planted") || len(got) != PseudonymLength {
		t.Fatal("identifiers are pseudonyms", got)
	}
	var joined, own otlpSpan
	for _, s := range byName["worker.job"] {
		if s.TraceID == testRequest {
			joined = s
		} else {
			own = s
		}
	}
	if joined.ParentSpanID != r.SpanID || joined.Kind != int(SpanConsumer) || joined.attribute("agentcapsule.job.kind") != "delivery" {
		t.Fatal("the worker's job joins the request's trace under its span", joined)
	}
	if a[1].ParentSpanID != joined.SpanID || a[1].TraceID != testRequest {
		t.Fatal("the job's own children", a[1])
	}
	if own.TraceID == "" || own.TraceID == testRequest || own.ParentSpanID != "" {
		t.Fatal("work without a request has its own trace", own)
	}
}

// Nothing but declared codes, numbers and pseudonyms reaches a span: planted
// identifiers and secrets, given as identifiers or as codes, never appear in
// the output, and a code outside its list is "invalid".
func TestNoIdentifierOrContentReachesASpan(t *testing.T) {
	planted := []string{"org_7c1e5d0a9b", "agt_3f9a0c2d71", "mbr_alice@example.org", "Alice Martin", "inv_5e2b1c0d", "acp_secret_token_value",
		"sk-proj-abcdef123456", "my vault code is 4417", `"},{"injected":"x`, "line\nbreak"}
	var out syncBuffer
	tracer, err := NewTracer(&out, "agentcapsule-worker", testKey)
	if err != nil {
		t.Fatal(err)
	}
	typ := NewSpanType("worker.deliver", SpanInternal, SpanAttributes{Codes: []Label{{"agentcapsule.outcome", []string{"delivered", "retried"}}},
		IDs: []string{"agentcapsule.agent"}})
	ctx := WithTracer(context.Background(), tracer)
	for _, p := range planted {
		_, s := typ.Start(ctx)
		s.ID("agentcapsule.agent", p)
		s.Code("agentcapsule.outcome", p)
		s.Code("agentcapsule.undeclared", "delivered")
		s.Int(p, 1)
		s.ID(p, p)
		s.End()
		// Declared keys only: the last attribute an undeclared key set is
		// written under invalid_key.
	}
	tracer.Close()
	raw := out.Bytes()
	for _, p := range planted {
		for _, part := range append(strings.Fields(p), p) {
			if len(part) > 4 && bytes.Contains(raw, []byte(part)) {
				t.Fatalf("%q reached a span", part)
			}
		}
	}
	spans := decodeSpans(t, raw)
	if len(spans) != len(planted) {
		t.Fatal("spans", len(spans))
	}
	for i, s := range spans {
		if s.attribute("agentcapsule.outcome") != Invalid || s.attribute("agentcapsule.undeclared") != "" ||
			s.attribute("agentcapsule.agent") != Pseudonym(testKey, planted[i]) || s.attribute("invalid_key") == "" {
			t.Fatal("attributes", s.Attributes)
		}
	}
	other := Pseudonym(bytes.Repeat([]byte{0x5b}, 32), planted[1])
	if other == Pseudonym(testKey, planted[1]) {
		t.Fatal("another installation's key gives another pseudonym")
	}
	if _, err := NewTracer(&out, "agentcapsule-api", []byte("short")); err == nil {
		t.Fatal("a short key is refused")
	}
	for _, bad := range []func(){
		func() { NewSpanType("Has Space", SpanInternal, SpanAttributes{}) },
		func() {
			NewSpanType("ok.name", SpanInternal, SpanAttributes{Codes: []Label{{"agentcapsule.x", []string{`with"quote`}}}})
		},
		func() { NewSpanType("ok.name", SpanInternal, SpanAttributes{Codes: []Label{{"agentcapsule.x", nil}}}) },
		func() { NewSpanType("ok.name", SpanInternal, SpanAttributes{IDs: []string{"Agent ID"}}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("an invalid declaration is refused")
				}
			}()
			bad()
		}()
	}
}

// blockedWriter never returns until released: a trace file on a stuck disk.
type blockedWriter struct{ release chan struct{} }

func (w blockedWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// The cost of tracing is bounded. Without a tracer a span costs no
// allocation. With one, a stuck writer never blocks the work: spans beyond
// the queue are dropped and counted, so memory stays bounded, and recording
// one stays far below a millisecond.
func TestTracingOverheadIsBounded(t *testing.T) {
	typ := NewSpanType("worker.job", SpanConsumer, SpanAttributes{Codes: []Label{{"agentcapsule.job.kind", []string{"delivery"}}},
		Ints: []string{"agentcapsule.failures"}, IDs: []string{"agentcapsule.agent"}})
	untraced := context.Background()
	if n := testing.AllocsPerRun(1000, func() {
		_, s := typ.Start(untraced)
		s.Code("agentcapsule.job.kind", "delivery")
		s.ID("agentcapsule.agent", "agt_x")
		s.End()
	}); n != 0 {
		t.Fatal("an untraced span allocates", n)
	}

	stuck := blockedWriter{release: make(chan struct{})}
	tracer, err := NewTracer(stuck, "agentcapsule-worker", testKey)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	tracer.Count(registry)
	ctx := WithTracer(context.Background(), tracer)
	const spans = 4 * TraceQueue
	start := time.Now()
	for range spans {
		_, s := typ.Start(ctx)
		s.Code("agentcapsule.job.kind", "delivery")
		s.ID("agentcapsule.agent", "agt_x")
		s.Int("agentcapsule.failures", 2)
		s.End()
	}
	elapsed := time.Since(start)
	// The writer holds at most one batch; the queue holds the rest.
	if d := tracer.Dropped(); d < spans-TraceQueue-traceBatch || d > spans {
		t.Fatal("dropped", d)
	}
	if !strings.Contains(exposition(t, registry), "agentcapsule_telemetry_spans_dropped_total ") {
		t.Fatal("the dropped spans are served")
	}
	// Generous for the race detector on a busy host: a span costs a few
	// microseconds without it.
	if per := elapsed / spans; per > 200*time.Microsecond {
		t.Fatal("recording a span is too slow", per)
	}
	close(stuck.release)
	tracer.Close()
	_, late := typ.Start(ctx)
	late.End()
	if tracer.Dropped() == 0 {
		t.Fatal("a span after Close is dropped")
	}
}
