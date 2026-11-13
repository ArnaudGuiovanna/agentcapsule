package telemetry

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func exposition(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestTheExpositionFollowsThePrometheusTextFormat(t *testing.T) {
	r := NewRegistry()
	routes := Label{"route", []string{"/v1/agents/{id}", "/v1/queue"}}
	requests := r.Counter("agentcapsule_api_requests_total", "HTTP requests.", routes, Label{"status_class", []string{"2xx", "4xx"}})
	requests.Inc("/v1/agents/{id}", "2xx")
	requests.Add(2, "/v1/agents/{id}", "2xx")
	requests.Inc("/v1/queue", "4xx")
	r.Gauge("agentcapsule_worker_vms_running", "Running VMs.").Set(3)
	latency := r.Histogram("agentcapsule_api_request_duration_seconds", "Latency.", []float64{0.1, 1}, routes)
	latency.Observe(0.05, "/v1/queue")
	latency.Observe(0.5, "/v1/queue")
	latency.Observe(5, "/v1/queue")
	got := exposition(t, r)
	for _, want := range []string{
		"# HELP agentcapsule_api_requests_total HTTP requests.\n# TYPE agentcapsule_api_requests_total counter\n",
		`agentcapsule_api_requests_total{route="/v1/agents/{id}",status_class="2xx"} 3` + "\n",
		`agentcapsule_api_requests_total{route="/v1/queue",status_class="4xx"} 1` + "\n",
		"# TYPE agentcapsule_worker_vms_running gauge\nagentcapsule_worker_vms_running 3\n",
		`agentcapsule_api_request_duration_seconds_bucket{route="/v1/queue",le="0.1"} 1` + "\n",
		`agentcapsule_api_request_duration_seconds_bucket{route="/v1/queue",le="1"} 2` + "\n",
		`agentcapsule_api_request_duration_seconds_bucket{route="/v1/queue",le="+Inf"} 3` + "\n",
		`agentcapsule_api_request_duration_seconds_sum{route="/v1/queue"} 5.55` + "\n",
		`agentcapsule_api_request_duration_seconds_count{route="/v1/queue"} 3` + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	// Families are sorted by name, so scrapes compare line by line.
	if strings.Index(got, "agentcapsule_api_request_duration_seconds") > strings.Index(got, "agentcapsule_api_requests_total") {
		t.Fatal("families are not sorted")
	}
	requests.Add(-1, "/v1/queue", "4xx")
	if !strings.Contains(exposition(t, r), `status_class="4xx"} 1`+"\n") {
		t.Fatal("a counter went down")
	}
}

// Nothing outside the declared values reaches a metric or a log line: a token
// (made of ordinary characters), a sentence or an injection attempt becomes
// "other" or "invalid".
func TestFreeTextNeverReachesMetricsOrLogs(t *testing.T) {
	secrets := []string{"Bearer eyJhbGciOiJFZERTQSJ9.payload.sig", "sk-proj-abcdef123456", "skprojabcdef123456", "agt_0123456789abcdef",
		"my vault code is 4417", `"},{"injected":"x`, "line\nbreak", strings.Repeat("a", 129), ""}
	r := NewRegistry()
	c := r.Counter("agentcapsule_test_total", "Test.", Label{"outcome", []string{"done", "retried"}})
	var logs bytes.Buffer
	l := NewLogger(&logs, map[string][]string{"event": {"test_event"}, "outcome": {"done"}, "route": {"/v1/agents/{id}/invocations"}})
	for _, s := range secrets {
		c.Inc(s)
		l.Event("test_event", Code("outcome", s), RequestID(s))
		l.Event(s)
	}
	l.Event("test_event", Code("route", "/v1/agents/{id}/invocations"), Int("status", 202), Seconds("duration", 1500*time.Millisecond),
		RequestID("0123456789abcdef0123456789abcdef"))
	out := exposition(t, r) + logs.String()
	for _, s := range secrets[:len(secrets)-1] {
		if strings.Contains(out, s) {
			t.Fatalf("%q reached the output:\n%s", s, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.HasPrefix(line, `{"time":"`) || !strings.HasSuffix(line, "}") {
			t.Fatal("not one JSON object per line", line)
		}
	}
	if !strings.Contains(logs.String(), `"event":"test_event","route":"/v1/agents/{id}/invocations","status":202,"duration":1.500000,"request_id":"0123456789abcdef0123456789abcdef"}`) {
		t.Fatal("fields", logs.String())
	}
	if !strings.Contains(out, `agentcapsule_test_total{outcome="other"} `+strconv.Itoa(len(secrets))) {
		t.Fatal("invalid values are not grouped", out)
	}
}

func TestTheNumberOfSeriesIsBounded(t *testing.T) {
	r := NewRegistry()
	values := make([]string, maxSeries+10)
	for i := range values {
		values[i] = "k" + strconv.Itoa(i)
	}
	c := r.Counter("agentcapsule_test_total", "Test.", Label{"kind", values})
	for _, v := range values {
		c.Inc(v)
	}
	got := exposition(t, r)
	if n := strings.Count(got, "agentcapsule_test_total{"); n != maxSeries {
		t.Fatal("series", n)
	}
	if !strings.Contains(got, "agentcapsule_telemetry_series_dropped_total 10") {
		t.Fatal("dropped samples are not counted", got)
	}
}

func TestTheHandlerCollectsCurrentValuesFirst(t *testing.T) {
	r := NewRegistry()
	depth := r.Gauge("agentcapsule_worker_jobs_pending", "Pending jobs.", Label{"kind", []string{"delivery"}})
	calls := 0
	r.Collect(func(ctx context.Context) error {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("collection without a deadline")
		}
		depth.Reset()
		depth.Set(float64(calls), "delivery")
		if calls == 2 {
			return errors.New("database unavailable")
		}
		return nil
	})
	h := r.Handler(time.Second)
	for range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
			t.Fatal(rec.Code, rec.Header())
		}
	}
	got := exposition(t, r)
	if !strings.Contains(got, `agentcapsule_worker_jobs_pending{kind="delivery"} 2`) || !strings.Contains(got, "agentcapsule_telemetry_collect_errors_total 1") {
		t.Fatal(got)
	}
	for path, code := range map[string]int{"/": 404, "/metrics/x": 404} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != code {
			t.Fatal(path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != 405 {
		t.Fatal("POST", rec.Code)
	}
}

func TestConcurrentUse(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("agentcapsule_test_total", "Test.", Label{"kind", []string{"a"}})
	h := r.Histogram("agentcapsule_test_seconds", "Test.", []float64{1})
	var logs bytes.Buffer
	l := NewLogger(&logs, map[string][]string{"event": {"tick"}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				c.Inc("a")
				h.Observe(0.5)
				l.Event("tick")
				_ = exposition(t, r)
			}
		}()
	}
	wg.Wait()
	if !strings.Contains(exposition(t, r), `agentcapsule_test_total{kind="a"} 8000`) || strings.Count(logs.String(), "\n") != 8000 {
		t.Fatal("lost updates")
	}
}

func TestRegistrationRejectsBadNames(t *testing.T) {
	for _, fn := range []func(r *Registry){
		func(r *Registry) { r.Counter("Bad-Name", "x") },
		func(r *Registry) { r.Counter("ok_total", "x", Label{"le", []string{"1"}}) },
		func(r *Registry) { r.Counter("ok_total", "x", Label{"kind", nil}) },
		func(r *Registry) { r.Counter("ok_total", "x", Label{"kind", []string{`a"b`}}) },
		func(r *Registry) { r.Counter("ok_total", "x"); r.Counter("ok_total", "x") },
		func(r *Registry) { r.Histogram("ok_seconds", "x", []float64{2, 1}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("accepted")
				}
			}()
			fn(NewRegistry())
		}()
	}
}
