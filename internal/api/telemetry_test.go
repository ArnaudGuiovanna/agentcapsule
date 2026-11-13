package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every problem code written in the API's sources is in problemCodes, so that
// no request is logged with an "invalid" problem.
func TestEveryProblemCodeIsDeclared(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`problem\(w, [0-9]+, "([a-z_]+)"\)`)
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllStringSubmatch(string(raw), -1) {
			found++
			if !slices.Contains(problemCodes, m[1]) {
				t.Errorf("%s: problem code %q is not in problemCodes", name, m[1])
			}
		}
	}
	if found < 20 {
		t.Fatal("the scan found too few problem codes", found)
	}
}

// Each request is counted by its route pattern, never by the IDs in its path,
// and logged once with the X-Request-ID its response carries. No token, path
// ID or body reaches the metrics or the logs.
func TestHTTPTelemetry(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	id := apiActiveTenantAgent(t, l, owner, "observed")
	registry := telemetry.NewRegistry()
	var events bytes.Buffer
	l.server.EnableTelemetry(registry, &events)

	ok := call(t, l.server, "GET", "/v1/agents/"+id, owner, "", "")
	missing := call(t, l.server, "GET", "/v1/agents/agt_does_not_exist", owner, "", "")
	stranger := l.sign(t, at, "nobody-jti", "nobody", allAgentScopes)
	refused := call(t, l.server, "PUT", "/v1/agents/"+id+"/inbound", stranger, "k", `{"mode":"auto","secret":"my vault code is 4417"}`)
	unclean := call(t, l.server, "GET", "/v1/agents/../queue", owner, "", "")
	if ok.Code != 200 || missing.Code != 404 || refused.Code/100 != 4 || unclean.Code != 400 {
		t.Fatal(ok.Code, missing.Code, refused.Code, unclean.Code)
	}

	var exposition bytes.Buffer
	if _, err := registry.WriteTo(&exposition); err != nil {
		t.Fatal(err)
	}
	metrics := exposition.String()
	for _, want := range []string{
		`agentcapsule_api_requests_total{route="/v1/agents/{id}",method="GET",status_class="2xx"} 1`,
		`agentcapsule_api_requests_total{route="/v1/agents/{id}",method="GET",status_class="4xx"} 1`,
		`agentcapsule_api_requests_total{route="/v1/agents/{id}/inbound",method="PUT",status_class="4xx"} 1`,
		`agentcapsule_api_requests_total{route="invalid_path",method="GET",status_class="4xx"} 1`,
		`agentcapsule_api_request_duration_seconds_count{route="/v1/agents/{id}"} 2`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %s in\n%s", want, metrics)
		}
	}
	lines := strings.Split(strings.TrimSpace(events.String()), "\n")
	if len(lines) != 4 {
		t.Fatal("one event per request", len(lines), events.String())
	}
	for i, w := range []struct {
		requestID, route, problem string
		status                    int
	}{
		{ok.Header().Get("X-Request-ID"), "/v1/agents/{id}", "", 200},
		{missing.Header().Get("X-Request-ID"), "/v1/agents/{id}", "not_found", 404},
		{refused.Header().Get("X-Request-ID"), "/v1/agents/{id}/inbound", "", refused.Code},
		{unclean.Header().Get("X-Request-ID"), "invalid_path", "invalid_path", 400},
	} {
		var e map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &e); err != nil {
			t.Fatal(err, lines[i])
		}
		if e["event"] != "http_request" || e["request_id"] != w.requestID || e["route"] != w.route || int(e["status"].(float64)) != w.status {
			t.Fatal("event", i, lines[i])
		}
		if w.problem != "" && e["problem"] != w.problem {
			t.Fatal("problem", i, lines[i])
		}
		if _, ok := e["duration"].(float64); !ok {
			t.Fatal("duration", lines[i])
		}
	}
	out := metrics + events.String()
	for _, secret := range []string{owner, stranger, id, "agt_does_not_exist", "4417", "nobody"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%.12s… reached the telemetry", secret)
		}
	}
}

// The operation a request creates records the request's X-Request-ID, which
// the worker's job events repeat (OPS-02).
func TestHTTPOperationsRecordTheirRequestID(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	body := `{"name":"traced","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`
	r := call(t, l.server, "POST", "/v1/agents", owner, "create-traced", body)
	var out controlplane.AgentCreation
	if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &out) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	db, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var recorded string
	if err = db.QueryRow(t.Context(), "SELECT request_id FROM platform_operations WHERE id=$1", out.OperationID).Scan(&recorded); err != nil || recorded != r.Header().Get("X-Request-ID") {
		t.Fatal("the operation did not record the request's ID", recorded, err)
	}
	// A replay answers from the receipt: the operation keeps its first request.
	again := call(t, l.server, "POST", "/v1/agents", owner, "create-traced", body)
	if err = db.QueryRow(t.Context(), "SELECT request_id FROM platform_operations WHERE id=$1", out.OperationID).Scan(&recorded); err != nil ||
		recorded != r.Header().Get("X-Request-ID") || recorded == again.Header().Get("X-Request-ID") {
		t.Fatal("a replay changed the operation's request ID", err)
	}
}
