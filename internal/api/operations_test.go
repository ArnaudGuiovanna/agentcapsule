package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// Under storage pressure (OPS-03) a new agent and an import are refused with
// the typed problem storage_pressure, before anything is reserved.
func TestHTTPStoragePressureIsATypedRefusal(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	if err := l.store.RecordStoragePressure(t.Context(), "local", true, true); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"pressed","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`
	ref := `{"reference":"ghcr.io/acme/echo@sha256:` + strings.Repeat("d", 64) + `"}`
	for _, r := range []struct{ token, path, body string }{{owner, "/v1/agents", body}, {l.platform, "/v1/harness-imports", ref}} {
		got := call(t, l.server, "POST", r.path, r.token, "pressed", r.body)
		if got.Code != 503 || !strings.Contains(got.Body.String(), `"code":"storage_pressure"`) || got.Header().Get("Retry-After") == "" {
			t.Fatal(r.path, got.Code, got.Body.String())
		}
	}
	if err := l.store.RecordStoragePressure(t.Context(), "local", false, false); err != nil {
		t.Fatal(err)
	}
	if r := call(t, l.server, "POST", "/v1/agents", owner, "pressed", body); r.Code != 202 {
		t.Fatal("refused after the pressure ended", r.Code, r.Body.String())
	}
}

// GET /v1/audit/export (TEN-06): the organization's events of a range, as a
// download, with the rights of GET /v1/audit.
func TestHTTPAuditExport(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	agent := apiTenantAgent(t, l, owner, "exported")
	apiAddMember(t, l, owner, "bob", "agent_user")
	from, to := url.QueryEscape(time.Now().Add(-time.Hour).Format(time.RFC3339)), url.QueryEscape(time.Now().Add(time.Hour).Format(time.RFC3339))
	path := "/v1/audit/export?from=" + from + "&to=" + to
	r := call(t, l.server, "GET", path, owner, "", "")
	var export controlplane.AuditExport
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &export) != nil || !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("export", r.Code, r.Body.String())
	}
	found := false
	for _, e := range export.Items {
		found = found || e.Target == agent && e.Action == "agent.created"
	}
	if !found || export.OrganizationID != l.org.ID {
		t.Fatal("export content", export)
	}
	if r = call(t, l.server, "GET", path, l.sign(t, at, "bob-audit", "bob", "audit:read"), "", ""); r.Code != 403 {
		t.Fatal("a member without the auditor role exported", r.Code)
	}
	for _, bad := range []string{"/v1/audit/export", "/v1/audit/export?from=yesterday&to=" + to, "/v1/audit/export?from=" + to + "&to=" + from} {
		if r = call(t, l.server, "GET", bad, owner, "", ""); r.Code != 400 {
			t.Fatal("invalid range", bad, r.Code)
		}
	}
	if r = call(t, l.server, "POST", path, owner, "x", "{}"); r.Code != 405 {
		t.Fatal("method", r.Code)
	}
}
