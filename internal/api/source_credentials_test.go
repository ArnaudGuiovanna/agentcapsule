package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

const apiSourceSecret = "glpat-api-forge-token-0123456789" // gitleaks:allow test fixture, not a credential

// ADR 023 §3.1 over HTTP: the secret goes in and never comes out, neither in
// an answer, a replay, the list nor the trail; a name is the organization's
// once; a disabled credential cannot be rotated.
func TestHTTPSourceCredentialsNeverShowTheirSecret(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	body := `{"name":"school-gitlab","kind":"gitlab","host":"gitlab.example.org","secret":"` + apiSourceSecret + `"}`
	var bodies []string
	r := call(t, l.server, "POST", "/v1/source-credentials", owner, "create", body)
	var v controlplane.SourceCredential
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.Generation != 1 || v.Status != "active" {
		t.Fatal("create", r.Code, r.Body.String())
	}
	bodies = append(bodies, r.Body.String())
	if r = call(t, l.server, "POST", "/v1/source-credentials", owner, "create", body); r.Code != 201 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay", r.Code, r.Header())
	}
	bodies = append(bodies, r.Body.String())
	if r = call(t, l.server, "POST", "/v1/source-credentials", owner, "again", body); r.Code != 409 || problemCode(r) != "source_credential_name_taken" {
		t.Fatal("a second credential of the same name", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/source-credentials", owner, "unknown", strings.Replace(body, `"name"`, `"extra":1,"name"`, 1)); r.Code != 400 {
		t.Fatal("an unknown field", r.Code, r.Body.String())
	}
	r = call(t, l.server, "POST", "/v1/source-credentials/"+v.ID+"/rotate", owner, "rotate", `{"secret":"`+apiSourceSecret+`-2"}`)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"generation":2`) {
		t.Fatal("rotate", r.Code, r.Body.String())
	}
	bodies = append(bodies, r.Body.String())
	if r = call(t, l.server, "POST", "/v1/source-credentials/"+v.ID+"/disable", owner, "disable", `{}`); r.Code != 200 || !strings.Contains(r.Body.String(), `"status":"disabled"`) {
		t.Fatal("disable", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/source-credentials/"+v.ID+"/rotate", owner, "rotate-disabled", `{"secret":"x`+apiSourceSecret+`"}`); r.Code != 409 || problemCode(r) != "invalid_transition" {
		t.Fatal("a disabled credential was rotated", r.Code, r.Body.String())
	}
	for _, path := range []string{"/v1/source-credentials", "/v1/audit?limit=200"} {
		r = call(t, l.server, "GET", path, owner, "", "")
		if r.Code != 200 {
			t.Fatal(path, r.Code, r.Body.String())
		}
		bodies = append(bodies, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), "source_credential.disabled") || !strings.Contains(r.Body.String(), `"target":"`+v.ID+`"`) {
		t.Fatal("the trail lacks the credential's events", r.Body.String())
	}
	for _, b := range bodies {
		if strings.Contains(b, apiSourceSecret) || strings.Contains(b, "sealed") {
			t.Fatal("an answer carries the secret:", b)
		}
	}
}
