package api

import (
	"encoding/json"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

type quotaProblemBody struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Quota  string `json:"quota"`
}

// TEN-007 over HTTP (ADR 021): the platform operator sets an organization's
// quotas; a creation past one answers 409 organization_quota_exceeded naming
// it, and that refused attempt joins the organization's trail; a quota an
// agent alone could never fit answers 409 quota_below_agent.
func TestHTTPOrganizationQuotas(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	apiTenantAgent(t, l, owner, "support")
	path := "/v1/organizations/" + l.org.ID + "/quotas"
	problemOf := func(t *testing.T, code int, body []byte) quotaProblemBody {
		t.Helper()
		var p quotaProblemBody
		if err := json.Unmarshal(body, &p); err != nil || p.Status != code {
			t.Fatal("problem", code, string(body))
		}
		return p
	}

	if r := call(t, l.server, "PUT", path, l.platform, "below", `{"max_memory_mib":128}`); r.Code != 409 ||
		problemOf(t, 409, r.Body.Bytes()) != (quotaProblemBody{409, "quota_below_agent", "max_memory_mib"}) {
		t.Fatal("a quota an agent cannot fit", r.Code, r.Body.String())
	}
	for _, bad := range []string{`{"max_agents":0}`, `{"max_storage_mib":63}`, `{"max_agents":1,"tenant_id":"x"}`} {
		if r := call(t, l.server, "PUT", path, l.platform, "bad", bad); r.Code != 400 {
			t.Fatal("an invalid quota", bad, r.Code)
		}
	}
	set := call(t, l.server, "PUT", path, l.platform, "set", `{"max_agents":1,"max_active_vms":2}`)
	var q controlplane.OrganizationQuotas
	if set.Code != 200 || json.Unmarshal(set.Body.Bytes(), &q) != nil || q.MaxAgents == nil || *q.MaxAgents != 1 || q.MaxStorageMiB != nil {
		t.Fatal("set", set.Code, set.Body.String())
	}
	if r := call(t, l.server, "PUT", path, l.platform, "set", `{"max_agents":1,"max_active_vms":2}`); r.Code != 200 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay", r.Code)
	}
	if r := call(t, l.server, "PUT", path, l.platform, "set", `{"max_agents":2}`); r.Code != 422 {
		t.Fatal("a key reused with other quotas", r.Code)
	}
	if r := call(t, l.server, "PUT", path, owner, "owner", `{"max_agents":100}`); r.Code != 403 {
		t.Fatal("an organization raised its own quota", r.Code)
	}

	body := `{"name":"second","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":64}}`
	r := call(t, l.server, "POST", "/v1/agents", owner, "second", body)
	if r.Code != 409 || r.Header().Get("Content-Type") != "application/problem+json" ||
		problemOf(t, 409, r.Body.Bytes()) != (quotaProblemBody{409, "organization_quota_exceeded", "max_agents"}) {
		t.Fatal("a creation past the agents quota", r.Code, r.Body.String())
	}

	for token, want := range map[string]string{l.platform: path, owner: "/v1/organizations/current/quotas"} {
		r := call(t, l.server, "GET", want, token, "", "")
		var st controlplane.OrganizationQuotaStatus
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &st) != nil || st.OrganizationID != l.org.ID ||
			st.Usage.Agents != 1 || st.Usage.StorageMiB != 128 || st.Limits.MaxActiveVMs == nil || st.UpdatedAt == nil {
			t.Fatal("quotas read", want, r.Code, r.Body.String())
		}
	}

	// The change and the refused creation are in the organization's trail.
	page := call(t, l.server, "GET", "/v1/audit?limit=200", owner, "", "")
	var trail controlplane.AuditPage
	if page.Code != 200 || json.Unmarshal(page.Body.Bytes(), &trail) != nil {
		t.Fatal("trail", page.Code)
	}
	var changed, refused int
	for _, e := range trail.Items {
		if e.Action == "organization.quotas_set" && e.Outcome == "done" {
			changed++
		}
		if e.Action == "agent.created" && e.Outcome == "refused" && e.Reason == "organization_quota_exceeded" {
			refused++
		}
	}
	if changed != 1 || refused != 1 {
		t.Fatal("trail", changed, refused)
	}
}
