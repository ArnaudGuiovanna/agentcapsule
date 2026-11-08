package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

const allAgentScopes = allTeamScopes + " agent:read agent:create agent:assign agent:operate agent:delete identity:manage audit:read agent:invoke agent:content:read provider:manage quota:manage usage:read"

func apiAgentsLab(t *testing.T) (*apiDelegationFixture, time.Time, string) {
	t.Helper()
	l := apiDelegationLab(t)
	l.trust.AllowedScopes = strings.Fields(allAgentScopes)
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.verifier = v
	l.server.SetDelegatedIdentityVerifier(v)
	r, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "agents-install", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, r.MinimumIAT)
	if err = l.store.ConfigureHostStorage(t.Context(), "local", 4096); err != nil {
		t.Fatal(err)
	}
	if _, err = l.store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	return l, r.MinimumIAT, l.sign(t, r.MinimumIAT, "owner", "alice", allAgentScopes)
}

func apiTenantAgent(t *testing.T, l *apiDelegationFixture, token, name string) string {
	t.Helper()
	body := `{"name":"` + name + `","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`
	r := call(t, l.server, "POST", "/v1/agents", token, "create-"+name, body)
	var out controlplane.AgentCreation
	if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &out) != nil {
		t.Fatal("create tenant agent", r.Code, r.Body.String())
	}
	return out.AgentID
}

func apiAgentIDs(t *testing.T, l *apiDelegationFixture, token string) []string {
	t.Helper()
	r := call(t, l.server, "GET", "/v1/agents", token, "", "")
	var out struct {
		Items []controlplane.TenantAgent `json:"items"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil {
		t.Fatal("list agents", r.Code, r.Body.String())
	}
	ids := []string{}
	for _, a := range out.Items {
		ids = append(ids, a.ID)
	}
	return ids
}

func TestHTTPTenantAgentsAssignmentsAndOffboarding(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	one := apiTenantAgent(t, l, owner, "alpha")
	two := apiTenantAgent(t, l, owner, "beta")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	member := l.sign(t, at, "bob-read", "bob", "org:read agent:read")

	if got := apiAgentIDs(t, l, member); len(got) != 0 {
		t.Fatal("unassigned member lists agents", got)
	}
	if r := call(t, l.server, "GET", "/v1/agents/"+one, member, "", ""); r.Code != 404 {
		t.Fatal("unassigned member can tell the agent exists", r.Code)
	}
	if got := apiAgentIDs(t, l, owner); len(got) != 2 {
		t.Fatal("owner does not see the tenant's agents", got)
	}

	// Only the assignment makes the agent visible to the member.
	body := `{"principal_id":"` + bob.PrincipalID + `","permissions":["read_metadata","invoke"]}`
	r := call(t, l.server, "POST", "/v1/agents/"+one+"/assignments", owner, "assign-bob", body)
	var assignment controlplane.AgentAssignment
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &assignment) != nil {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/agents/"+one+"/assignments", owner, "assign-bob-2", body); r.Code != 409 {
		t.Fatal("duplicate assignment", r.Code)
	}
	if got := apiAgentIDs(t, l, member); len(got) != 1 || got[0] != one {
		t.Fatal("assigned member does not see exactly its agent", got)
	}
	if r = call(t, l.server, "GET", "/v1/agents/"+two, member, "", ""); r.Code != 404 {
		t.Fatal("assignment on one agent exposed another", r.Code)
	}
	// A plain member cannot create agents or assignments, whatever scopes it holds.
	allScopes := l.sign(t, at, "bob-all", "bob", allAgentScopes)
	if r = call(t, l.server, "POST", "/v1/agents/"+one+"/assignments", allScopes, "self", `{"principal_id":"`+bob.PrincipalID+`","permissions":["read_content"]}`); r.Code != 403 {
		t.Fatal("member granted itself content access", r.Code)
	}
	// The legacy domain neither lists nor reads a tenant agent.
	if r = call(t, l.server, "GET", "/v1/agents/"+one, l.legacy, "", ""); r.Code != 404 {
		t.Fatal("legacy service reads a tenant agent", r.Code)
	}

	// Offboarding the member: access ends, the organization's agents remain.
	if r = call(t, l.server, "POST", "/v1/members/"+bob.PrincipalID+"/revoke", owner, "revoke-bob", `{}`); r.Code != 200 {
		t.Fatal("revoke member", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", "/v1/agents", member, "", ""); r.Code != 401 {
		t.Fatal("revoked member still reads", r.Code)
	}
	if got := apiAgentIDs(t, l, owner); len(got) != 2 {
		t.Fatal("offboarding removed an organization agent", got)
	}
	if r = call(t, l.server, "POST", "/v1/agents/"+one+"/assignments/"+assignment.ID+"/revoke", owner, "revoke-assignment", `{}`); r.Code != 200 {
		t.Fatal("revoke assignment", r.Code, r.Body.String())
	}
	list := call(t, l.server, "GET", "/v1/agents/"+one+"/assignments", owner, "", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"status":"revoked"`) {
		t.Fatal("assignment listing", list.Code, list.Body.String())
	}
}

func TestHTTPServiceAccountsEndToEnd(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	r := call(t, l.server, "POST", "/v1/service-accounts", owner, "svc", `{"name":"ci bot","role":"agent_operator"}`)
	var account controlplane.ServiceAccount
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &account) != nil {
		t.Fatal("create service account", r.Code, r.Body.String())
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	issue := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, "tok", `{"scopes":["org:read","agent:read","agent:create"],"expires_at":"`+exp+`"}`)
	var token controlplane.IssuedServiceToken
	if issue.Code != 201 || json.Unmarshal(issue.Body.Bytes(), &token) != nil || !strings.HasPrefix(token.Token, "acps_") {
		t.Fatal("issue token", issue.Code, issue.Body.String())
	}
	// The listing never returns the secret again.
	list := call(t, l.server, "GET", "/v1/service-accounts/"+account.ID+"/tokens", owner, "", "")
	if list.Code != 200 || strings.Contains(list.Body.String(), token.Token) || strings.Contains(list.Body.String(), `"token"`) {
		t.Fatal("token listing exposes the secret", list.Code)
	}
	// The integrator uses its own credential on tenant routes.
	if id := apiTenantAgent(t, l, token.Token, "from-ci"); id == "" {
		t.Fatal("no agent created")
	}
	if got := apiAgentIDs(t, l, token.Token); len(got) != 1 {
		t.Fatal("technical account does not list the agent it created", got)
	}
	if r = call(t, l.server, "POST", "/v1/service-accounts", token.Token, "child", `{"name":"x","role":"agent_user"}`); r.Code != 403 {
		t.Fatal("technical account created an account", r.Code)
	}
	// Revocation takes effect on the next request; the agent stays.
	if r = call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens/"+token.ID+"/revoke", owner, "rev", `{}`); r.Code != 200 {
		t.Fatal("revoke", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", "/v1/agents", token.Token, "", ""); r.Code != 401 {
		t.Fatal("revoked token still accepted", r.Code)
	}
	if got := apiAgentIDs(t, l, owner); len(got) != 1 {
		t.Fatal("revoking the credential removed the agent", got)
	}
	// An ordinary member cannot manage identities.
	apiAddMember(t, l, owner, "plain", "agent_user")
	plain := l.sign(t, at, "plain-all", "plain", allAgentScopes)
	if r = call(t, l.server, "POST", "/v1/service-accounts", plain, "nope", `{"name":"x","role":"agent_user"}`); r.Code != 403 {
		t.Fatal("agent_user created a technical account", r.Code)
	}
	// The legacy domain does not accept an acps_ token and vice versa.
	if r = call(t, l.server, "GET", "/v1/me", token.Token, "", ""); r.Code == 200 {
		t.Fatal("technical account token opened the legacy owner domain")
	}
}

func TestHTTPAuditFeed(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	apiTenantAgent(t, l, owner, "traced")
	first := call(t, l.server, "GET", "/v1/audit?limit=1", owner, "", "")
	var page controlplane.AuditPage
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Next == "" {
		t.Fatal("first audit page", first.Code, first.Body.String())
	}
	second := call(t, l.server, "GET", "/v1/audit?limit=1&after="+page.Next, owner, "", "")
	var next controlplane.AuditPage
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &next) != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID {
		t.Fatal("second audit page", second.Code, second.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/audit?after=%21%21", owner, "", ""); r.Code != 400 {
		t.Fatal("garbage cursor", r.Code)
	}
	apiAddMember(t, l, owner, "viewer", "agent_user")
	if r := call(t, l.server, "GET", "/v1/audit", l.sign(t, at, "viewer-audit", "viewer", allAgentScopes), "", ""); r.Code != 403 {
		t.Fatal("agent_user read the audit trail", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/audit", l.legacy, "", ""); r.Code != 403 {
		t.Fatal("legacy credential read a tenant audit trail", r.Code)
	}
}

const invokeScopes = "org:read agent:read agent:invoke agent:content:read provider:manage quota:manage usage:read"

// apiActiveTenantAgent drives a tenant reservation to LIVE with the same explicit
// SQL fixture the owner-domain HTTP tests use; no physical VM is asserted.
func apiActiveTenantAgent(t *testing.T, l *apiDelegationFixture, owner, name string) string {
	t.Helper()
	id := apiTenantAgent(t, l, owner, name)
	jobs, err := l.store.PendingProvisioning(t.Context(), "local", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID != id {
			continue
		}
		if err = l.store.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
			t.Fatal(err)
		}
		p, err := l.store.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		vm := "0123456789abcdef"
		if err = l.store.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", p.Generation, vm); err != nil {
			t.Fatal(err)
		}
		if err = l.store.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: vm}); err != nil {
			t.Fatal(err)
		}
		if err = l.store.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
			t.Fatal(err)
		}
		if err = l.store.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, true); err != nil {
			t.Fatal(err)
		}
		if err = l.store.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		return id
	}
	t.Fatal("reservation not discoverable")
	return ""
}

func TestHTTPTenantInvocationIsGovernedByAssignments(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(l.store, l.server.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDelegatedIdentityVerifier(l.verifier)
	l.server = server
	agent := apiActiveTenantAgent(t, l, owner, "answering")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	carol := apiAddMember(t, l, owner, "carol", "agent_user")
	bobToken := l.sign(t, at, "bob-invoke", "bob", invokeScopes)
	carolToken := l.sign(t, at, "carol-invoke", "carol", invokeScopes)
	path, input := "/v1/agents/"+agent+"/messages", `{"content":[{"type":"text","text":"hello"}]}`

	if r := call(t, l.server, "POST", path, carolToken, "k", input); r.Code != 404 {
		t.Fatal("unassigned member reached the agent", r.Code)
	}
	if r := call(t, l.server, "POST", path, owner, "k", input); r.Code != 403 {
		t.Fatal("an owner invoked without an assignment", r.Code)
	}
	assignment := `{"principal_id":"` + bob.PrincipalID + `","permissions":["read_metadata","invoke"]}`
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg", assignment); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	accepted := call(t, l.server, "POST", path, bobToken, "k", input)
	var op controlplane.AgentCreation
	if accepted.Code != 202 || json.Unmarshal(accepted.Body.Bytes(), &op) != nil || accepted.Header().Get("Retry-After") == "" {
		t.Fatal("assigned member could not invoke", accepted.Code, accepted.Body.String())
	}
	if r := call(t, l.server, "POST", path, bobToken, "k", input); r.Code != 202 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("invocation replay", r.Code)
	}
	// The requester follows its operation; another member cannot.
	if r := call(t, l.server, "GET", "/v1/operations/"+op.OperationID, bobToken, "", ""); r.Code != 200 {
		t.Fatal("requester cannot follow its operation", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/operations/"+op.OperationID, carolToken, "", ""); r.Code != 404 {
		t.Fatal("operation visible to someone who did not ask", r.Code)
	}
	// No result exists yet, and it is never an administrator's to read.
	if r := call(t, l.server, "GET", "/v1/operations/"+op.OperationID+"/result", bobToken, "", ""); r.Code != 404 {
		t.Fatal("result before completion", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/operations/"+op.OperationID+"/result", owner, "", ""); r.Code == 200 {
		t.Fatal("an administrator read a private result")
	}
	_ = carol

	// The structured resource: same admission, its own idempotency scope.
	res := "/v1/agents/" + agent + "/invocations"
	if r := call(t, l.server, "POST", res, carolToken, "r1", input); r.Code != 404 {
		t.Fatal("unassigned member created an invocation", r.Code)
	}
	if r := call(t, l.server, "POST", res, owner, "r1", input); r.Code != 403 {
		t.Fatal("an owner created an invocation without an assignment", r.Code)
	}
	made := call(t, l.server, "POST", res, bobToken, "r1", input)
	var inv controlplane.Invocation
	if made.Code != 202 || json.Unmarshal(made.Body.Bytes(), &inv) != nil || inv.State != "accepted" || inv.ID == "" {
		t.Fatal("invocation not accepted", made.Code, made.Body.String())
	}
	if r := call(t, l.server, "POST", res, bobToken, "r1", input); r.Code != 202 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("invocation replay", r.Code)
	}
	for _, bad := range []string{`{"content":[{"type":"text","text":"x"}],"work_timeout_seconds":30}`, `{"content":[{"type":"text","text":"x"}],"work_timeout_seconds":90000}`} {
		if r := call(t, l.server, "POST", res, bobToken, "wt-"+bad[len(bad)-6:], bad); r.Code != 400 {
			t.Fatal("work timeout out of range accepted", r.Code)
		}
	}
	if strings.Contains(made.Body.String(), "result_due_at") {
		t.Fatal("a fresh invocation already has a result deadline")
	}
	if r := call(t, l.server, "GET", "/v1/invocations/"+inv.ID, bobToken, "", ""); r.Code != 200 {
		t.Fatal("requester cannot follow its invocation", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/invocations/"+inv.ID, carolToken, "", ""); r.Code != 404 {
		t.Fatal("invocation visible to someone who did not ask", r.Code)
	}
	list := call(t, l.server, "GET", res+"?limit=1", bobToken, "", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), inv.ID) || strings.Contains(list.Body.String(), "hello") {
		t.Fatal("invocation list", list.Code, list.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/invocations/"+inv.ID+"/result", owner, "", ""); r.Code == 200 {
		t.Fatal("an administrator read a private result")
	}

	// Queue limits: administrators set them, a full queue answers 429 with a
	// Retry-After, and the view carries counts only.
	if r := call(t, l.server, "POST", "/v1/queue/limits", bobToken, "ql0", `{"max_pending_per_agent":1,"max_pending_tenant":1}`); r.Code != 403 {
		t.Fatal("a member set queue limits", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "ql1", `{"max_pending_per_agent":2,"max_pending_tenant":1}`); r.Code != 400 {
		t.Fatal("inconsistent limits accepted", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "ql2", `{"max_pending_per_agent":1,"max_pending_tenant":1}`); r.Code != 200 {
		t.Fatal("set limits", r.Code, r.Body.String())
	}
	full := call(t, l.server, "POST", res, bobToken, "r2", `{"content":[{"type":"text","text":"more"}],"ttl_seconds":60}`)
	if full.Code != 429 || full.Header().Get("Retry-After") == "" {
		t.Fatal("a full queue was not refused with 429", full.Code, full.Body.String())
	}
	view := call(t, l.server, "GET", "/v1/queue", owner, "", "")
	if view.Code != 200 || !strings.Contains(view.Body.String(), `"max_pending_per_agent":1`) || strings.Contains(view.Body.String(), "hello") {
		t.Fatal("queue view", view.Code, view.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/queue", bobToken, "", ""); r.Code != 403 {
		t.Fatal("a member read the queue view", r.Code)
	}
	if r := call(t, l.server, "GET", res+"?state=expired", bobToken, "", ""); r.Code != 200 {
		t.Fatal("state filter", r.Code)
	}
	if r := call(t, l.server, "GET", res+"?state=bogus", bobToken, "", ""); r.Code != 400 {
		t.Fatal("bad state filter accepted", r.Code)
	}

	// Scheduling: a future run_at is accepted and cancellable by its requester only.
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "ql3", `{"max_pending_per_agent":50,"max_pending_tenant":50}`); r.Code != 200 {
		t.Fatal("raise limits", r.Code)
	}
	dueAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if r := call(t, l.server, "POST", res, bobToken, "sch0", `{"content":[{"type":"text","text":"x"}],"run_at":"2001-01-01T00:00:00Z"}`); r.Code != 400 {
		t.Fatal("a past run_at was accepted", r.Code)
	}
	sch := call(t, l.server, "POST", res, bobToken, "sch1", `{"content":[{"type":"text","text":"later"}],"run_at":"`+dueAt+`"}`)
	var scheduled controlplane.Invocation
	if sch.Code != 202 || json.Unmarshal(sch.Body.Bytes(), &scheduled) != nil || scheduled.State != "scheduled" || scheduled.RunAt == nil {
		t.Fatal("not scheduled", sch.Code, sch.Body.String())
	}
	if r := call(t, l.server, "POST", "/v1/invocations/"+scheduled.ID+"/cancel", carolToken, "c0", ""); r.Code != 404 {
		t.Fatal("a stranger cancelled it", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/invocations/"+scheduled.ID+"/cancel", bobToken, "c1", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"canceled"`) {
		t.Fatal("requester could not cancel", r.Code, r.Body.String())
	}
	if r := call(t, l.server, "GET", res+"?state=canceled", bobToken, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), scheduled.ID) {
		t.Fatal("canceled filter", r.Code)
	}

	// Idle policy: operators set it; bounds are enforced; the view shows it.
	policy := "/v1/agents/" + agent + "/idle-policy"
	if r := call(t, l.server, "POST", policy, bobToken, "ip0", `{"idle_timeout_seconds":300}`); r.Code != 403 && r.Code != 404 {
		t.Fatal("a member set an idle policy", r.Code)
	}
	if r := call(t, l.server, "POST", policy, owner, "ip1", `{"idle_timeout_seconds":5}`); r.Code != 400 {
		t.Fatal("tiny idle timeout accepted", r.Code)
	}
	if r := call(t, l.server, "POST", policy, owner, "ip2", `{}`); r.Code != 400 {
		t.Fatal("missing idle timeout accepted", r.Code)
	}
	if r := call(t, l.server, "POST", policy, owner, "ip3", `{"idle_timeout_seconds":300}`); r.Code != 200 {
		t.Fatal("set idle policy", r.Code, r.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/agents/"+agent, owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"idle_timeout_seconds":300`) {
		t.Fatal("idle policy not shown", r.Code, r.Body.String())
	}

	// Attachments: the raw body is the file, its metadata travels in headers, and
	// responses never echo content.
	upload := func(token, key, name, media, body string, extra map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/agents/"+agent+"/attachments", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", key)
		if media != "" {
			r.Header.Set("Content-Type", media)
		}
		if name != "" {
			r.Header.Set("X-Attachment-Name", name)
		}
		for k, v := range extra {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		l.server.ServeHTTP(w, r)
		return w
	}
	for name, c := range map[string]struct {
		token, name, media, body string
		extra                    map[string]string
		code                     int
	}{
		"stranger":  {carolToken, "a.txt", "text/plain", "hello", nil, 404},
		"no type":   {bobToken, "a.txt", "", "hello", nil, 415},
		"bad type":  {bobToken, "a.txt", "nonsense", "hello", nil, 415},
		"no name":   {bobToken, "", "text/plain", "hello", nil, 400},
		"bad name":  {bobToken, "..%2Fx", "text/plain", "hello", nil, 400},
		"digest":    {bobToken, "a.txt", "text/plain", "hello", map[string]string{"X-Content-SHA256": strings.Repeat("0", 64)}, 400},
		"too large": {bobToken, "a.txt", "text/plain", strings.Repeat("x", capsuleprotocol.MaxAttachmentBytes+1), nil, 413},
	} {
		if r := upload(c.token, "bad-"+name, c.name, c.media, c.body, c.extra); r.Code != c.code {
			t.Fatal(name, r.Code, r.Body.String())
		}
	}
	sum := sha256.Sum256([]byte("hello"))
	up := upload(bobToken, "f1", "r%C3%A9sum%C3%A9.txt", "text/plain; charset=utf-8", "hello", map[string]string{"X-Content-SHA256": hex.EncodeToString(sum[:])})
	var file controlplane.Attachment
	if up.Code != 201 || json.Unmarshal(up.Body.Bytes(), &file) != nil || file.Name != "résumé.txt" || file.MediaType != "text/plain" || file.State != "pending" || strings.Contains(up.Body.String(), "hello") {
		t.Fatal("upload", up.Code, up.Body.String())
	}
	if r := upload(bobToken, "f1", "r%C3%A9sum%C3%A9.txt", "text/plain", "hello", nil); r.Code != 201 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("upload replay", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/attachments/"+file.ID, bobToken, "", ""); r.Code != 200 || strings.Contains(r.Body.String(), "hello") {
		t.Fatal("uploader metadata", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/attachments/"+file.ID, carolToken, "", ""); r.Code != 404 {
		t.Fatal("a stranger saw the file", r.Code)
	}
	sent := call(t, l.server, "POST", res, bobToken, "fa1", `{"content":[{"type":"text","text":"read it"}],"attachments":["`+file.ID+`"]}`)
	var withFile controlplane.Invocation
	if sent.Code != 202 || json.Unmarshal(sent.Body.Bytes(), &withFile) != nil || len(withFile.Attachments) != 1 || withFile.Attachments[0] != file.ID {
		t.Fatal("invocation with a file", sent.Code, sent.Body.String())
	}
	if r := call(t, l.server, "POST", res, bobToken, "fa2", `{"content":[{"type":"text","text":"again"}],"attachments":["`+file.ID+`"]}`); r.Code != 409 || !strings.Contains(r.Body.String(), "attachment_unavailable") {
		t.Fatal("a used file was sent again", r.Code, r.Body.String())
	}
	if r := call(t, l.server, "DELETE", "/v1/attachments/"+file.ID, bobToken, "fd1", ""); r.Code != 409 {
		t.Fatal("an attached file was deleted", r.Code)
	}
	spare := upload(bobToken, "f2", "spare.txt", "text/plain", "spare", nil)
	var spareFile controlplane.Attachment
	if spare.Code != 201 || json.Unmarshal(spare.Body.Bytes(), &spareFile) != nil {
		t.Fatal("second upload", spare.Code)
	}
	if r := call(t, l.server, "DELETE", "/v1/attachments/"+spareFile.ID, bobToken, "fd2", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"purged"`) {
		t.Fatal("pending file not deleted", r.Code, r.Body.String())
	}
	// The organization's storage quota answers 429.
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "ql4", `{"max_pending_per_agent":50,"max_pending_tenant":50,"max_attachment_bytes":1048576}`); r.Code != 200 {
		t.Fatal("set storage quota", r.Code, r.Body.String())
	}
	if r := upload(bobToken, "f3", "big.bin", "application/octet-stream", strings.Repeat("y", 1<<20), nil); r.Code != 429 || !strings.Contains(r.Body.String(), "attachment_quota_exceeded") {
		t.Fatal("storage quota not enforced", r.Code, r.Body.String())
	}
}
