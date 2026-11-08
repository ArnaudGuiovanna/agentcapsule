package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

const allTeamScopes = "org:read member:read member:manage team:read team:manage"

func apiTeamsLab(t *testing.T) (*apiDelegationFixture, time.Time, string) {
	t.Helper()
	l := apiDelegationLab(t)
	l.trust.AllowedScopes = strings.Fields(allTeamScopes)
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.verifier = v
	l.server.SetDelegatedIdentityVerifier(v)
	r, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "team-install", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, r.MinimumIAT)
	return l, r.MinimumIAT, l.sign(t, r.MinimumIAT, "owner", "alice", allTeamScopes)
}
func apiCreateTeam(t *testing.T, l *apiDelegationFixture, token, key string) controlplane.Team {
	t.Helper()
	r := call(t, l.server, "POST", "/v1/teams", token, key, fmt.Sprintf(`{"name":%q}`, key))
	var team controlplane.Team
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &team) != nil {
		t.Fatal("create team", r.Code, r.Body.String())
	}
	return team
}
func teamMemberBody(id string) string {
	b, _ := json.Marshal(controlplane.AddTeamMemberInput{PrincipalID: id})
	return string(b)
}

func TestHTTPTeamsRolesScopesAndMetadata(t *testing.T) {
	l, at, owner := apiTeamsLab(t)
	team := apiCreateTeam(t, l, owner, "metadata")
	memberPath := "/v1/teams/" + team.ID + "/members"
	roles := []string{"org_owner", "org_admin", "agent_operator", "agent_user", "auditor"}
	for _, role := range roles {
		m := apiAddMember(t, l, owner, "target-"+role, role)
		token := l.sign(t, at, role, m.Subject, allTeamScopes)
		wantRead, wantWrite := 403, 403
		if role == "org_owner" || role == "org_admin" || role == "auditor" {
			wantRead = 200
		}
		if role == "org_owner" || role == "org_admin" {
			wantWrite = 201
		}
		for _, path := range []string{"/v1/teams", "/v1/teams/" + team.ID, memberPath} {
			if r := call(t, l.server, "GET", path, token, "", ""); r.Code != wantRead {
				t.Fatal("role read", role, path, r.Code, wantRead)
			}
		}
		if r := call(t, l.server, "POST", "/v1/teams", token, "create", `{"name":"role"}`); r.Code != wantWrite {
			t.Fatal("role write", role, r.Code, wantWrite)
		}
		// An admin may manage an owner's team membership; this grants no org role.
		if r := call(t, l.server, "POST", memberPath, token, "join", teamMemberBody(l.org.OwnerPrincipalID)); r.Code != wantWrite && !(wantWrite == 201 && r.Code == 200) {
			t.Fatal("role membership", role, r.Code, wantWrite)
		}
	}
	readOnly := l.sign(t, at, "team-read", "alice", "team:read")
	manageOnly := l.sign(t, at, "team-manage", "alice", "team:manage")
	for _, tc := range []struct {
		token       string
		read, write int
	}{
		{readOnly, 200, 403}, {manageOnly, 403, 201}, {l.sign(t, at, "members-only", "alice", allMemberScopes), 403, 403},
	} {
		if r := call(t, l.server, "GET", memberPath, tc.token, "", ""); r.Code != tc.read {
			t.Fatal("scope read", r.Code, tc.read)
		}
		if r := call(t, l.server, "POST", "/v1/teams", tc.token, "scope-create", `{"name":"scoped"}`); r.Code != tc.write {
			t.Fatal("scope write", r.Code, tc.write)
		}
	}
	r := call(t, l.server, "GET", memberPath, readOnly, "", "")
	var out struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil || len(out.Items) != 1 {
		t.Fatal("membership metadata", r.Code, r.Body.String())
	}
	for _, item := range out.Items {
		if len(item) != 4 {
			t.Fatal("unexpected metadata field", item)
		}
		for _, k := range []string{"team_id", "principal_id", "status", "created_at"} {
			if _, ok := item[k]; !ok {
				t.Fatal("missing field", k)
			}
		}
	}
	if r := call(t, l.server, "GET", "/v1/members", readOnly, "", ""); r.Code != 403 {
		t.Fatal("team scope disclosed member identities", r.Code)
	}
}

func TestHTTPTeamsLifecycleAndInput(t *testing.T) {
	l, _, owner := apiTeamsLab(t)
	team := apiCreateTeam(t, l, owner, "support")
	other := apiCreateTeam(t, l, owner, "other")
	m := apiAddMember(t, l, owner, "human", "agent_user")
	base := "/v1/teams/" + team.ID
	join := call(t, l.server, "POST", base+"/members", owner, "join", teamMemberBody(m.PrincipalID))
	if join.Code != 201 {
		t.Fatal(join.Code)
	}
	if r := call(t, l.server, "POST", "/v1/teams/"+other.ID+"/members", owner, "join", teamMemberBody(m.PrincipalID)); r.Code != 422 {
		t.Fatal("team target omitted from hash", r.Code)
	}
	if r := call(t, l.server, "POST", base+"/members", owner, "join", teamMemberBody(l.org.OwnerPrincipalID)); r.Code != 422 {
		t.Fatal("member target omitted from hash", r.Code)
	}
	leave := base + "/members/" + m.PrincipalID + "/revoke"
	if r := call(t, l.server, "POST", leave, owner, "leave", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	r := call(t, l.server, "POST", base+"/members", owner, "join", teamMemberBody(m.PrincipalID))
	if r.Code != 201 || r.Header().Get("Idempotency-Replayed") != "true" || r.Body.String() != join.Body.String() {
		t.Fatal("historical replay", r.Code)
	}
	if r = call(t, l.server, "GET", base+"/members", owner, "", ""); !strings.Contains(r.Body.String(), `"status":"revoked"`) {
		t.Fatal("replay reactivated", r.Body.String())
	}
	if r = call(t, l.server, "POST", base+"/members", owner, "explicit-rejoin", teamMemberBody(m.PrincipalID)); r.Code != 200 || r.Header().Get("Idempotency-Replayed") == "true" {
		t.Fatal("explicit rejoin", r.Code)
	}
	if r = call(t, l.server, "POST", base+"/disable", owner, "disable", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	for _, key := range []string{"join", "new-after-disable"} {
		if r = call(t, l.server, "POST", base+"/members", owner, key, teamMemberBody(m.PrincipalID)); r.Code != 409 {
			t.Fatal("disabled team", r.Code)
		}
	}
	if r = call(t, l.server, "POST", "/v1/teams", owner, "support", `{"name":"support"}`); r.Code != 201 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("create replay", r.Code)
	}
	if r = call(t, l.server, "GET", base, owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"status":"disabled"`) {
		t.Fatal("disabled metadata", r.Code)
	}
	for _, body := range []string{`{"name":""}`, `{"name":"  "}`, `{"name":"x","tenant_id":"evil"}`} {
		if r = call(t, l.server, "POST", "/v1/teams", owner, "bad", body); r.Code != 400 {
			t.Fatal("bad create", r.Code)
		}
	}
	if r = call(t, l.server, "POST", "/v1/teams", owner, "", `{"name":"x"}`); r.Code != 400 {
		t.Fatal("missing key", r.Code)
	}
	for _, path := range []string{"/v1/teams", base + "/members"} {
		for _, query := range []string{"?limit=0", "?limit=201", "?limit=bad", "?after=" + strings.Repeat("x", 101)} {
			if r = call(t, l.server, "GET", path+query, owner, "", ""); r.Code != 400 {
				t.Fatal("pagination", r.Code)
			}
		}
	}
	for _, path := range []string{base + "/disable", leave} {
		if r = call(t, l.server, "POST", path, owner, "bad", `{"reactivate":true}`); r.Code != 400 {
			t.Fatal("reactivation accepted", r.Code)
		}
	}
	if r = call(t, l.server, "POST", base+"/members", owner, "bad", `{"principal_id":"x","role":"org_owner"}`); r.Code != 400 {
		t.Fatal("extra field", r.Code)
	}
}

func TestHTTPTeamsTenantAndCredentialBoundaries(t *testing.T) {
	l, at, one := apiTeamsLab(t)
	first := apiCreateTeam(t, l, one, "first")
	second := *l
	r := call(t, l.server, "POST", "/v1/organizations", l.platform, "second-org", `{"name":"second","initial_owner":{"issuer":"https://client.example","subject":"alice","display_name":"Alice"}}`)
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &second.org) != nil {
		t.Fatal("second tenant", r.Code)
	}
	second.trust.TenantID = second.org.ID
	second.trust.Audience = "second-capsule"
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust, second.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.server.SetDelegatedIdentityVerifier(v)
	i, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "second-install", Actor: "test-operator", Action: "install", TenantID: second.org.ID, Issuer: second.trust.Issuer, Audience: second.trust.Audience, Trust: &second.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, i.MinimumIAT)
	two := second.sign(t, i.MinimumIAT, "owner", "alice", allTeamScopes)
	foreign := apiCreateTeam(t, &second, two, "foreign")
	if r = call(t, l.server, "GET", "/v1/teams?tenant_id="+second.org.ID, one, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), first.ID) || strings.Contains(r.Body.String(), foreign.ID) {
		t.Fatal("list tenant leak", r.Code)
	}
	for _, tc := range []struct{ token, id, member string }{{one, foreign.ID, second.org.OwnerPrincipalID}, {two, first.ID, l.org.OwnerPrincipalID}} {
		base := "/v1/teams/" + tc.id
		for _, path := range []string{base, base + "/members"} {
			if r = call(t, l.server, "GET", path, tc.token, "", ""); r.Code != 404 {
				t.Fatal("foreign read", r.Code)
			}
		}
		for _, path := range []string{base + "/disable", base + "/members/" + tc.member + "/revoke"} {
			if r = call(t, l.server, "POST", path, tc.token, "foreign", `{}`); r.Code != 404 {
				t.Fatal("foreign write", r.Code)
			}
		}
		if r = call(t, l.server, "POST", base+"/members", tc.token, "foreign", teamMemberBody(tc.member)); r.Code != 404 {
			t.Fatal("foreign addition", r.Code)
		}
	}
	if r = call(t, l.server, "POST", "/v1/teams/"+first.ID+"/members", one, "foreign-target", teamMemberBody(second.org.OwnerPrincipalID)); r.Code != 404 {
		t.Fatal("cross tenant principal", r.Code)
	}
	for _, tc := range []struct {
		token  string
		status int
	}{{l.platform, 403}, {l.legacy, 403}, {l.sign(t, at, "unknown", "unregistered", allTeamScopes), 401}} {
		if r = call(t, l.server, "GET", "/v1/teams", tc.token, "", ""); r.Code != tc.status {
			t.Fatal("read credential", r.Code, tc.status)
		}
		if r = call(t, l.server, "POST", "/v1/teams", tc.token, "boundary", `{"name":"boundary"}`); r.Code != tc.status {
			t.Fatal("write credential", r.Code, tc.status)
		}
	}
	if r = call(t, l.server, "POST", "/v1/organizations/"+l.org.ID+"/disable", l.platform, "disable", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	if r = call(t, l.server, "POST", "/v1/teams", one, "first", `{"name":"first"}`); r.Code != 401 {
		t.Fatal("disabled tenant replay", r.Code)
	}
}
