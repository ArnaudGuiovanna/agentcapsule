package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

const allMemberScopes = "org:read member:read member:manage"

func apiMembersLab(t *testing.T) (*apiDelegationFixture, time.Time, string) {
	t.Helper()
	l := apiDelegationLab(t)
	l.trust.AllowedScopes = []string{"org:read", "member:read", "member:manage"}
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.verifier = v
	l.server.SetDelegatedIdentityVerifier(v)
	r, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "member-install", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, r.MinimumIAT)
	return l, r.MinimumIAT, l.sign(t, r.MinimumIAT, "owner", "alice", allMemberScopes)
}
func apiMemberBody(l *apiDelegationFixture, subject, role string) string {
	b, _ := json.Marshal(controlplane.CreateMemberInput{Issuer: l.trust.Issuer, Subject: subject, DisplayName: subject, Role: authorization.Role(role)})
	return string(b)
}
func apiAddMember(t *testing.T, l *apiDelegationFixture, token, subject, role string) controlplane.Member {
	t.Helper()
	r := call(t, l.server, "POST", "/v1/members", token, "add-"+subject, apiMemberBody(l, subject, role))
	var m controlplane.Member
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &m) != nil {
		t.Fatal("member setup", r.Code, r.Body.String())
	}
	return m
}

func TestHTTPMembersRoleAndTargetMatrix(t *testing.T) {
	l, at, owner := apiMembersLab(t)
	roles := []string{"org_owner", "org_admin", "agent_operator", "agent_user", "auditor"}
	actors := map[string]string{"org_owner": owner}
	targets := map[string]controlplane.Member{}
	for _, role := range roles {
		m := apiAddMember(t, l, owner, "target-"+role, role)
		targets[role] = m
		if role != "org_owner" {
			actors[role] = l.sign(t, at, role, m.Subject, allMemberScopes)
		}
	}
	for _, actorRole := range roles {
		t.Run(actorRole, func(t *testing.T) {
			token := actors[actorRole]
			wantRead := 403
			if actorRole == "org_owner" || actorRole == "org_admin" || actorRole == "auditor" {
				wantRead = 200
			}
			if r := call(t, l.server, "GET", "/v1/members", token, "", ""); r.Code != wantRead {
				t.Fatal("list role", r.Code, wantRead)
			}
			for _, targetRole := range roles {
				t.Run(targetRole, func(t *testing.T) {
					allowed := actorRole == "org_owner" || (actorRole == "org_admin" && targetRole != "org_owner" && targetRole != "org_admin")
					want := 403
					if allowed {
						want = 200
					}
					// A no-op still requires the current target policy. Leaving roles
					// unchanged lets every actor face the same target matrix.
					r := call(t, l.server, "POST", "/v1/members/"+targets[targetRole].PrincipalID+"/role", token, "noop-"+targetRole, fmt.Sprintf(`{"role":%q}`, targetRole))
					if r.Code != want {
						t.Fatal("change target role", r.Code, want)
					}
					if allowed {
						want = 201
					}
					r = call(t, l.server, "POST", "/v1/members", token, "grant-"+targetRole, apiMemberBody(l, actorRole+"-grants-"+targetRole, targetRole))
					if r.Code != want {
						t.Fatal("grant target role", r.Code, want)
					}
				})
			}
		})
	}
	for _, target := range []string{"org_owner", "org_admin"} {
		if r := call(t, l.server, "POST", "/v1/members/"+targets[target].PrincipalID+"/revoke", actors["org_admin"], "protected-"+target, `{}`); r.Code != 403 {
			t.Fatal("admin revoked protected role", r.Code)
		}
	}
	if r := call(t, l.server, "POST", "/v1/members/"+targets["agent_user"].PrincipalID+"/role", actors["org_admin"], "escalate", `{"role":"org_admin"}`); r.Code != 403 {
		t.Fatal("admin granted privileged role", r.Code)
	}
}

func TestHTTPMembersIdempotencyAndRevocation(t *testing.T) {
	l, at, owner := apiMembersLab(t)
	body := apiMemberBody(l, "admin", "org_admin")
	first := call(t, l.server, "POST", "/v1/members", owner, "create-admin", body)
	var admin controlplane.Member
	if first.Code != 201 || json.Unmarshal(first.Body.Bytes(), &admin) != nil {
		t.Fatal(first.Code)
	}
	replayed := call(t, l.server, "POST", "/v1/members", owner, "create-admin", body)
	if replayed.Code != 201 || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != first.Body.String() {
		t.Fatal("exact replay")
	}
	if r := call(t, l.server, "POST", "/v1/members", owner, "create-admin", apiMemberBody(l, "different", "org_admin")); r.Code != 422 {
		t.Fatal("mismatched creation", r.Code)
	}
	a := l.sign(t, at, "admin", "admin", allMemberScopes)
	u := apiAddMember(t, l, a, "user", "agent_user")
	other := apiAddMember(t, l, a, "other", "agent_user")
	path := "/v1/members/" + u.PrincipalID + "/role"
	changed := call(t, l.server, "POST", path, a, "change", `{"role":"auditor"}`)
	if changed.Code != 200 {
		t.Fatal(changed.Code)
	}
	if r := call(t, l.server, "POST", path, a, "change", `{"role":"auditor"}`); r.Code != 200 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("role replay", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/members/"+other.PrincipalID+"/role", a, "change", `{"role":"auditor"}`); r.Code != 422 {
		t.Fatal("target missing from input hash", r.Code)
	}
	// Current target privileges override both saved create and role receipts.
	if r := call(t, l.server, "POST", path, owner, "promote", `{"role":"org_admin"}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	if r := call(t, l.server, "POST", path, a, "change", `{"role":"auditor"}`); r.Code != 403 {
		t.Fatal("role replay target elevation", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/members", a, "add-user", apiMemberBody(l, "user", "agent_user")); r.Code != 403 {
		t.Fatal("create replay target elevation", r.Code)
	}
	revoke := "/v1/members/" + admin.PrincipalID + "/revoke"
	if r := call(t, l.server, "POST", revoke, owner, "revoke-admin", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	for _, key := range []string{"revoke-admin", "noop-revoke"} {
		if r := call(t, l.server, "POST", revoke, owner, key, `{}`); r.Code != 200 {
			t.Fatal("revoke repeat", r.Code)
		}
	}
	if r := call(t, l.server, "POST", "/v1/members", a, "add-other", apiMemberBody(l, "other", "agent_user")); r.Code != 401 {
		t.Fatal("revoked replay", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/members", a, "", ""); r.Code != 401 {
		t.Fatal("revoked read", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/members", owner, "resurrect", body); r.Code != 409 {
		t.Fatal("duplicate resurrected", r.Code)
	}
	if r := call(t, l.server, "POST", revoke, owner, "revoke-admin", `{"reactivate":true}`); r.Code != 400 {
		t.Fatal("reactivation field accepted", r.Code)
	}
}

func TestHTTPMembersTenantAndCredentialBoundaries(t *testing.T) {
	l, at, one := apiMembersLab(t)
	second := *l
	r := call(t, l.server, "POST", "/v1/organizations", l.platform, "second-org", `{"name":"second","initial_owner":{"issuer":"https://client.example","subject":"alice","display_name":"Alice"}}`)
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &second.org) != nil {
		t.Fatal("second tenant")
	}
	second.trust.TenantID = second.org.ID
	second.trust.Audience = "second-capsule"
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust, second.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.server.SetDelegatedIdentityVerifier(v)
	installed, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "second-install", Actor: "test-operator", Action: "install", TenantID: second.org.ID, Issuer: second.trust.Issuer, Audience: second.trust.Audience, Trust: &second.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, installed.MinimumIAT)
	two := second.sign(t, installed.MinimumIAT, "same-jti", "alice", allMemberScopes)
	firstMember := apiAddMember(t, l, one, "same-subject", "agent_user")
	secondMember := apiAddMember(t, &second, two, "same-subject", "agent_user")
	if firstMember.PrincipalID == secondMember.PrincipalID {
		t.Fatal("cross-tenant identity collapse")
	}
	for _, tc := range []struct {
		token        string
		own, foreign string
	}{{one, firstMember.PrincipalID, secondMember.PrincipalID}, {two, secondMember.PrincipalID, firstMember.PrincipalID}} {
		r = call(t, l.server, "GET", "/v1/members?tenant_id="+second.org.ID, tc.token, "", "")
		if r.Code != 200 || !strings.Contains(r.Body.String(), tc.own) || strings.Contains(r.Body.String(), tc.foreign) {
			t.Fatal("list tenant leak", r.Code)
		}
		for _, op := range []string{"role", "revoke"} {
			body := `{}`
			if op == "role" {
				body = `{"role":"auditor"}`
			}
			if r = call(t, l.server, "POST", "/v1/members/"+tc.foreign+"/"+op, tc.token, "foreign-"+op, body); r.Code != 404 {
				t.Fatal("cross-tenant target", op, r.Code)
			}
		}
	}
	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"platform", l.platform, 403}, {"legacy", l.legacy, 403},
		{"unknown", l.sign(t, at, "unknown", "unregistered", allMemberScopes), 401},
		{"no-scope", l.sign(t, at, "no-scope", "alice", "org:read"), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := call(t, l.server, "GET", "/v1/members", tc.token, "", ""); r.Code != tc.status {
				t.Fatal("read credential boundary", r.Code, tc.status)
			}
			if r := call(t, l.server, "POST", "/v1/members", tc.token, "boundary", apiMemberBody(l, "boundary", "agent_user")); r.Code != tc.status {
				t.Fatal("write credential boundary", r.Code, tc.status)
			}
		})
	}
	if r := call(t, l.server, "POST", "/v1/members", one, "tenant-input", `{"tenant_id":"evil","issuer":"x","subject":"y","display_name":"Y","role":"agent_user"}`); r.Code != 400 {
		t.Fatal("tenant input accepted", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/organizations/"+l.org.ID+"/disable", l.platform, "disable", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/members", one, "add-same-subject", apiMemberBody(l, "same-subject", "agent_user")); r.Code != 401 {
		t.Fatal("disabled tenant replay", r.Code)
	}
}

func TestHTTPMembersInputAndLastOwner(t *testing.T) {
	l, _, owner := apiMembersLab(t)
	for _, body := range []string{
		`{"issuer":" x","subject":"y","display_name":"Y","role":"agent_user"}`,
		`{"issuer":"x","subject":"y\n","display_name":"Y","role":"agent_user"}`,
		`{"issuer":"x","subject":"y","display_name":"Y","role":"platform"}`,
		`{"issuer":"x","subject":"y","display_name":"Y","role":"agent_user","scopes":["platform:admin"]}`,
	} {
		if r := call(t, l.server, "POST", "/v1/members", owner, "bad", body); r.Code != 400 {
			t.Fatal("bad member input", r.Code)
		}
	}
	if r := call(t, l.server, "POST", "/v1/members", owner, "", apiMemberBody(l, "good", "agent_user")); r.Code != 400 {
		t.Fatal("missing idempotency key", r.Code)
	}
	for _, suffix := range []string{"?limit=0", "?limit=201", "?limit=bad"} {
		if r := call(t, l.server, "GET", "/v1/members"+suffix, owner, "", ""); r.Code != 400 {
			t.Fatal("bad pagination", r.Code)
		}
	}
	for _, op := range []string{"role", "revoke"} {
		body := `{}`
		if op == "role" {
			body = `{"role":"org_admin"}`
		}
		if r := call(t, l.server, "POST", "/v1/members/"+l.org.OwnerPrincipalID+"/"+op, owner, "last-"+op, body); r.Code != 409 {
			t.Fatal("lost last owner", r.Code)
		}
	}
}
