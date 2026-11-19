package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/golang-jwt/jwt/v5"
)

var appTestSigningKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func testKey() controlplane.OIDCKey {
	return controlplane.OIDCKey{Kty: "RSA", Kid: "test", N: base64.RawURLEncoding.EncodeToString(appTestSigningKey().N.Bytes()), E: "AQAB"}
}
func stringify(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func appTestConfig(name string) controlplane.ApplicationConfig {
	return controlplane.ApplicationConfig{Name: name, Issuer: "https://login.example.test/" + name, Audience: "agentcapsule-api", ClientID: "monapp", RedirectURIs: []string{"https://monapp.example.test/callback"}, VerificationKeys: []controlplane.OIDCKey{testKey()}}
}
func appConfigFixture(t *testing.T, f *rbacFixture) map[string]string {
	name := f.next()
	return map[string]string{"app_config": stringify(appTestConfig(name)), "other_app_config": stringify(appTestConfig(name + "-other"))}
}
func appFixture(t *testing.T, f *rbacFixture) map[string]string {
	var app controlplane.IssuedApplication
	f.must(t, "owner", "POST", "/v1/applications", stringify(appTestConfig(f.next())), 201, &app)
	return map[string]string{"app": app.ID, "issuer": app.Issuer, "backend": app.ProvisioningToken, "team": rbacFreshTeam(t, f)["fresh"]}
}
func policyFixture(t *testing.T, f *rbacFixture) map[string]string {
	v := appFixture(t, f)
	var policy controlplane.AssignmentPolicy
	f.must(t, "owner", "POST", "/v1/assignment-policies/plan", f.resolve(t, appPolicyBody, "owner", v), 201, &policy)
	v["policy"] = policy.ID
	return v
}
func activePolicyFixture(t *testing.T, f *rbacFixture) map[string]string {
	v := policyFixture(t, f)
	f.must(t, "owner", "POST", "/v1/assignment-policies/"+v["policy"]+"/apply", "{}", 200, nil)
	v["expires"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return v
}

func signAppToken(t *testing.T, issuer, subject, audience string) string {
	now := time.Now().UTC()
	c := jwt.MapClaims{"iss": issuer, "aud": audience, "sub": subject, "jti": "jti-" + subject, "azp": "monapp", "typ": "Bearer",
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "openid email org:read member:accept agent:read agent:invoke agent:content:read", "email": subject + "@example.test", "email_verified": true}
	v := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	v.Header["kid"] = "test"
	raw, err := v.SignedString(appTestSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func inviteFixture(t *testing.T, f *rbacFixture) map[string]string {
	v := activePolicyFixture(t, f)
	var invitation controlplane.Invitation
	f.must(t, "owner", "POST", "/v1/applications/"+v["app"]+"/invitations", f.resolve(t, appInviteBody, "owner", v), 201, &invitation)
	v["proof"] = invitation.Proof
	f.static["applicant"] = signAppToken(t, v["issuer"], "alice", "agentcapsule-api")
	return v
}
func activationFixture(t *testing.T, f *rbacFixture) map[string]string {
	v := inviteFixture(t, f)
	var a controlplane.Activation
	f.must(t, "applicant", "POST", "/v1/applications/"+v["app"]+"/accept", stringify(controlplane.AcceptInvitation{Proof: v["proof"]}), 200, &a)
	v["activation"] = a.ID
	return v
}

const appPolicyBody = `{"application_id":"{app}","allowed_teams":["{team}"],"on_exhaustion":"wait","slots":[{"name":"support","team_id":"{team}","agent_id":"{agent}","permissions":["read_metadata","invoke","read_content"]}]}`
const appInviteBody = `{"policy_id":"{policy}","team_id":"{team}","email":"alice@example.test","expires_at":"{expires}"}`

var applicationRoutesMatrix = []rbacRoute{
	{Method: "GET", Path: "/v1/applications", Success: 200, Want: "S S 403 403 403 403 403 403 403 S 401 401 403"},
	{Method: "POST", Path: "/v1/applications", Success: 201, Want: rbacCreateAdmin, body: "{app_config}", fresh: appConfigFixture},
	{Method: "GET", Path: "/v1/applications/{app}", Success: 200, Want: rbacIdentity, fresh: appFixture},
	{Method: "POST", Path: "/v1/applications/{app}/rotate", Success: 200, Want: rbacIdentity, body: "{}", fresh: appFixture, revokes: "service_token"},
	{Method: "POST", Path: "/v1/applications/{app}/revoke", Success: 200, Want: rbacIdentity, body: "{}", fresh: appFixture, revokes: "service_token principal"},
	{Method: "POST", Path: "/v1/assignment-policies/plan", Success: 201, Want: rbacManage, body: appPolicyBody, fresh: appFixture},
	{Method: "POST", Path: "/v1/assignment-policies/{policy}/apply", Success: 200, Want: rbacManage, body: "{}", fresh: policyFixture},
	{Method: "POST", Path: "/v1/applications/{app}/invitations", Success: 201, Want: rbacManage, body: appInviteBody, fresh: activePolicyFixture},
	{Method: "POST", Path: "/v1/applications/{app}/accept", Success: 200, Want: "401 401 401 401 401 401 401 401 401 401 401 401 401", body: `{"proof":"{proof}"}`, fresh: inviteFixture, Note: "requires the recipient's OIDC access token and invitation proof"},
	{Method: "GET", Path: "/v1/applications/{app}/activations/{activation}", Success: 200, Want: rbacManage, fresh: activationFixture, Note: "also visible to its member and application backend"},
	{Method: "PUT", Path: "/v1/applications/{app}/activations/{activation}", Success: 200, Want: rbacManage, body: `{"version":2}`, fresh: activationFixture, revokes: "team_membership", Note: "also available to the authorized application backend"},
	{Method: "GET", Path: "/v1/access/explain?member={user_principal}&agent={agent}", Success: 200, Want: rbacManage},
}

func TestMonAppMemberLifecycle(t *testing.T) {
	f := newRBACFixture(t)
	v := inviteFixture(t, f)
	app := "/v1/applications/" + v["app"]
	raw := f.static["applicant"]
	request := func(actor, method, path, key, body string, code int) string {
		t.Helper()
		r := call(t, f.server, method, path, actor, key, body)
		if r.Code != code {
			t.Fatalf("%s %s: %d want %d: %s", method, path, r.Code, code, r.Body.String())
		}
		return r.Body.String()
	}
	accept := stringify(controlplane.AcceptInvitation{Proof: v["proof"]})
	request(signAppToken(t, v["issuer"], "bob", "agentcapsule-api"), "POST", app+"/accept", "not-bob", accept, 404)
	request(signAppToken(t, v["issuer"], "alice", "monapp"), "POST", app+"/accept", "audience", accept, 401)
	var a controlplane.Activation
	first := request(raw, "POST", app+"/accept", "activate", accept, 200)
	if err := json.Unmarshal([]byte(first), &a); err != nil || a.State != "ready" || a.Agents["support"] != f.ids["agent"] {
		t.Fatal("activation", first, err)
	}
	if first != request(raw, "POST", app+"/accept", "activate", accept, 200) || first != request(raw, "POST", app+"/accept", "second-click", accept, 200) {
		t.Fatal("double acceptance changed assignment")
	}
	request(raw, "GET", "/v1/agents/"+f.ids["agent"], "", "", 200)
	request(v["backend"], "GET", "/v1/agents/"+f.ids["agent"], "", "", 403)
	path := app + "/activations/" + a.ID
	request(f.token(t, "foreign"), "GET", path, "", "", 404)
	f.static["alice-monapp"] = raw
	inv := f.invoke(t, "alice-monapp")
	f.complete(t, inv)
	request(raw, "GET", "/v1/invocations/"+inv+"/result", "", "", 200)
	request(f.token(t, "team"), "GET", "/v1/invocations/"+inv+"/result", "", "", 404)
	request(v["backend"], "PUT", path, "move", `{"version":2}`, 200)
	request(raw, "GET", "/v1/agents/"+f.ids["agent"], "", "", 404)
	request(v["backend"], "PUT", path, "move", `{"version":3,"disabled":true}`, 422)
	request(v["backend"], "PUT", path, "leave", `{"version":3,"disabled":true}`, 200)
	request(v["backend"], "PUT", path, "old", fmt.Sprintf(`{"version":2,"team_id":%q}`, v["team"]), 409)
	request(raw, "GET", "/v1/organizations/current", "", "", 401)
	if !strings.Contains(request(f.token(t, "owner"), "GET", "/v1/audit", "", "", 200), "application.member_updated") {
		t.Fatal("missing lifecycle audit")
	}
}
