package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	return signAppTokenForEmail(t, issuer, subject, subject+"@example.test", audience)
}

func signAppTokenForEmail(t *testing.T, issuer, subject, email, audience string) string {
	now := time.Now().UTC()
	c := jwt.MapClaims{"iss": issuer, "aud": audience, "sub": subject, "jti": "jti-" + subject, "azp": "monapp", "typ": "Bearer",
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "openid email org:read member:accept member:invite agent:read agent:invoke agent:content:read", "email": email, "email_verified": true}
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
	{Method: "POST", Path: "/v1/pools/{pool}/expand", Success: 200, Want: "S S S 403 403 403 403 403 403 404 401 401 403", body: `{"count":1}`},
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

// Exercise the language-neutral reference over a TLS listener. The control
// plane, PostgreSQL and authorizations are real; the fixture worker completes
// the admitted operation. With the live realm fixture the member sessions are
// obtained by following the bundled provider's browser and PKCE exchanges.
func TestMonAppHTTPReference(t *testing.T) {
	f := newRBACFixture(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var deployment controlplane.DeploymentPlan
	f.must(t, "owner", "POST", "/v1/deployment-plans", `{"template":"matrix-base@1","count":4}`, 201, &deployment)
	f.must(t, "owner", "POST", "/v1/deployment-plans/"+deployment.ID+"/apply", "{}", 202, nil)
	var pool controlplane.AgentPool
	f.must(t, "owner", "POST", "/v1/pools", stringify(controlplane.PoolInput{Name: "personal", DeploymentID: deployment.ID}), 201, &pool)
	rows, err := f.db.Query(t.Context(), "SELECT agent_id FROM agent_pool_members WHERE pool_id=$1", pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		agents = append(agents, id)
	}
	rows.Close()
	if len(agents) != 4 {
		t.Fatal("expected a four-agent pool", agents)
	}
	for _, id := range agents {
		apiProvisionAgent(t, f.l, id)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/invocations") {
			f.server.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, r)
		if rec.Code == 202 {
			var inv controlplane.Invocation
			if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil {
				t.Error(err)
				return
			}
			f.complete(t, inv.ID)
		}
		for k, vals := range rec.Header() {
			w.Header()[k] = vals
		}
		w.WriteHeader(rec.Code)
		_, _ = io.Copy(w, rec.Body)
	}))
	defer srv.Close()
	ca := write("api-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	cfg := appTestConfig("monapp")
	live := os.Getenv("AGENTCAPSULE_TEST_MONAPP_KEYCLOAK_DIR")
	if live != "" {
		cfg.Issuer = "https://localhost:19443/realms/agentcapsule"
		data, err := os.ReadFile(filepath.Join(live, "tls.crt"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			t.Fatal("empty realm root")
		}
		client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
		resp, err := client.Get(cfg.Issuer + "/protocol/openid-connect/certs")
		if err != nil {
			t.Fatal(err)
		}
		var jwks struct {
			Keys []struct {
				controlplane.OIDCKey
				Use, Alg string
			}
		}
		if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		cfg.VerificationKeys = nil
		for _, k := range jwks.Keys {
			if k.Use == "sig" && k.Alg == "RS256" {
				cfg.VerificationKeys = append(cfg.VerificationKeys, k.OIDCKey)
			}
		}
	}
	var members []map[string]any
	for _, name := range []string{"alice", "bob"} {
		tokenFile := filepath.Join(dir, name+".jwt")
		member := map[string]any{"email": name + "@example.test", "token_file": tokenFile}
		if live != "" {
			member["keycloak_login"] = map[string]string{"username": name, "password_file": filepath.Join(live, name), "ca_file": filepath.Join(live, "tls.crt")}
			args := []string{"../../examples/monapp/oidc-login.py", "--issuer", cfg.Issuer, "--client-id", cfg.ClientID, "--redirect-uri", cfg.RedirectURIs[0], "--username", name,
				"--ca-file", filepath.Join(live, "tls.crt"), "--password-file", filepath.Join(live, name), "--output", tokenFile}
			if out, err := exec.CommandContext(t.Context(), "python3", args...).CombinedOutput(); err != nil {
				t.Fatalf("OIDC %s: %v %s", name, err, out)
			}
		} else {
			write(name+".jwt", signAppToken(t, cfg.Issuer, name, cfg.Audience))
		}
		members = append(members, member)
	}
	conf := map[string]any{"api": srv.URL, "api_ca": ca, "application": cfg, "members": members, "admin_token_file": write("admin.jwt", f.token(t, "owner")),
		"other_org_token_file": write("foreign.jwt", f.token(t, "foreign")), "support_team_id": rbacFreshTeam(t, f)["fresh"], "support_agent_id": f.ids["agent"], "pool_id": pool.ID, "timeout_seconds": 30}
	conf["sales_agent_id"] = f.activeAgent(t, f.next())
	conf["second_personal_pool_id"] = pool.ID
	conf["refusal_pool_id"] = f.ids["pool"]
	if live == "" {
		conf["reassigned_email_token_file"] = write("former.jwt", signAppTokenForEmail(t, cfg.Issuer, "former-alice", "alice@example.test", cfg.Audience))
		conf["wrong_audience_token_file"] = write("wrong-audience.jwt", signAppToken(t, cfg.Issuer, "alice", "another-api"))
	} else {
		for key, name := range map[string]string{"reassigned_email_token_file": "former.jwt", "wrong_audience_token_file": "wrong-audience.jwt"} {
			p := filepath.Join(live, name)
			if _, err := os.Stat(p); err == nil {
				conf[key] = p
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	path := write("scenario.json", stringify(conf))
	output, err := exec.CommandContext(t.Context(), "python3", "../../examples/monapp/verify.py", path).CombinedOutput()
	if err != nil {
		t.Fatalf("reference client: %v %s", err, output)
	}
	t.Log(string(output))
	var receipts struct {
		Transfer struct {
			FromTeam    string                          `json:"from_team_id"`
			ToTeam      string                          `json:"to_team_id"`
			Revocations []controlplane.AccessRevocation `json:"revocations"`
		} `json:"transfer"`
		Checks      map[string]bool                 `json:"optional_checks"`
		Member      []controlplane.AccessRevocation `json:"revocations"`
		Application []controlplane.AccessRevocation `json:"application_revocations"`
	}
	if err := json.Unmarshal(output, &receipts); err != nil || len(receipts.Member) == 0 || len(receipts.Application) == 0 {
		t.Fatal("missing durable revocations in SDK conformance output", err)
	}
	moved := receipts.Transfer
	if moved.FromTeam == "" || moved.ToTeam == "" || moved.FromTeam == moved.ToTeam ||
		len(moved.Revocations) != 1 || moved.Revocations[0].Kind != "team_membership" {
		t.Fatal("missing durable team transfer", moved)
	}
	if !receipts.Checks["sales_agent"] || receipts.Checks["fresh_member_sessions"] != (live != "") ||
		receipts.Checks["fresh_session_after_app_revoke"] != (live != "") {
		t.Fatal("missing Sales or session check", receipts.Checks)
	}
	reportFile := write("report.json", string(output))
	srv.Close()
	// Force a new database connection pool and API instance to reconstruct the
	// application's state. The same admin identities can read the persisted receipts.
	store, err := controlplane.Open(t.Context(), f.l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	accounts, err := controlplane.NewAccounts(store, bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewForHost(store, accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetDelegatedIdentityVerifier(f.server.delegations.Load())
	newServer := httptest.NewTLSServer(restarted)
	defer newServer.Close()
	conf["api"] = newServer.URL
	conf["api_ca"] = write("restart-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newServer.Certificate().Raw})))
	restartedConfig := write("after-restart.json", stringify(conf))
	again, err := exec.CommandContext(t.Context(), "python3", "../../examples/monapp/verify.py", restartedConfig, "--check-revoked", reportFile).CombinedOutput()
	if err != nil {
		t.Fatalf("reference client after restart: %v %s", err, again)
	}
	t.Log(string(again))
}

func TestApplicationPoolExhaustionAndDurableReplay(t *testing.T) {
	f := newRBACFixture(t)
	pool := f.ids["pool"]
	owner := f.token(t, "owner")
	run := func(mode string, want int) (controlplane.Activation, string, string) {
		t.Helper()
		v := appFixture(t, f)
		slots := []controlplane.PolicySlot{
			{Name: "research", PoolID: pool, Permissions: []string{"read_metadata"}},
			{Name: "admin", PoolID: pool, Permissions: []string{"read_metadata"}},
		}
		var pol controlplane.AssignmentPolicy
		f.must(t, "owner", "POST", "/v1/assignment-policies/plan", stringify(controlplane.PolicySpec{ApplicationID: v["app"], Slots: slots, OnExhaustion: mode}), 201, &pol)
		f.must(t, "owner", "POST", "/v1/assignment-policies/"+pol.ID+"/apply", "{}", 200, nil)
		var invitation controlplane.Invitation
		root := "/v1/applications/" + v["app"]
		f.must(t, "owner", "POST", root+"/invitations", stringify(controlplane.InviteInput{PolicyID: pol.ID, Email: "alice@example.test", ExpiresAt: time.Now().Add(time.Hour)}), 201, &invitation)
		token := signAppToken(t, v["issuer"], "alice", "agentcapsule-api")
		proof := stringify(controlplane.AcceptInvitation{Proof: invitation.Proof})
		r := call(t, f.server, "POST", root+"/accept", token, "click", proof)
		if r.Code != want {
			t.Fatalf("accept for %s: %d %s", mode, r.Code, r.Body.String())
		}
		if want != 200 {
			if problemCode(r) != "pool_exhausted" {
				t.Fatal(r.Body.String())
			}
			var n int
			if err := f.db.QueryRow(t.Context(), "SELECT count(*) FROM app_personal_reservations WHERE policy_id=$1", pol.ID).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial allocation", n, err)
			}
			return controlplane.Activation{}, root, proof
		}
		var a controlplane.Activation
		if err := json.Unmarshal(r.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(t.Context(), "DELETE FROM tenant_http_receipts WHERE tenant_id=$1 AND principal_id=$2", f.l.org.ID, a.PrincipalID); err != nil {
			t.Fatal(err)
		}
		again := call(t, f.server, "POST", root+"/accept", token, "after-expiry", proof)
		var retried controlplane.Activation
		if again.Code != 200 || json.Unmarshal(again.Body.Bytes(), &retried) != nil || retried.ID != a.ID || stringify(a.Agents) != stringify(retried.Agents) {
			t.Fatal(again.Code, again.Body.String())
		}
		return a, root, proof
	}
	run("refuse", 409)
	a, root, _ := run("wait", 200)
	if a.State != "waiting_capacity" || len(a.Agents) != 1 {
		t.Fatal("waiter", a)
	}
	f.must(t, "owner", "POST", "/v1/pools/"+pool+"/expand", `{"count":1}`, 200, nil)
	if _, err := f.db.Exec(t.Context(), "UPDATE app_activations SET retry_at=clock_timestamp() WHERE id=$1", a.ID); err != nil {
		t.Fatal(err)
	}
	go f.server.accounts.RetryWaitingActivations(t.Context())
	until := time.Now().Add(10 * time.Second)
	for {
		r := call(t, f.server, "GET", root+"/activations/"+a.ID, owner, "", "")
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &a) != nil {
			t.Fatal(r.Code, r.Body.String())
		}
		if len(a.Agents) == 2 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("waiter did not resume", a)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a.Agents["admin"] == a.Agents["research"] || a.State != "preparing" {
		t.Fatal(a)
	}
	auto, _, _ := run("create", 200)
	if len(auto.Agents) != 2 || auto.Agents["admin"] == auto.Agents["research"] {
		t.Fatal("automatic provisioning", auto)
	}
	var distinct, volumes int
	err := f.db.QueryRow(t.Context(), `SELECT count(DISTINCT r.agent_id),count(DISTINCT e.volume_id)
      FROM app_personal_reservations r JOIN store_enrollments e ON e.agent_id=r.agent_id WHERE r.principal_id IN ($1,$2)`, a.PrincipalID, auto.PrincipalID).Scan(&distinct, &volumes)
	if err != nil || distinct != 4 || volumes != 4 {
		t.Fatal(distinct, volumes, err)
	}
}

func TestAppInvitationScopeExpiryAndManager(t *testing.T) {
	f := newRBACFixture(t)
	v := activationFixture(t, f)
	var manager controlplane.Activation
	f.must(t, "owner", "GET", "/v1/applications/"+v["app"]+"/activations/"+v["activation"], "", 200, &manager)
	var policy controlplane.AssignmentPolicy
	f.must(t, "owner", "POST", "/v1/assignment-policies/plan", stringify(controlplane.PolicySpec{ApplicationID: v["app"], AllowedTeams: []string{v["team"]}, ManagerIDs: []string{manager.PrincipalID}, OnExhaustion: "refuse",
		Slots: []controlplane.PolicySlot{{Name: "personal", PoolID: f.ids["pool"], Permissions: []string{"invoke"}}}}), 201, &policy)
	f.must(t, "owner", "POST", "/v1/assignment-policies/"+policy.ID+"/apply", "{}", 200, nil)
	root := "/v1/applications/" + v["app"]
	in := controlplane.InviteInput{PolicyID: policy.ID, Email: "bob@example.test", TeamID: v["team"], ExpiresAt: time.Now().Add(time.Hour)}
	var invitation controlplane.Invitation
	f.must(t, "applicant", "POST", root+"/invitations", stringify(in), 201, &invitation)
	in.TeamID = f.ids["team"]
	if r := f.call(t, "applicant", "POST", root+"/invitations", "outside", stringify(in)); r.Code != 403 {
		t.Fatal("unauthorized team", r.Code, r.Body.String())
	}
	if _, err := f.db.Exec(t.Context(), "UPDATE app_invitations SET expires_at=clock_timestamp() WHERE id=$1", invitation.ID); err != nil {
		t.Fatal(err)
	}
	token := signAppToken(t, v["issuer"], "bob", "agentcapsule-api")
	r := call(t, f.server, "POST", root+"/accept", token, "expired", stringify(controlplane.AcceptInvitation{Proof: invitation.Proof}))
	if r.Code != 409 || problemCode(r) != "expired" {
		t.Fatal("expired", r.Code, r.Body.String())
	}
	f.must(t, "owner", "POST", root+"/revoke", "{}", 200, nil)
	r = call(t, f.server, "POST", root+"/accept", token, "revoked", stringify(controlplane.AcceptInvitation{Proof: invitation.Proof}))
	if r.Code != 401 {
		t.Fatal("revoked", r.Code, r.Body.String())
	}
}
