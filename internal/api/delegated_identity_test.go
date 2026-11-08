package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type apiDelegationFixture struct {
	server                *Server
	store                 *controlplane.Store
	dsn, platform, legacy string
	org                   controlplane.CreateOrganizationResponse
	trust                 delegatedidentity.Trust
	key                   ed25519.PrivateKey
	verifier              *delegatedidentity.Verifier
}

func apiDelegationLab(t *testing.T) *apiDelegationFixture {
	t.Helper()
	server, store, legacy, dsn := apiLab(t)
	platform := platformForAPI(t, store)
	body := `{"name":"Tenant API","initial_owner":{"issuer":"https://client.example","subject":"alice","display_name":"Alice"}}`
	r := call(t, server, "POST", "/v1/organizations", platform, "org", body)
	l := &apiDelegationFixture{server: server, store: store, dsn: dsn, platform: platform, legacy: legacy}
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &l.org) != nil {
		t.Fatal("organization setup")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l.key = key
	l.trust = delegatedidentity.Trust{TenantID: l.org.ID, Issuer: "https://client.example", Audience: "capsule", Keys: map[string]ed25519.PublicKey{"primary": pub}, AllowedScopes: []string{"org:read"}, MaxTTL: 5 * time.Minute}
	l.verifier, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *apiDelegationFixture) sign(t *testing.T, at time.Time, jti, subject, scope string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": subject, "jti": jti, "iat": at.Unix(), "exp": at.Add(5 * time.Minute).Unix(), "scope": scope, "role": "platform", "trust_generation": int64(1)})
	token.Header["kid"] = "primary"
	raw, err := token.SignedString(l.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func waitAPITenantClock(t *testing.T, dsn string, at time.Time) {
	t.Helper()
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		if err := db.QueryRow(t.Context(), "SELECT clock_timestamp()>=$1::timestamptz", at).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("database clock cutoff not reached")
}

func TestHTTPDelegationCurrentOrganizationAndBoundaries(t *testing.T) {
	l := apiDelegationLab(t)
	before := l.sign(t, time.Now().UTC().Truncate(time.Second), "preactivation", "alice", "org:read")
	if r := call(t, l.server, "GET", "/v1/organizations/current", before, "", ""); r.Code != 401 {
		t.Fatal("JWT accepted without configuration", r.Code)
	}
	l.server.SetDelegatedIdentityVerifier(l.verifier)
	if r := call(t, l.server, "GET", "/v1/organizations/current", before, "", ""); r.Code != 401 {
		t.Fatal("configuration auto-activated trust", r.Code)
	}
	installed, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "install", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal(err)
	}
	waitAPITenantClock(t, l.dsn, installed.MinimumIAT)
	raw := l.sign(t, installed.MinimumIAT, "current", "alice", "org:read")
	r := call(t, l.server, "GET", "/v1/organizations/current?tenant_id=other", raw, "", "")
	var current controlplane.CurrentOrganization
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &current) != nil || current.Organization.ID != l.org.ID || current.PrincipalID != l.org.OwnerPrincipalID || current.Role != "org_owner" {
		t.Fatal("tenant metadata response", r.Code)
	}
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/v1/organizations/current", l.platform, 403},
		{"/v1/organizations/current", l.legacy, 403},
		{"/v1/organizations/current", l.sign(t, installed.MinimumIAT, "unknown", "unregistered", "org:read"), 401},
		{"/v1/organizations/current", l.sign(t, installed.MinimumIAT, "no-scope", "alice", ""), 403},
		{"/v1/organizations", raw, 403},
		{"/v1/organizations/" + l.org.ID, raw, 403},
		{"/v1/users", raw, 403},
		{"/v1/me", raw, 403},
		{"/v1/agents", raw, 403},
		{"/v1/operations/unknown", raw, 403},
	} {
		r := call(t, l.server, "GET", tc.path, tc.token, "", "")
		if r.Code != tc.status {
			t.Fatalf("%s status %d want %d", tc.path, r.Code, tc.status)
		}
		if strings.Contains(r.Body.String(), raw) || strings.Contains(r.Body.String(), l.platform) {
			t.Fatal("credential disclosed")
		}
	}
	_, err = l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "revoke", Actor: "test-operator", Action: "revoke-token", TenantID: l.org.ID, Issuer: l.trust.Issuer, TokenID: "current"})
	if err != nil {
		t.Fatal(err)
	}
	if r := call(t, l.server, "GET", "/v1/organizations/current", raw, "", ""); r.Code != 401 {
		t.Fatal("revoked delegation accepted", r.Code)
	}
}

func TestDelegationOperatorCLIAndRealAPI(t *testing.T) {
	l := apiDelegationLab(t)
	dir := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agentcapsule-admin", "agentcapsule-api"} {
		build := exec.CommandContext(t.Context(), "go", "build", "-o", filepath.Join(dir, name), "./cmd/"+name)
		build.Dir = root
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
	}
	config := map[string]any{"version": 1, "trusts": []any{map[string]any{"tenant_id": l.org.ID, "issuer": l.trust.Issuer, "audience": l.trust.Audience, "allowed_scopes": l.trust.AllowedScopes, "max_ttl_seconds": 300, "keys": []any{map[string]any{"kid": "primary", "public_key": base64.StdEncoding.EncodeToString(l.trust.Keys["primary"])}}}}}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "delegation.json")
	if err = os.WriteFile(configFile, encoded, 0644); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "receipt.key")
	if err = os.WriteFile(keyFile, []byte(strings.Repeat("6", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	admin := func(action, operation string) controlplane.DelegationChangeResult {
		t.Helper()
		args := []string{"configure-delegation", "-action", action, "-operation-id", operation, "-tenant-id", l.org.ID, "-issuer", l.trust.Issuer}
		if action == "revoke-token" {
			args = append(args, "-token-id", "live")
		} else {
			args = append(args, "-audience", l.trust.Audience, "-trust-file", configFile)
		}
		cmd := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), args...)
		cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+l.dsn)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("operator change: %v (output withheld)", err)
		}
		var result controlplane.DelegationChangeResult
		if json.Unmarshal(out, &result) != nil {
			t.Fatal("operator returned invalid public metadata")
		}
		return result
	}
	installed := admin("install", "install")
	replay := admin("install", "install")
	if !replay.Replayed || !replay.MinimumIAT.Equal(installed.MinimumIAT) {
		t.Fatal("CLI retry changed cutoff")
	}
	waitAPITenantClock(t, l.dsn, installed.MinimumIAT)
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listen.Addr().String()
	_ = listen.Close()
	log, err := os.Create(filepath.Join(dir, "api.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-api"), "-listen", address, "-receipt-key-file", keyFile, "-host-id", "local", "-delegated-identity-file", configFile)
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+l.dsn)
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = cmd.Process.Kill()
			<-done
		}
	})
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-done:
			finished = true
			t.Fatalf("API exited: %v (log withheld)", err)
		default:
		}
		response, err := client.Get("http://" + address + "/v1/health/ready")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("API readiness timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw := l.sign(t, installed.MinimumIAT, "live", "alice", "org:read")
	request := func(want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", "http://"+address+"/v1/organizations/current", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+raw)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != want {
			t.Fatal("real current response", response.StatusCode, err)
		}
		if want == 200 && !strings.Contains(string(body), l.org.ID) {
			t.Fatal("real API returned wrong tenant")
		}
	}
	request(200)
	admin("revoke-token", "revoke")
	request(401)
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal("API shutdown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("API shutdown timeout")
	}
	output, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), raw) || strings.Contains(string(output), l.dsn) || strings.Contains(string(output), l.platform) {
		t.Fatal("sensitive data in process log")
	}
}
