package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// emptyAPISchema is a new, empty schema: no migration, no credential.
func emptyAPISchema(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL missing")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	root, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	schema := "bootstrap_" + hex.EncodeToString(id)
	if _, err = root.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		root.Close()
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	testDSN := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	db, err := pgxpool.New(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := root.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		root.Close()
	})
	return testDSN, db
}

// signDelegation signs a token as an organization's identity provider does.
func signDelegation(t *testing.T, key ed25519.PrivateKey, kid, issuer, audience, subject, jti, scope string, at time.Time, generation int64) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": issuer, "aud": audience, "sub": subject, "jti": jti,
		"iat": at.Unix(), "exp": at.Add(4 * time.Minute).Unix(), "scope": scope, "trust_generation": generation})
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The operator bootstrap of docs/bootstrap.md, from an empty database to an
// organization whose first owner signs in and names an administrator, with
// the real binaries. Each step is run twice: a repeat confirms or is refused,
// never duplicates. Nothing has a default password, every step is audited,
// and a user ID written by the caller is refused (TEN-001, TEN-008).
func TestOperatorBootstrapFromEmptyDatabase(t *testing.T) {
	dsn, db := emptyAPISchema(t)
	dir := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agentcapsule-admin", "agentcapsule-api", "agentcapsule-authority"} {
		build := exec.CommandContext(t.Context(), "go", "build", "-o", filepath.Join(dir, name), "./cmd/"+name)
		build.Dir = root
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
	}
	// admin runs a command and returns its standard output and error apart.
	admin := func(args ...string) (string, string, error) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), args...)
		cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	must := func(want string, args ...string) string {
		t.Helper()
		out, errOut, err := admin(args...)
		if err != nil || (want != "" && out != want) {
			t.Fatalf("%s: %v %q %q", args[0], err, out, errOut)
		}
		return out
	}

	// 1. Migrate, twice.
	must("migration_complete\n", "migrate")
	must("migration_complete\n", "migrate")
	// No default password: a migrated installation holds no credential and no
	// identity, and the legacy installation command is gone.
	for _, table := range []string{"platform_credentials", "api_tokens", "service_tokens", "users", "organizations", "principals", "delegation_trusts", "delegation_keys"} {
		var n int
		if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatal("a fresh installation holds", table, n, err)
		}
	}
	if _, errOut, err := admin("bootstrap", "-receipt-key-file", filepath.Join(dir, "x"), "-token-file", filepath.Join(dir, "y")); err == nil || errOut != "bootstrap_removed_use_bootstrap_platform\n" {
		t.Fatal("the legacy owner bootstrap still runs", err, errOut)
	}

	// 2. The platform operator's credential: random, in a private file.
	keyFile, tokenFile := filepath.Join(dir, "receipt.key"), filepath.Join(dir, "platform.token")
	must("platform_bootstrap_complete\n", "bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", tokenFile)
	must("platform_bootstrap_complete\n", "bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", tokenFile)
	if _, errOut, err := admin("bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", filepath.Join(dir, "second.token")); err == nil || errOut != "platform_bootstrap_rejected_conflict\n" {
		t.Fatal("a second platform credential was created", err, errOut)
	}
	secret, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	platform := string(secret)
	if st, err := os.Stat(tokenFile); err != nil || st.Mode().Perm() != 0600 || !strings.HasPrefix(platform, "acpp_") {
		t.Fatal("platform token file", err)
	}

	// The API, on loopback (TLS: docs/install.md).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	log, err := os.Create(filepath.Join(dir, "api.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	api := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-api"), "-listen", address, "-receipt-key-file", keyFile, "-host-id", "local")
	api.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn, "AGENTCAPSULE_MODE=development")
	api.Stdout, api.Stderr = log, log
	if err = api.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- api.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = api.Process.Kill()
			<-done
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-done:
			finished = true
			t.Fatalf("API exited: %v", err)
		default:
		}
		if r, err := client.Get("http://" + address + "/v1/health/ready"); err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("API readiness timeout")
		}
	}
	call := func(method, path, token, key, body string, headers map[string]string) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, "http://"+address+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		return r.StatusCode, out
	}

	// 3. The organization, with its first owner's identity: issuer and subject
	// at its identity provider.
	const issuer, audience = "https://idp.acme.example", "agentcapsule:acme"
	organization := `{"name":"Acme","initial_owner":{"issuer":"` + issuer + `","subject":"alice","display_name":"Alice"}}`
	status, body := call("POST", "/v1/organizations", platform, "create-acme", organization, nil)
	var org controlplane.CreateOrganizationResponse
	if status != 201 || json.Unmarshal(body, &org) != nil || org.ID == "" {
		t.Fatal("organization", status, string(body))
	}
	if status, again := call("POST", "/v1/organizations", platform, "create-acme", organization, nil); status != 201 || !bytes.Equal(again, body) {
		t.Fatal("the same request did not replay", status)
	}
	if status, body := call("POST", "/v1/organizations", platform, "create-acme-again", strings.Replace(organization, "Acme", "ACME", 1), nil); status != 409 || !strings.Contains(string(body), "organization_name_taken") {
		t.Fatal("the organization was created twice", status, string(body))
	}

	// 4. Its identity trust: the public key of its identity provider.
	pub1, key1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"org:read", "member:read", "member:manage", "audit:read"}
	trust, err := json.Marshal(map[string]any{"version": 1, "trusts": []any{map[string]any{"tenant_id": org.ID, "issuer": issuer, "audience": audience,
		"allowed_scopes": scopes, "max_ttl_seconds": 300, "keys": []any{map[string]any{"kid": "2026-11", "public_key": base64.StdEncoding.EncodeToString(pub1)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	trustFile := filepath.Join(dir, "acme-trust.json")
	if err = os.WriteFile(trustFile, trust, 0644); err != nil {
		t.Fatal(err)
	}
	install := []string{"configure-delegation", "-action", "install", "-operation-id", "acme-trust", "-tenant-id", org.ID, "-issuer", issuer, "-audience", audience, "-trust-file", trustFile}
	var installed, replayed controlplane.DelegationChangeResult
	if json.Unmarshal([]byte(must("", install...)), &installed) != nil || installed.Status != "active" || installed.Generation != 1 {
		t.Fatal("trust installation", installed)
	}
	if json.Unmarshal([]byte(must("", install...)), &replayed) != nil || !replayed.Replayed || !replayed.MinimumIAT.Equal(installed.MinimumIAT) {
		t.Fatal("trust installation replay", replayed)
	}
	waitAPITenantClock(t, dsn, installed.MinimumIAT)
	at := installed.MinimumIAT
	sign := func(key ed25519.PrivateKey, kid, subject, jti string) string {
		return signDelegation(t, key, kid, issuer, audience, subject, jti, strings.Join(scopes, " "), at, 1)
	}

	// 5. The first owner signs in, and makes an administrator.
	current := func(token string) (int, controlplane.CurrentOrganization) {
		t.Helper()
		status, body := call("GET", "/v1/organizations/current", token, "", "", nil)
		var c controlplane.CurrentOrganization
		if status == 200 && json.Unmarshal(body, &c) != nil {
			t.Fatal("current organization")
		}
		return status, c
	}
	alice := sign(key1, "2026-11", "alice", "alice-1")
	if status, c := current(alice); status != 200 || c.Organization.ID != org.ID || c.Role != "org_owner" || c.PrincipalID != org.OwnerPrincipalID {
		t.Fatal("the first owner cannot sign in", status, c)
	}
	admin1 := `{"issuer":"` + issuer + `","subject":"bob","display_name":"Bob","role":"org_admin"}`
	if status, body := call("POST", "/v1/members", alice, "make-bob-admin", admin1, nil); status != 201 {
		t.Fatal("the owner could not name an administrator", status, string(body))
	}
	if status, _ := call("POST", "/v1/members", alice, "make-bob-admin-again", admin1, nil); status != 409 {
		t.Fatal("the administrator was registered twice", status)
	}
	if status, c := current(sign(key1, "2026-11", "bob", "bob-1")); status != 200 || c.Role != "org_admin" {
		t.Fatal("the administrator cannot sign in", status, c)
	}

	// Free-form user IDs are refused: a name, a header, an unsigned token, a
	// token signed by anyone else, an unregistered subject, a legacy account.
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": issuer, "aud": audience, "sub": "alice", "jti": "none",
		"iat": at.Unix(), "exp": at.Add(time.Minute).Unix(), "scope": "org:read", "trust_generation": 1})
	unsignedToken.Header["kid"] = "2026-11"
	unsigned, err := unsignedToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	store, err := controlplane.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	legacy, err := store.BootstrapService(t.Context(), "legacy-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]struct {
		token   string
		headers map[string]string
	}{
		"user-header":  {"", map[string]string{"X-User-ID": "alice", "X-Remote-User": "alice", "X-Forwarded-User": "alice"}},
		"bare-name":    {"alice", nil},
		"principal-id": {org.OwnerPrincipalID, nil},
		"unsigned":     {unsigned, nil},
		"self-signed":  {sign(stranger, "2026-11", "alice", "forged"), nil},
		"unregistered": {sign(key1, "2026-11", "mallory", "mallory-1"), nil},
		"legacy-token": {legacy, nil},
	} {
		if status, _ := call("GET", "/v1/organizations/current", attempt.token, "", "", attempt.headers); status != 401 {
			t.Fatal("a free-form identity was accepted:", name, status)
		}
	}
	if status, _ := call("GET", "/v1/users", legacy, "", "", nil); status != 401 {
		t.Fatal("the legacy owner domain is open", status)
	}

	// Every step is audited: the organization sees its own trail, the
	// operator sees the platform's.
	status, body = call("GET", "/v1/audit", alice, "", "", nil)
	if status != 200 || !strings.Contains(string(body), `"organization.created"`) || !strings.Contains(string(body), `"delegation.install"`) {
		t.Fatal("the organization's audit", status, string(body))
	}
	trail := must("", "list-audit")
	for _, action := range []string{"platform_credential.created", "organization.created", "delegation.install"} {
		if !strings.Contains(trail, `"action":"`+action+`"`) {
			t.Fatal("the operator audit misses", action, trail)
		}
	}
	if !strings.Contains(trail, fmt.Sprintf(`"actor":"local-uid:%d"`, os.Geteuid())) || strings.Contains(trail, platform) {
		t.Fatal("the operator audit does not name the operator, or shows a secret", trail)
	}

	// Trust rotation (TEN-02): a new key, an overlap, the old key retired.
	pub2, key2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyChange := func(op string, args ...string) controlplane.DelegationChangeResult {
		t.Helper()
		var r controlplane.DelegationChangeResult
		out := must("", append([]string{"configure-delegation", "-operation-id", op, "-tenant-id", org.ID, "-issuer", issuer, "-audience", audience}, args...)...)
		if json.Unmarshal([]byte(out), &r) != nil || r.Generation != 1 {
			t.Fatal("key change", out)
		}
		return r
	}
	// Adding or retiring a key changes who may sign in: -confirm names the key (ADR 014).
	if _, errOut, err := admin("configure-delegation", "-operation-id", "acme-key-unconfirmed", "-tenant-id", org.ID, "-issuer", issuer, "-audience", audience,
		"-action", "add-key", "-key-id", "2026-12", "-public-key", base64.StdEncoding.EncodeToString(pub2)); err == nil || errOut != "confirmation_required\n" {
		t.Fatal("a key was added without confirmation", err, errOut)
	}
	keyChange("acme-key-2026-12", "-action", "add-key", "-key-id", "2026-12", "-public-key", base64.StdEncoding.EncodeToString(pub2), "-confirm", "2026-12")
	for _, token := range []string{sign(key1, "2026-11", "alice", "old-key"), sign(key2, "2026-12", "alice", "new-key")} {
		if status, _ := current(token); status != 200 {
			t.Fatal("a key was refused during the overlap", status)
		}
	}
	// Retiring a key revokes access: its record goes to the authority
	// service before the commit (ADR 006 wave 5), refused in production
	// without it.
	if _, errOut, err := admin("configure-delegation", "-operation-id", "acme-retire-2026-11", "-tenant-id", org.ID, "-issuer", issuer, "-audience", audience,
		"-action", "retire-key", "-key-id", "2026-11", "-overlap", "0s", "-confirm", "2026-11"); err == nil || errOut != "authority_required_in_production\n" {
		t.Fatal("a key was retired without the authority service", err, errOut)
	}
	authority := startAuthorityService(t, dir)
	retired := keyChange("acme-retire-2026-11", append([]string{"-action", "retire-key", "-key-id", "2026-11", "-overlap", "0s", "-confirm", "2026-11"}, authority.flags()...)...)
	if len(retired.Revocations) != 1 || retired.Revocations[0].Kind != "delegation_trust" || retired.Revocations[0].State != controlplane.RevocationConfirmed {
		t.Fatal("the key's revocation record", retired)
	}
	if status, _ := current(sign(key1, "2026-11", "alice", "retired-key")); status != 401 {
		t.Fatal("a retired key signed in", status)
	}
	if status, _ := current(sign(key2, "2026-12", "alice", "kept-key")); status != 200 {
		t.Fatal("the new key was refused", status)
	}
	if _, errOut, err := admin("configure-delegation", "-operation-id", "acme-retire-last", "-tenant-id", org.ID, "-issuer", issuer, "-audience", audience,
		"-action", "retire-key", "-key-id", "2026-12", "-confirm", "2026-12", "-authority-socket", authority.socket, "-restore-authority-id", authority.restoreID,
		"-key-authority-id", authority.keyID); err == nil || errOut != "delegation_change_rejected_conflict\n" {
		t.Fatal("the last key was retired", err, errOut)
	}

	if err = api.Process.Signal(syscall.SIGTERM); err != nil {
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
	if strings.Contains(string(output), platform) || strings.Contains(string(output), alice) || strings.Contains(string(output), legacy) {
		t.Fatal("a credential in the API's log")
	}
}
