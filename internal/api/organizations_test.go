package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5/pgxpool"
)

func platformForAPI(t *testing.T, s *controlplane.Store) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := "acpp_" + base64.RawURLEncoding.EncodeToString(b)
	if err := s.BootstrapPlatformToken(t.Context(), "api-platform", secret, time.Hour); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestHTTPOrganizationsPlatformBoundaryAndReplay(t *testing.T) {
	server, store, legacy, dsn := apiLab(t)
	platform := platformForAPI(t, store)
	body := `{"name":"Engineering","initial_owner":{"issuer":"https://issuer.example","subject":"alice","display_name":"Alice"}}`
	created := call(t, server, "POST", "/v1/organizations", platform, "create", body)
	if created.Code != 201 {
		t.Fatal("creation status", created.Code)
	}
	var o controlplane.CreateOrganizationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &o); err != nil || o.ID == "" || o.OwnerPrincipalID == "" {
		t.Fatal("creation response", err)
	}
	replay := call(t, server, "POST", "/v1/organizations", platform, "create", body)
	if replay.Code != 201 || !bytes.Equal(created.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("creation replay")
	}
	if r := call(t, server, "POST", "/v1/organizations", platform, "create", strings.Replace(body, "Engineering", "Changed", 1)); r.Code != 422 {
		t.Fatal("conflicting creation", r.Code)
	}
	if r := call(t, server, "GET", "/v1/organizations/"+o.ID, platform, "", ""); r.Code != 200 {
		t.Fatal("get organization", r.Code)
	}
	if r := call(t, server, "GET", "/v1/organizations?limit=1", platform, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), o.ID) {
		t.Fatal("list organization", r.Code)
	}
	for _, c := range []struct {
		method, path, secret, key, body string
		status                          int
	}{
		{"GET", "/v1/organizations", "", "", "", 401},
		{"GET", "/v1/organizations", legacy, "", "", 403},
		{"POST", "/v1/organizations", legacy, "old-service", body, 403},
		{"GET", "/v1/organizations/" + o.ID, legacy, "", "", 403},
		{"POST", "/v1/organizations/" + o.ID + "/disable", legacy, "disable", "{}", 403},
		{"GET", "/v1/users", platform, "", "", 403},
		{"POST", "/v1/users", platform, "legacy-user", `{"display_name":"Other"}`, 403},
		{"GET", "/v1/me", platform, "", "", 403},
		{"GET", "/v1/agents", platform, "", "", 403},
		{"GET", "/v1/agents/missing", platform, "", "", 403},
		{"GET", "/v1/operations/missing", platform, "", "", 403},
		{"GET", "/v1/organizations?limit=201", platform, "", "", 400},
		{"GET", "/v1/organizations/missing", platform, "", "", 404},
		{"POST", "/v1/organizations", platform, "", body, 400},
		{"POST", "/v1/organizations", platform, "unbound", `{"name":"No owner"}`, 400},
		{"POST", "/v1/organizations/" + o.ID + "/disable", platform, "invalid", `{"status":"active"}`, 400},
	} {
		r := call(t, server, c.method, c.path, c.secret, c.key, c.body)
		if r.Code != c.status {
			t.Fatalf("%s %s: status %d want %d", c.method, c.path, r.Code, c.status)
		}
		if strings.Contains(r.Body.String(), platform) || strings.Contains(r.Body.String(), legacy) {
			t.Fatal("credential in HTTP response")
		}
	}
	// An existing personal token gains no platform authority either.
	u := call(t, server, "POST", "/v1/users", legacy, "user", `{"display_name":"Legacy owner"}`)
	var user controlplane.User
	if u.Code != 201 || json.Unmarshal(u.Body.Bytes(), &user) != nil {
		t.Fatal("legacy user setup")
	}
	issued := call(t, server, "POST", "/v1/users/"+user.ID+"/tokens", legacy, "user-token", `{"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)+`"}`)
	var token controlplane.TokenResponse
	if issued.Code != 201 || json.Unmarshal(issued.Body.Bytes(), &token) != nil {
		t.Fatal("legacy token setup")
	}
	if r := call(t, server, "GET", "/v1/organizations", token.Token, "", ""); r.Code != 403 {
		t.Fatal("personal token elevated", r.Code)
	}
	disabled := call(t, server, "POST", "/v1/organizations/"+o.ID+"/disable", platform, "disable", "{}")
	if disabled.Code != 200 || !strings.Contains(disabled.Body.String(), `"status":"disabled"`) {
		t.Fatal("disable organization", disabled.Code)
	}
	again := call(t, server, "POST", "/v1/organizations/"+o.ID+"/disable", platform, "disable", "{}")
	if again.Code != 200 || !bytes.Equal(disabled.Body.Bytes(), again.Body.Bytes()) {
		t.Fatal("disable replay")
	}
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := store.Authenticate(t.Context(), platform)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(t.Context(), "UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1", p.TokenID); err != nil {
		t.Fatal(err)
	}
	if r := call(t, server, "POST", "/v1/organizations", platform, "create", body); r.Code != http.StatusUnauthorized {
		t.Fatal("revoked token replayed receipt", r.Code)
	}
}

func TestPlatformBootstrapCLIPrivateStableFiles(t *testing.T) {
	_, store, _, dsn := apiLab(t)
	dir := t.TempDir()
	binary := filepath.Join(dir, "agentcapsule-admin")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/agentcapsule-admin")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build admin: %v %s", err, output)
	}
	keyFile, tokenFile := filepath.Join(dir, "receipt.key"), filepath.Join(dir, "platform.token")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{0x36}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(success bool) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, "bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", tokenFile, "-platform-account", "cli-platform")
		cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn)
		out, err := cmd.CombinedOutput()
		if success && (err != nil || string(out) != "platform_bootstrap_complete\n") {
			t.Fatalf("bootstrap failed: %v (output withheld)", err)
		}
		if !success && (err == nil || string(out) != "platform_bootstrap_rejected_conflict\n") {
			t.Fatal("bootstrap did not refuse revoked credential as a definite conflict (output withheld)")
		}
	}
	run(true)
	secret, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(tokenFile)
	if err != nil || st.Mode().Perm() != 0600 || len(secret) != 48 {
		t.Fatal("private token file invalid", err)
	}
	p, err := store.Authenticate(t.Context(), string(secret))
	if err != nil || p.Kind != "platform" {
		t.Fatal("platform token unavailable", err)
	}
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var before, after time.Time
	if err = db.QueryRow(t.Context(), "SELECT expires_at FROM platform_credentials WHERE id=$1", p.TokenID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	run(true)
	again, err := os.ReadFile(tokenFile)
	if err != nil || !bytes.Equal(secret, again) {
		t.Fatal("bootstrap replaced secret", err)
	}
	if err = db.QueryRow(t.Context(), "SELECT expires_at FROM platform_credentials WHERE id=$1", p.TokenID).Scan(&after); err != nil || !before.Equal(after) {
		t.Fatal("bootstrap extended expiry", err)
	}
	if _, err = db.Exec(t.Context(), "UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1", p.TokenID); err != nil {
		t.Fatal(err)
	}
	run(false)
}

func TestCredentialCLIListRevokeAndReplaceWithNewFile(t *testing.T) {
	_, store, _, dsn := apiLab(t)
	dir := t.TempDir()
	binary := filepath.Join(dir, "agentcapsule-admin")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/agentcapsule-admin")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build admin: %v %s", err, output)
	}
	keyFile := filepath.Join(dir, "receipt.key")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{0x36}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	admin := func(args ...string) (string, error) {
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	bootstrap := func(tokenFile string) (string, error) {
		return admin("bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", tokenFile, "-platform-account", "cli-platform")
	}
	first, second := filepath.Join(dir, "first.token"), filepath.Join(dir, "second.token")
	if out, err := bootstrap(first); err != nil || out != "platform_bootstrap_complete\n" {
		t.Fatalf("bootstrap failed: %v %q", err, out)
	}
	// A different token file cannot add a second active credential.
	if out, err := bootstrap(second); err == nil || out != "platform_bootstrap_rejected_conflict\n" {
		t.Fatalf("second active credential accepted: %v %q", err, out)
	}
	_ = os.Remove(second)
	secret, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := admin("list-credentials")
	if err != nil || strings.Contains(listing, string(secret)) || !strings.Contains(listing, `"status":"active"`) {
		t.Fatalf("listing wrong or exposes a secret: %v", err)
	}
	var credential struct{ Kind, ID string }
	if err = json.Unmarshal([]byte(strings.SplitN(listing, "\n", 2)[0]), &credential); err != nil || credential.Kind != "platform" || credential.ID == "" {
		t.Fatal("listing is not usable by revoke-credential", err)
	}
	if out, err := admin("revoke-credential", "-kind", "platform", "-id", credential.ID); err != nil || out != "credential_revoked\n" {
		t.Fatalf("revocation failed: %v %q", err, out)
	}
	if _, err = store.Authenticate(t.Context(), string(secret)); err == nil {
		t.Fatal("revoked credential still authenticates")
	}
	// The same file is refused for good; a new file replaces the credential.
	if out, err := bootstrap(first); err == nil || out != "platform_bootstrap_rejected_conflict\n" {
		t.Fatalf("revoked secret was reused: %v %q", err, out)
	}
	if out, err := bootstrap(second); err != nil || out != "platform_bootstrap_complete\n" {
		t.Fatalf("operator is locked out after revocation: %v %q", err, out)
	}
	replacement, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := store.Authenticate(t.Context(), string(replacement)); err != nil || p.Kind != "platform" {
		t.Fatal("replacement credential does not authenticate", err)
	}
	if out, err := admin("revoke-credential", "-kind", "platform", "-id", "ptok_missing"); err == nil || out != "credential_revocation_rejected_not_found\n" {
		t.Fatalf("unknown credential not reported as definite: %v %q", err, out)
	}
}
