package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func apiLab(t *testing.T) (*Server, *controlplane.Store, string, string) {
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
	schema := "api_" + hex.EncodeToString(id)
	if _, err = root.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		root.Close()
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	testDSN := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := root.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
		root.Close()
	})
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	a, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHost(s, a, "local")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "api-test-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return server, s, secret, testDSN
}
func call(t *testing.T, s *Server, method, path, token, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if len(w.Header().Get("X-Request-ID")) != 32 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing response boundary headers")
	}
	return w
}
func TestHTTPAccountsAndRoleBoundary(t *testing.T) {
	server, store, admin, _ := apiLab(t)
	created := call(t, server, "POST", "/v1/users", admin, "create", `{"display_name":"Arnaud"}`)
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	var user controlplane.User
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	replay := call(t, server, "POST", "/v1/users", admin, "create", `{"display_name":"Arnaud"}`)
	if replay.Code != 201 || replay.Body.String() != created.Body.String() || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("HTTP replay differs")
	}
	conflict := call(t, server, "POST", "/v1/users", admin, "create", `{"display_name":"Marc"}`)
	if conflict.Code != 422 {
		t.Fatal("missing idempotency conflict", conflict.Code)
	}
	body := fmt.Sprintf(`{"expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	issued := call(t, server, "POST", "/v1/users/"+user.ID+"/tokens", admin, "token", body)
	if issued.Code != 201 {
		t.Fatal(issued.Code, issued.Body.String())
	}
	var token controlplane.TokenResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	me := call(t, server, "GET", "/v1/me", token.Token, "", "")
	if me.Code != 200 || !strings.Contains(me.Body.String(), user.ID) {
		t.Fatal("owner profile missing")
	}
	for _, c := range []struct {
		method, path, token, key, body string
		want                           int
	}{
		{"GET", "/v1/me", admin, "", "", 403},
		{"GET", "/v1/users", token.Token, "", "", 403},
		{"POST", "/v1/users", token.Token, "new", `{"display_name":"x"}`, 403},
		{"POST", "/v1/users/" + user.ID + "/tokens", token.Token, "other", body, 403},
		{"GET", "/v1/me", "", "", "", 401},
		{"POST", "/v1/users", admin, "", `{"display_name":"x"}`, 400},
		{"POST", "/v1/users", admin, "unknown", `{"display_name":"x","role":"admin"}`, 400},
		{"POST", "/v1/users", admin, "double", `{"display_name":"x"}{}`, 400},
		{"POST", "/v1/users", admin, "large", `{"display_name":"` + strings.Repeat("x", 70000) + `"}`, 413},
		{"PUT", "/v1/me", token.Token, "", "", 405},
		{"GET", "/v1/missing", token.Token, "", "", 404},
		{"GET", "/v1/users?limit=900", admin, "", "", 400},
	} {
		r := call(t, server, c.method, c.path, c.token, c.key, c.body)
		if r.Code != c.want || r.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("%s %s got %d want %d", c.method, c.path, r.Code, c.want)
		}
		if strings.Contains(r.Body.String(), token.Token) || strings.Contains(r.Body.String(), admin) {
			t.Fatal("credential leaked in problem")
		}
	}
	p, err := store.Authenticate(t.Context(), token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeToken(t.Context(), p, p.TokenID); err != nil {
		t.Fatal(err)
	}
	if r := call(t, server, "GET", "/v1/me", token.Token, "", ""); r.Code != 401 {
		t.Fatal("revoked token accepted")
	}
	if r := call(t, server, "GET", "/v1/health/ready", "", "", ""); r.Code != 200 {
		t.Fatal("ready failed")
	}
}

func TestHTTPRejectsAmbiguousCredentialsAndPaths(t *testing.T) {
	s, _, token, _ := apiLab(t)
	for _, path := range []string{"/v1/me", "/v1//me", "/v1/users/abc%2fdef/tokens"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Add("Authorization", "Bearer "+token)
		r.Header.Add("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 401 && w.Code != 400 {
			t.Fatal("ambiguous input accepted", w.Code)
		}
	}
}

func TestAPIBinariesBootstrapServeAndShutdown(t *testing.T) {
	_, _, token, dsn := apiLab(t)
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
	tokenFile, keyFile := filepath.Join(dir, "admin.token"), filepath.Join(dir, "receipt.key")
	if err = os.WriteFile(keyFile, bytes.Repeat([]byte{0x36}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn)
	bootstrap := func() {
		t.Helper()
		c := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), "bootstrap", "-receipt-key-file", keyFile, "-token-file", tokenFile, "-service-account", "api-test-admin")
		c.Env = env
		output, err := c.CombinedOutput()
		if err != nil || string(output) != "bootstrap_complete\n" {
			t.Fatalf("bootstrap failed: %v (secret output withheld)", err)
		}
	}
	bootstrap()
	bootstrap()
	transitKey := filepath.Join(dir, "transit.key")
	if err = os.WriteFile(transitKey, bytes.Repeat([]byte{0x74}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), "activate-transit-keys", "-active-key", "v1", "-key", "v1="+transitKey)
		c.Env = env
		output, err := c.CombinedOutput()
		if err != nil || string(output) != "transit_keys_activated\n" {
			t.Fatalf("transit activation failed: %v (output withheld)", err)
		}
	}
	artifact := filepath.Join(dir, "approved.initrd")
	if err = os.WriteFile(artifact, []byte("CLI approval fixture, not a guest image"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"configure-host", "-host-id", "local", "-storage-mib", "256"}, {"approve-local-harness", "-name", "reference", "-version", "1.0.0", "-artifact", artifact}} {
		for range 2 {
			c := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), args...)
			c.Env = env
			output, err := c.CombinedOutput()
			if err != nil || string(output) != "catalog_configuration_complete\n" {
				t.Fatalf("catalog CLI: %v %s", err, output)
			}
		}
	}
	// Pick an isolated listener; the tiny close/start race is handled by the
	// startup assertion rather than by connecting to any preexisting process.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	log, err := os.Create(filepath.Join(dir, "api.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-api"), "-listen", address, "-receipt-key-file", keyFile, "-host-id", "local", "-transit-active-key", "v1", "-transit-key", "v1="+transitKey)
	cmd.Env = env
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
			t.Fatalf("API exited before ready: %v", err)
		default:
		}
		r, err := client.Get("http://" + address + "/v1/health/ready")
		if err == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("API did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+address+"/v1/users", strings.NewReader(`{"display_name":"Process user"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "process-user")
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatal("real API creation", r.StatusCode)
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal("shutdown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("shutdown stuck")
	}
	output, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), token) || strings.Contains(string(output), "Process user") || strings.Contains(string(output), dsn) {
		t.Fatal("sensitive data in process log")
	}
}
