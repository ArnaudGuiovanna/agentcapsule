package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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
	_, _, _, dsn := apiLab(t)
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
	// Production requires the authority service (ADR 006): both
	// authorities, standalone, and the service as this account, which is
	// also the API's.
	authority := startAuthorityService(t, dir)
	tokenFile, keyFile := filepath.Join(dir, "platform.token"), filepath.Join(dir, "receipt.key")
	if err = os.WriteFile(keyFile, bytes.Repeat([]byte{0x36}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+dsn)
	bootstrap := func() {
		t.Helper()
		c := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), "bootstrap-platform", "-receipt-key-file", keyFile, "-token-file", tokenFile, "-platform-account", "api-test-platform")
		c.Env = env
		output, err := c.CombinedOutput()
		if err != nil || string(output) != "platform_bootstrap_complete\n" {
			t.Fatalf("bootstrap failed: %v (secret output withheld)", err)
		}
	}
	bootstrap()
	bootstrap()
	secret, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := string(secret)
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
	if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	metricsAddress := l.Addr().String()
	_ = l.Close()
	// Production: HTTPS only, with a certificate for the loopback address.
	certFile, certKeyFile := filepath.Join(dir, "api.crt"), filepath.Join(dir, "api.key")
	first := writeServerCertificate(t, certFile, certKeyFile)
	roots := x509.NewCertPool()
	roots.AddCert(first)
	log, err := os.Create(filepath.Join(dir, "api.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-api"), "-listen", address, "-receipt-key-file", keyFile, "-host-id", "local",
		"-transit-active-key", "v1", "-transit-key", "v1="+transitKey, "-metrics-listen", metricsAddress,
		"-tls-cert", certFile, "-tls-key", certKeyFile, "-tls-server-name", "127.0.0.1",
		"-authority-socket", authority.socket, "-restore-authority-id", authority.restoreID, "-key-authority-id", authority.keyID)
	cmd.Env = append(env, "AGENTCAPSULE_MODE=")
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
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-done:
			finished = true
			t.Fatalf("API exited before ready: %v", err)
		default:
		}
		r, err := client.Get("https://" + address + "/v1/health/ready")
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
	// The readiness probe reports the authority service: its mode while it
	// answers, 503 while it does not; the API reaches it again once it
	// restarts.
	readiness := func() (int, map[string]any) {
		t.Helper()
		r, err := client.Get("https://" + address + "/v1/health/ready")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var body map[string]any
		if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return r.StatusCode, body
	}
	if code, body := readiness(); code != 200 || body["status"] != "ready" || body["authority"] != "standalone" {
		t.Fatal("readiness with the authority service", code, body)
	}
	authority.stop(t)
	if code, body := readiness(); code != 503 || body["code"] != "authority_unavailable" {
		t.Fatal("readiness without the authority service", code, body)
	}
	authority.start(t)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if code, body := readiness(); code == 200 && body["authority"] == "standalone" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the API did not reach its restarted authority service")
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+address+"/v1/organizations", strings.NewReader(`{"name":"Process organization","initial_owner":{"issuer":"https://issuer.example","subject":"process-owner","display_name":"Process owner"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "process-organization")
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatal("real API creation", r.StatusCode)
	}
	created := r.Header.Get("X-Request-ID")
	// Metrics on their own loopback listener (OPS-02), by route pattern.
	m, err := client.Get("http://" + metricsAddress + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	exposition, _ := io.ReadAll(m.Body)
	m.Body.Close()
	if m.StatusCode != 200 || !strings.Contains(string(exposition), `agentcapsule_api_requests_total{route="/v1/organizations",method="POST",status_class="2xx"} 1`) {
		t.Fatal("metrics", m.StatusCode, string(exposition))
	}
	// Clear text reaches no route: the TLS listener answers it with a refusal.
	if r, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/v1/health/ready"); err == nil {
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatal("clear text served", r.StatusCode)
		}
	}
	// A renewed certificate is served after SIGHUP, to new connections.
	second := writeServerCertificate(t, certFile, certKeyFile)
	if err = cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	served := func() *big.Int {
		conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) // only to read the certificate
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber
	}
	for deadline := time.Now().Add(10 * time.Second); served().Cmp(second.SerialNumber) != 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the renewed certificate is not served after SIGHUP")
		}
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
	if strings.Contains(string(output), token) || strings.Contains(string(output), "Process owner") || strings.Contains(string(output), dsn) {
		t.Fatal("sensitive data in process log")
	}
	// The request's event carries the X-Request-ID its response gave.
	if !strings.Contains(string(output), `"event":"http_request","request_id":"`+created+`","route":"/v1/organizations","method":"POST","status":201`) {
		t.Fatal("no event for the request", string(output))
	}
}

// authorityService is agentcapsule-authority serve, standalone, as the API's
// account: the API socket admits it.
type authorityService struct {
	dir, config, socket, restoreID, keyID string
	process                               *exec.Cmd
	done                                  chan error
}

// flags are those that reach the service's API socket, as the API and
// agentcapsule-admin take them.
func (a *authorityService) flags() []string {
	return []string{"-authority-socket", a.socket, "-restore-authority-id", a.restoreID, "-key-authority-id", a.keyID}
}

// startAuthorityService initializes both authorities with agentcapsule-admin
// and starts the service built in dir, its sockets in a short directory.
func startAuthorityService(t *testing.T, dir string) *authorityService {
	t.Helper()
	admin := func(args ...string) map[string]string {
		t.Helper()
		c := exec.CommandContext(t.Context(), filepath.Join(dir, "agentcapsule-admin"), args...)
		output, err := c.Output()
		var ids map[string]string
		if err != nil || json.Unmarshal(output, &ids) != nil {
			t.Fatalf("agentcapsule-admin %s: %v %s", args[0], err, output)
		}
		return ids
	}
	keyRoot, restoreRoot := filepath.Join(dir, "key-authority"), filepath.Join(dir, "restore-authority")
	for _, root := range []string{keyRoot, restoreRoot} {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyID := admin("init-key-authority", "-root", keyRoot)["authority_id"]
	restoreID := admin("init-restore-authority", "-root", restoreRoot, "-data-root", filepath.Join(dir, "host"),
		"-key-authority-root", keyRoot, "-key-authority-id", keyID)["authority_id"]
	sockets, err := os.MkdirTemp("", "acapi-") // a socket path has at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	a := &authorityService{dir: dir, config: filepath.Join(dir, "authority.json"), socket: filepath.Join(sockets, "api.sock"),
		restoreID: restoreID, keyID: keyID}
	config := fmt.Sprintf(`{"version":2,"role":"primary","key_authority":{"root":%q,"identity":%q},`+
		`"restore_authority":{"root":%q,"identity":%q},"worker_socket":%q,"api_socket":%q,"api_uid":%d}`,
		keyRoot, keyID, restoreRoot, restoreID, filepath.Join(sockets, "worker.sock"), a.socket, os.Getuid())
	if err = os.WriteFile(a.config, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	a.start(t)
	t.Cleanup(func() {
		if a.process != nil {
			_ = a.process.Process.Kill()
			<-a.done
		}
	})
	return a
}

func (a *authorityService) start(t *testing.T) {
	t.Helper()
	a.process = exec.Command(filepath.Join(a.dir, "agentcapsule-authority"), "serve", "-config", a.config)
	if err := a.process.Start(); err != nil {
		t.Fatal(err)
	}
	a.done = make(chan error, 1)
	go func(p *exec.Cmd, done chan error) { done <- p.Wait() }(a.process, a.done)
}

// stop ends the service with SIGTERM, as systemd stops it.
func (a *authorityService) stop(t *testing.T) {
	t.Helper()
	if err := a.process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.done:
		if err != nil {
			t.Fatal("the authority service did not stop cleanly", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the authority service did not stop")
	}
	a.process = nil
}

// writeServerCertificate replaces the API's certificate files with a new
// self-signed certificate for 127.0.0.1 and returns it.
func writeServerCertificate(t *testing.T, certFile, keyFile string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "agentcapsule-api"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, block := range map[string]*pem.Block{certFile: {Type: "CERTIFICATE", Bytes: der}, keyFile: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		mode := os.FileMode(0o644)
		if path == keyFile {
			mode = 0o600
		}
		// A new file renamed into place, as a renewal tool does.
		next := path + ".next"
		if err = os.WriteFile(next, pem.EncodeToMemory(block), mode); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(next, path); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
