//go:build linux && cgo

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exercise the CLI entry point, TLS trust, actual HTTP authorization and
// migration-backed single-use semantics in the same journey.
func TestCLIEnrollmentAndContextIsolation(t *testing.T) {
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("set AGENTCAPSULE_TEST_POSTGRES")
	}
	ctx := t.Context()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash := sha256.Sum256([]byte(randomKey()))
	schema := "cli_" + hex.EncodeToString(hash[:8])
	if _, err = db.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlplane.Open(ctx, cfg.ConnString()+" search_path="+schema+",pg_catalog")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	accounts, err := controlplane.NewAccounts(store, bytes.Repeat([]byte{0x35}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	srv, err := api.NewForHost(store, accounts, "cli-test")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(srv)
	defer httpServer.Close()
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", dir)
	ca := filepath.Join(dir, "root.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	proof := "acpe_" + randomKey()
	if err = store.IssuePlatformEnrollment(ctx, "operator-alice", proof, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	invoke := func(input string, args ...string) (string, error) {
		var out, stderr bytes.Buffer
		err := run(ctx, args, strings.NewReader(input), &out, &stderr)
		if strings.Contains(stderr.String()+out.String(), proof) {
			t.Fatal("enrollment proof in CLI output")
		}
		return out.String(), err
	}
	must := func(input string, args ...string) string {
		t.Helper()
		out, err := invoke(input, args...)
		if err != nil {
			t.Fatal(args, err)
		}
		return out
	}
	for _, name := range []string{"wsl", "other"} {
		must("", "context", "add", name, "--url", httpServer.URL, "--ca", ca, "--kind", "platform")
	}
	must("", "context", "use", "wsl")
	must(proof, "login", "--enrollment-file", "-")
	if _, err := invoke(proof, "--context", "other", "login", "--enrollment-file", "-"); err == nil {
		t.Fatal("reused enrollment")
	}
	c, err := loadContext(dir, "wsl")
	if err != nil {
		t.Fatal(err)
	}
	old := c.Token
	must("", "session", "renew")
	if _, err := store.Authenticate(ctx, old); !errors.Is(err, controlplane.ErrAuthentication) {
		t.Fatal("old session still usable", err)
	}
	keyPath, ownerPath := filepath.Join(dir, "owner.pem"), filepath.Join(dir, "owner.json")
	must("", "identity", "create", "--key-file", keyPath, "--display-name", "Alice", "--output-file", ownerPath)
	out := must("", "organization", "create", "--name", "Acme", "--owner-file", ownerPath, "--idempotency-key", "acme")
	var org struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err = json.Unmarshal([]byte(out), &org); err != nil || org.Data.ID == "" {
		t.Fatal(out, err)
	}
	diagnosis := must("", "doctor")
	if strings.Contains(diagnosis, org.Data.ID) || !strings.Contains(diagnosis, "postgresql_version") {
		t.Fatal("diagnostic boundary")
	}
	must("", "context", "add", "acme", "--url", httpServer.URL, "--ca", ca, "--kind", "organization", "--organization", org.Data.ID)
	c, err = loadContext(dir, "wsl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = invoke(c.Token, "--context", "acme", "login", "--token-file", "-"); err == nil {
		t.Fatal("platform credential accepted as an organization")
	}
	must("", "--context", "acme", "login", "--key-file", keyPath)
	current := must("", "--context", "acme", "organization", "current")
	if !strings.Contains(current, "org_owner") || !strings.Contains(current, org.Data.ID) {
		t.Fatal("owner authorization", current)
	}
	must(`{"name":"Support"}`, "--context", "acme", "team", "create", "--file", "-")
	t.Run("dedicated provider key rotation", func(t *testing.T) {
		verifyCLIProviderRotation(t, accounts, org.Data.ID, invoke)
	})
	must("", "--context", "acme", "logout")
	if _, err = invoke("", "--context", "acme", "team", "list"); err == nil {
		t.Fatal("logout retained personal identity")
	}
	stat, err := os.Stat(contextPath(dir, "wsl"))
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("session file permissions", err)
	}
	must("", "logout")
	if _, err = store.Authenticate(ctx, c.Token); !errors.Is(err, controlplane.ErrAuthentication) {
		t.Fatal("logout did not revoke", err)
	}
}

func verifyCLIProviderRotation(t *testing.T, accounts *controlplane.Accounts, tenant string, invoke func(string, ...string) (string, error)) {
	t.Helper()
	dedicated, replacement, shared := randomKey(), randomKey(), randomKey()
	var replaced atomic.Bool
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var want string
		switch r.URL.Path {
		case "/dedicated/v1/models":
			want = dedicated
			if replaced.Load() {
				want = replacement
			}
		case "/shared/v1/models":
			want = shared
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"id":"support"}]}`)
	}))
	defer catalog.Close()
	call := func(input string, args ...string) string {
		t.Helper()
		out, err := invoke(input, append([]string{"--context", "acme"}, args...)...)
		if err != nil {
			t.Fatal(args, err)
		}
		for _, key := range []string{dedicated, replacement, shared} {
			if strings.Contains(out, key) {
				t.Fatal("provider credential in CLI output")
			}
		}
		return out
	}
	register := func(alias, key string) string {
		t.Helper()
		out := call(key, "provider", "create", "--name", alias, "--kind", "openai_compatible",
			"--auth-mode", "secret", "--secret-file", "-", "--base-url", catalog.URL+"/"+alias+"/v1")
		var provider struct{ Data controlplane.LLMProvider }
		if err := json.Unmarshal([]byte(out), &provider); err != nil || provider.Data.ID == "" {
			t.Fatal("missing provider in CLI receipt", err)
		}
		call("", "alias", "create", "--alias", alias, "--provider-id", provider.Data.ID, "--upstream-model", "support")
		return provider.Data.ID
	}
	id := register("dedicated", dedicated)
	register("shared", shared)
	service, err := controlplane.NewLLMService(accounts, llmgateway.NewForTests(llmgateway.Config{}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	probe := func(alias string, status int) {
		t.Helper()
		obs, err := service.Probe(t.Context(), tenant, alias)
		if err != nil || obs.HTTPStatus != status || obs.ModelListed != (status == http.StatusOK) {
			t.Fatalf("%s catalog returned %d, model listed %t, error %v", alias, obs.HTTPStatus, obs.ModelListed, err)
		}
	}
	probe("dedicated", http.StatusOK)
	probe("shared", http.StatusOK)
	replaced.Store(true)
	probe("dedicated", http.StatusUnauthorized)
	probe("shared", http.StatusOK)
	for range 2 {
		call(replacement, "provider", "rotate", id, "--secret-file", "-", "--idempotency-key", "replace-dedicated")
	}
	probe("dedicated", http.StatusOK)
	probe("shared", http.StatusOK)
	var inventory struct {
		Data struct{ Items []controlplane.LLMProvider }
	}
	if err := json.Unmarshal([]byte(call("", "provider", "list")), &inventory); err != nil {
		t.Fatal(err)
	}
	generations := map[string]int64{}
	for _, item := range inventory.Data.Items {
		generations[item.Name] = item.Generation
	}
	if generations["dedicated"] != 2 || generations["shared"] != 1 {
		t.Fatal("unexpected provider generations after retry", generations)
	}
}
