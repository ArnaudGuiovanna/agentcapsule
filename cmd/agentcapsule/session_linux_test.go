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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
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
	out := must(`{"name":"Acme","initial_owner":{"issuer":"https://id.acme.test","subject":"alice","display_name":"Alice"}}`, "organization", "create", "--file", "-", "--idempotency-key", "acme")
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
	stat, err := os.Stat(contextPath(dir, "wsl"))
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("session file permissions", err)
	}
	must("", "logout")
	if _, err = store.Authenticate(ctx, c.Token); !errors.Is(err, controlplane.ErrAuthentication) {
		t.Fatal("logout did not revoke", err)
	}
}
