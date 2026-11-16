//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func command(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, argv := os.Stdout, os.Stderr, os.Args
	os.Stdout, os.Stderr, os.Args = w, w, append([]string{"agentcapsule-admin"}, args...)
	code := run()
	os.Stdout, os.Stderr, os.Args = stdout, stderr, argv
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// The administration tool reaches PostgreSQL under the same rule as the
// services: in production, a Unix socket or verified TLS.
func TestAdminRefusesAClearTextDatabaseInProduction(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT", "PGCONNECT_TIMEOUT"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	args := []string{"bootstrap-platform", "-receipt-key-file", filepath.Join(dir, "receipt.key"), "-token-file", filepath.Join(dir, "token")}
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "host=127.0.0.1 port=1 dbname=agentcapsule connect_timeout=2")
	t.Setenv("AGENTCAPSULE_MODE", "")
	if out, code := command(t, args...); code != 1 || out != "database_tls_required_in_production\n" {
		t.Fatalf("%d %q", code, out)
	}
	for _, sub := range []string{"list-credentials", "activate-transit-keys"} {
		if out, _ := command(t, sub); out != "database_tls_required_in_production\n" && out != "configuration_required\n" {
			t.Errorf("%s: %q", sub, out)
		}
	}
	// Development lets it try, and says so; nothing listens on port 1.
	t.Setenv("AGENTCAPSULE_MODE", "development")
	if out, code := command(t, args...); code != 1 || out != "development_mode_clear_text_allowed_never_use_in_production\ndatabase_initialization_failed\n" {
		t.Fatalf("%d %q", code, out)
	}
	t.Setenv("AGENTCAPSULE_MODE", "prod")
	if out, _ := command(t, args...); out != "mode_invalid\n" {
		t.Fatalf("%q", out)
	}
}
