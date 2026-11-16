//go:build linux && cgo

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// authorities initializes both authorities, standalone, in a new directory.
func authorities(t *testing.T) (*keyauthority.Files, *restoreauthority.Catalog) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	return keys, catalog
}

// socketDir is a short private directory: a socket path has at most 107
// bytes.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "acapi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serve runs the authority service on keys and catalog until the test ends,
// with its sockets in dir. This test's account is the API's, and the
// worker socket admits it too, so that a hello reaches the role check.
func serve(t *testing.T, dir string, keys *keyauthority.Files, catalog *restoreauthority.Catalog) {
	t.Helper()
	uid := uint32(os.Getuid())
	server, err := svc.New(t.Context(), svc.Config{Catalog: catalog, Keys: keys, WorkerUID: uid, APIUID: uid})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := svc.Listen(filepath.Join(dir, "worker.sock"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	api, err := svc.Listen(filepath.Join(dir, "api.sock"), 0660)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var served sync.WaitGroup
	served.Go(func() {
		if err := server.Serve(ctx, worker, api); !errors.Is(err, context.Canceled) {
			t.Error("the authority service stopped", err)
		}
	})
	t.Cleanup(func() { cancel(); served.Wait() })
}

// productionStart is a production configuration that passes every check
// before the authority service: HTTPS, and PostgreSQL on a Unix socket
// that does not exist, so that a start that gets past the service stops at
// the database.
func productionStart(t *testing.T) []string {
	t.Helper()
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	receipt := filepath.Join(dir, "receipt.key")
	if err := os.WriteFile(receipt, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := certificate(t, dir, time.Now().Add(24*time.Hour))
	t.Setenv("AGENTCAPSULE_MODE", "")
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "host="+filepath.Join(dir, "no-postgresql")+" dbname=agentcapsule")
	return []string{"-receipt-key-file", receipt, "-host-id", "local", "-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key}
}

func authorityArgs(socket, restoreID, keyID string) []string {
	return []string{"-authority-socket", socket, "-restore-authority-id", restoreID, "-key-authority-id", keyID}
}

// ADR 006, wave 4: the API never talks to another installation's
// authorities. It refuses them at start, at once and before it opens the
// database, as it refuses the worker's socket.
func TestAPIRefusesAnotherInstallationsAuthority(t *testing.T) {
	keys, catalog := authorities(t)
	dir := socketDir(t)
	serve(t, dir, keys, catalog)
	api := filepath.Join(dir, "api.sock")
	base := productionStart(t)
	for _, c := range []struct {
		name, socket, restoreID, keyID, want string
	}{
		{"another restore authority", api, "restoreauth_" + strings.Repeat("0", 32), keys.Identity(), "authority_identity_mismatch"},
		{"another key authority", api, catalog.Identity(), "keyauth_" + strings.Repeat("0", 32), "authority_identity_mismatch"},
		{"the worker socket", filepath.Join(dir, "worker.sock"), catalog.Identity(), keys.Identity(), "authority_socket_role_mismatch"},
		{"its own authorities", api, catalog.Identity(), keys.Identity(), "database_initialization_failed"},
	} {
		start := time.Now()
		out, code := command(t, append(append([]string{}, base...), authorityArgs(c.socket, c.restoreID, c.keyID)...)...)
		if code != 1 || out != c.want+"\n" {
			t.Errorf("%s: %d %q, want %s", c.name, code, out, c.want)
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("%s: the refusal took %s", c.name, time.Since(start))
		}
	}
}

// Production requires the authority service (ADR 006, answer 3(a));
// development may run without it, and says so at every start.
func TestAPIRequiresTheAuthorityServiceInProduction(t *testing.T) {
	keys, catalog := authorities(t)
	base := productionStart(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "authority_required_in_production"},
		{[]string{"-authority-socket", "/run/agentcapsule-authority/api.sock"}, "configuration_required"},
		{[]string{"-restore-authority-id", catalog.Identity(), "-key-authority-id", keys.Identity()}, "configuration_required"},
		{authorityArgs("api.sock", catalog.Identity(), keys.Identity()), "authority_configuration_invalid"},
		{authorityArgs("/run/agentcapsule-authority/api.sock", keys.Identity(), catalog.Identity()), "authority_configuration_invalid"},
	} {
		out, code := command(t, append(append([]string{}, base...), c.args...)...)
		if code != 1 || out != c.want+"\n" {
			t.Errorf("%v: %d %q, want %s", c.args, code, out, c.want)
		}
	}
	t.Setenv("AGENTCAPSULE_MODE", "development")
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "host="+filepath.Join(t.TempDir(), "no-postgresql")+" dbname=agentcapsule")
	out, code := command(t, "-receipt-key-file", base[1], "-host-id", "local", "-listen", "127.0.0.1:0")
	if code != 1 || out != "development_mode_clear_text_allowed_never_use_in_production\n"+withoutAuthority+"\ndatabase_initialization_failed\n" {
		t.Fatalf("development without the authority service: %d %q", code, out)
	}
}

// A service that does not answer yet is waited for, and the API says so
// once; then it starts (here, up to its database).
func TestAPIWaitsForTheAuthorityService(t *testing.T) {
	keys, catalog := authorities(t)
	dir := socketDir(t)
	args := append(productionStart(t), authorityArgs(filepath.Join(dir, "api.sock"), catalog.Identity(), keys.Identity())...)
	type result struct {
		out  string
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		out, code, err := capture(args...)
		done <- result{out, code, err}
	}()
	time.Sleep(time.Second)
	select {
	case r := <-done:
		t.Fatal("the API did not wait for its authority service", r)
	default:
	}
	serve(t, dir, keys, catalog)
	var r result
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the API did not reach its authority service")
	}
	lines := strings.Split(strings.TrimSuffix(r.out, "\n"), "\n")
	if r.err != nil || r.code != 1 || len(lines) != 2 || !strings.Contains(lines[0], `"event":"authority_service_waiting"`) || lines[1] != "database_initialization_failed" {
		t.Fatalf("%d %q", r.code, r.out)
	}
}

// The preflight asks the authority service once, and says what to fix.
func TestPreflightReachesTheAuthorityService(t *testing.T) {
	keys, catalog := authorities(t)
	dir := socketDir(t)
	serve(t, dir, keys, catalog)
	api := filepath.Join(dir, "api.sock")
	base := append(productionStart(t), "-preflight")
	check := func(args []string, want ...string) {
		t.Helper()
		out, _ := command(t, append(append([]string{}, base...), args...)...)
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("missing %q in:\n%s", w, out)
			}
		}
	}
	check(authorityArgs(api, catalog.Identity(), keys.Identity()), "ok   authority: the authority service answers with the pinned identities; standalone")
	check(authorityArgs(api, "restoreauth_"+strings.Repeat("0", 32), keys.Identity()), "fail authority: the service on "+api+" holds other authorities")
	check(authorityArgs(filepath.Join(dir, "worker.sock"), catalog.Identity(), keys.Identity()), "fail authority: "+filepath.Join(dir, "worker.sock")+" is not the service's API socket")
	check(authorityArgs(filepath.Join(dir, "missing.sock"), catalog.Identity(), keys.Identity()), "fail authority: the authority service does not answer")
	check(nil, "fail authority: no -authority-socket: production needs the authority service", "     fix: give -authority-socket")
	if err := os.Chmod(api, 0); err != nil {
		t.Fatal(err)
	}
	check(authorityArgs(api, catalog.Identity(), keys.Identity()), "fail authority: this account may not open "+api, "agentcapsule-authority-clients")
	t.Setenv("AGENTCAPSULE_MODE", "development")
	check(nil, "warn authority: no authority service (development)")
}
