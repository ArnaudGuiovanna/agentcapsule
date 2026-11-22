//go:build linux && cgo

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// captured runs fn with standard output and error going to one pipe, and
// returns what it wrote without the final newline.
func captured(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()
	code := fn()
	os.Stdout, os.Stderr = stdout, stderr
	w.Close()
	out := <-done
	r.Close()
	return strings.TrimSpace(string(out)), code
}

// command runs the worker's entry point with args, on a fresh flag set.
func command(t *testing.T, args ...string) (string, int) {
	t.Helper()
	return captured(t, func() int {
		argv, set := os.Args, flag.CommandLine
		defer func() { os.Args, flag.CommandLine = argv, set }()
		os.Args = append([]string{"agentcapsule-worker"}, args...)
		flag.CommandLine = flag.NewFlagSet("agentcapsule-worker", flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		return run()
	})
}

// The restore test and the garbage collection take only their own flags,
// and are refused before the configuration is read when they are mixed
// with another mode.
func TestOperatorModesTakeOnlyTheirFlags(t *testing.T) {
	t.Setenv("AGENTCAPSULE_MODE", "")
	missing := filepath.Join(t.TempDir(), "worker.json")
	agent := "agt_" + strings.Repeat("a", 32)
	test := []string{"-config", missing, "-test-restore", agent, "-archive-root", "/var/lib/a", "-scratch", "/var/lib/s"}
	for want, cases := range map[string][][]string{
		"restore_test_configuration_invalid": {
			{"-config", missing, "-test-restore", agent},
			{"-config", missing, "-test-restore", agent, "-archive-root", "/var/lib/a"},
			{"-config", missing, "-test-restore", agent, "-archive-root", "/var/lib/a", "-scratch", "relative"},
			append(test, "-restore-agent", agent),
			append(test, "-restore-host", "lost"),
			append(test, "-archive-agent", agent),
			append(test, "-archive-id", "arc_bad"),
			append(test, "-collect-garbage"),
			append(test, "-preflight"),
			{"-config", missing, "-scratch", "/var/lib/s"},
		},
		"collect_garbage_configuration_invalid": {
			{"-config", missing, "-collect-garbage", "-archive-root", "/var/lib/a"},
			{"-config", missing, "-collect-garbage", "-restore-agent", agent},
			{"-config", missing, "-dry-run"},
			{"-config", missing, "-confirm", "host"},
		},
		"archive_fetch_configuration_invalid": {
			append(test, "-archive-fetch", "relative.py"),
		},
		"configuration_invalid": {
			test,
			append(test, "-archive-fetch", "/opt/agentcapsule/agentcapsule-archive-ship.py", "-archive-id", "arc_"+strings.Repeat("1", 32)),
			{"-config", missing, "-collect-garbage", "-dry-run"},
			{"-config", missing, "-collect-garbage", "-confirm", "host"},
		},
	} {
		for _, args := range cases {
			if out, code := command(t, args...); code != 1 || out != want {
				t.Errorf("%v: %q %d, want %s", args, out, code, want)
			}
		}
	}
}

// operationsDatabase is a migrated schema of its own, reached through
// AGENTCAPSULE_DATABASE_URL as the worker reaches its database.
func operationsDatabase(t *testing.T) (*controlplane.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	schema := "worker_cmd_" + hex.EncodeToString(id)
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTCAPSULE_DATABASE_URL", scoped)
	t.Setenv("AGENTCAPSULE_MODE", "")
	return s, db
}

// operationsConfig is a product worker's configuration, its roots under dir.
func operationsConfig(t *testing.T, dir, socket, restoreID, keyID string) worker.ServiceConfig {
	t.Helper()
	image := worker.ServiceImage{Path: "/opt/agentcapsule/firecracker", SHA256: strings.Repeat("0", 64)}
	return worker.ServiceConfig{Version: 1, HostID: "gc-host", Root: filepath.Join(dir, "runtime"), Firecracker: image, Jailer: image, Kernel: image,
		Initrd: image, MaxActive: 1, BootTimeout: "30s", BootLease: "2m", PollInterval: "30s", AttemptTimeout: "45s",
		Authority:    &worker.ServiceAuthority{Socket: socket, RestoreAuthorityID: restoreID, KeyAuthorityID: keyID},
		Provisioning: &worker.ProvisioningConfig{FirstUID: 20000, LastUID: 20100},
		Archives:     &worker.ServiceArchives{Root: filepath.Join(dir, "archives"), Keep: 1},
		Registry:     &worker.ServiceRegistry{Cache: filepath.Join(dir, "releases")}}
}

// The garbage collection on demand takes the guards of the operator's
// destructive commands (ADR 014 §7): without -confirm naming the host it
// removes nothing and opens no connection; -dry-run prints what it would
// remove and records nothing; a run prints what it removed and is audited
// in operator_audit, done, then unchanged when nothing is left.
func TestGarbageCollectionCommandIsConfirmedDryRunAndAudited(t *testing.T) {
	s, _ := operationsDatabase(t)
	dir := t.TempDir()
	c := operationsConfig(t, dir, "/run/agentcapsule-authority/worker.sock", "restoreauth_"+strings.Repeat("a", 32), "keyauth_"+strings.Repeat("b", 32))
	if _, _, _, err := c.Settings(); err != nil {
		t.Fatal("the test's configuration", err)
	}
	// What interrupted removals and downloads left, untouched for hours.
	old := time.Now().Add(-3 * time.Hour)
	leftovers := []string{filepath.Join(c.Archives.Root, ".removed-0123"), filepath.Join(c.Registry.Cache, ".staging", "crashed")}
	for _, p := range leftovers {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "data"), make([]byte, 512), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{filepath.Join(p, "data"), p} {
			if err := os.Chtimes(q, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(c.Archives.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	audited := func() []controlplane.OperatorAuditEvent {
		t.Helper()
		events, err := s.ListOperatorAudit(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		var gc []controlplane.OperatorAuditEvent
		for _, e := range events {
			if e.Action == "garbage.collected" {
				gc = append(gc, e)
			}
		}
		return gc
	}
	present := func() int {
		n := 0
		for _, p := range leftovers {
			if _, err := os.Stat(p); err == nil {
				n++
			}
		}
		return n
	}
	for _, confirm := range []string{"", "other-host"} {
		if out, code := captured(t, func() int { return collectGarbage(c, operatorconfig.Production, false, confirm) }); code != 1 || out != "confirmation_required" {
			t.Fatal("ran without its confirmation", confirm, out, code)
		}
	}
	if present() != 2 || len(audited()) != 0 {
		t.Fatal("an unconfirmed collection changed or recorded something")
	}
	type outcome struct {
		controlplane.OperatorOutcome
		worker.GarbageReport
	}
	var dry outcome
	out, code := captured(t, func() int { return collectGarbage(c, operatorconfig.Production, true, "") })
	if code != 0 || json.Unmarshal([]byte(out), &dry) != nil || !dry.DryRun || dry.Outcome != "done" || dry.Target != "gc-host" ||
		dry.Action != "garbage.collected" || dry.Archives == nil || dry.Archives.Leftovers != 1 || dry.Images == nil || dry.Images.Leftovers != 1 {
		t.Fatal("dry run", out, code)
	}
	if present() != 2 || len(audited()) != 0 {
		t.Fatal("a dry run removed or recorded something")
	}
	var done outcome
	out, code = captured(t, func() int { return collectGarbage(c, operatorconfig.Production, false, "gc-host") })
	if code != 0 || json.Unmarshal([]byte(out), &done) != nil || done.DryRun || done.Outcome != "done" || done.Archives.Bytes != 512 || done.Images.Bytes != 512 {
		t.Fatal("collection", out, code)
	}
	if present() != 0 {
		t.Fatal("the leftovers stayed")
	}
	out, code = captured(t, func() int { return collectGarbage(c, operatorconfig.Production, false, "gc-host") })
	if code != 0 || !strings.Contains(out, `"outcome":"unchanged"`) {
		t.Fatal("second collection", out, code)
	}
	events := audited()
	if len(events) != 2 || events[0].Target != "gc-host" || !strings.HasPrefix(events[0].Actor, "local-uid:") {
		t.Fatal("operator audit", events)
	}
	outcomes := map[string]bool{events[0].Outcome: true, events[1].Outcome: true}
	if !outcomes["done"] || !outcomes["unchanged"] {
		t.Fatal("operator audit outcomes", events)
	}
}

// The restore test command reaches the authority service and PostgreSQL as
// the worker does, and refuses a scratch directory inside the runtime root,
// an archive root that does not exist (it creates none) and an agent this
// host does not hold. The test itself is in internal/worker.
func TestRestoreTestCommandRefusesBeforeItReads(t *testing.T) {
	operationsDatabase(t)
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	server, err := authorityservice.New(t.Context(), authorityservice.Config{Catalog: catalog, Keys: keys,
		WorkerUID: uint32(os.Getuid()), APIUID: uint32(os.Getuid()) + 1, Started: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := os.MkdirTemp("/tmp", "acwc-") // a socket path has at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockets, "worker.sock")
	listener, err := authorityservice.Listen(socket, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener, nil) }()
	t.Cleanup(func() {
		cancel()
		<-served
		catalog.Close()
		os.RemoveAll(sockets)
	})
	c := operationsConfig(t, dir, socket, catalog.Identity(), keys.Identity())
	archives, scratch := filepath.Join(dir, "archives"), filepath.Join(dir, "scratch")
	agent := "agt_" + strings.Repeat("c", 32)
	testRestoreOf := func(archiveRoot, scratch string) (string, int) {
		return captured(t, func() int { return testRestore(c, operatorconfig.Production, agent, "", archiveRoot, scratch, "") })
	}
	if out, code := testRestoreOf(archives, filepath.Join(c.Root, "scratch")); code != 1 || out != "archive_domain_overlap" {
		t.Fatal("a scratch directory inside the runtime root", out, code)
	}
	if out, code := testRestoreOf(archives, scratch); code != 1 || out != "archive_storage_unavailable" {
		t.Fatal("a missing archive root", out, code)
	}
	if _, err = os.Stat(archives); !os.IsNotExist(err) {
		t.Fatal("the restore test created the archive root", err)
	}
	for _, d := range []string{archives, scratch} {
		if err = os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := testRestoreOf(archives, scratch); code != 1 || out != "restore_test_failed_state" {
		t.Fatal("an agent this host does not hold", out, code)
	}
	if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
		t.Fatal("the scratch directory is not empty", left, err)
	}
	if _, err = os.Stat(c.Root); !os.IsNotExist(err) {
		t.Fatal("the restore test created the runtime root", err)
	}
}
