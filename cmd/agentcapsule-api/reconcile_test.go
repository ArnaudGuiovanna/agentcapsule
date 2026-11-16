//go:build linux && cgo

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// promotedAuthorities are both authorities of a standby after a failover:
// a primary's replica, promoted to epoch 2.
func promotedAuthorities(t *testing.T) (*keyauthority.Files, *restoreauthority.Catalog) {
	t.Helper()
	ctx := t.Context()
	dir := t.TempDir()
	keys, catalog := authorities(t)
	text, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := authoritylog.ParseUnlockKey(text)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = catalog.Snapshot(ctx, keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(ctx, filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	replica.Close()
	p, err := restoreauthority.Promote(ctx, filepath.Join(dir, "replica"), filepath.Join(dir, "promoted-restore"), filepath.Join(dir, "promoted-keys"), unlock)
	if err != nil || p.Epoch != 2 {
		t.Fatal(p, err)
	}
	promotedKeys, err := keyauthority.Open(filepath.Join(dir, "promoted-keys"), p.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := restoreauthority.Open(ctx, filepath.Join(dir, "promoted-restore"), p.RestoreAuthority, p.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { promoted.Close() })
	return promotedKeys, promoted
}

// database is a migrated schema of the test PostgreSQL, bound to the
// receipt key productionStart writes.
func database(t *testing.T) (*controlplane.Store, string) {
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
	schema := "apicmd_" + hex.EncodeToString(id)
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
	t.Cleanup(func() {
		s.Close()
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
	accounts, err := controlplane.NewAccounts(s, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s, scoped
}

// restoreWitnessEarlyOpenGuard, at the API's start (ADR 006 §7,
// REPLAY_FIRST): on the authority service of a promoted standby, epoch 2,
// the API refuses to start until agentcapsule-admin reconcile has recorded
// that epoch; then it starts (here, up to a listener already taken).
func TestAPIRefusesToOpenBeforeTheReconciliation(t *testing.T) {
	s, dsn := database(t)
	keys, catalog := promotedAuthorities(t)
	dir := socketDir(t)
	serve(t, dir, keys, catalog)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	base := productionStart(t)
	t.Setenv("AGENTCAPSULE_DATABASE_URL", dsn)
	for i, arg := range base {
		if arg == "-listen" {
			base[i+1] = busy.Addr().String()
		}
	}
	socket := filepath.Join(dir, "api.sock")
	args := append(base, authorityArgs(socket, catalog.Identity(), keys.Identity())...)
	if out, code := command(t, args...); code != 1 || out != "authority_not_reconciled\n" {
		t.Fatalf("before the reconciliation: %d %q", code, out)
	}
	client, err := authorityclient.NewAPI(socket, catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = s.Reconcile(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	if out, code := command(t, args...); code != 1 || out != "listener_unavailable\n" {
		t.Fatalf("after the reconciliation: %d %q", code, out)
	}
}
