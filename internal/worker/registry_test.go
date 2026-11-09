//go:build linux

package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/rand"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type importLab struct {
	store    *controlplane.Store
	accounts *controlplane.Accounts
	platform controlplane.Principal
	db       *pgxpool.Pool
	reg      *registrytest.Registry
	rule     ociregistry.Rule
	importer *HarnessImporter
	cache    string
}

func newImportLab(t *testing.T) *importLab {
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
	schema := fmt.Sprintf("worker_import_%d", time.Now().UnixNano())
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
	reg := registrytest.New()
	t.Cleanup(func() {
		reg.Close()
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
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	secret := "acpp_" + base64.RawURLEncoding.EncodeToString(raw)
	if err = s.BootstrapPlatformToken(t.Context(), "import-platform", secret, time.Hour); err != nil {
		t.Fatal(err)
	}
	platform, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	rule := ociregistry.Rule{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true}
	fetcher, err := ociregistry.NewFetcher(ociregistry.Policy{Rules: []ociregistry.Rule{rule}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "releases")
	// Cached packages are read-only; let the temporary directory be removed.
	t.Cleanup(func() {
		_ = filepath.WalkDir(cache, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	importer, err := NewHarnessImporter(s, fetcher, cache, "importer-test")
	if err != nil {
		t.Fatal(err)
	}
	return &importLab{store: s, accounts: accounts, platform: platform, db: db, reg: reg, rule: rule, importer: importer, cache: cache}
}

func (l *importLab) publish(t *testing.T, name, version string) ociregistry.Reference {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "harness"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: name, Version: version, Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: []string{"/harness"}}
	dir := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(dir, harnesspkg.RootfsFile), 1); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(dir, m); err != nil {
		t.Fatal(err)
	}
	ref, err := ociregistry.Push(t.Context(), l.rule, "acme/"+name, version, dir)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (l *importLab) request(t *testing.T, key, ref string) controlplane.HarnessImport {
	t.Helper()
	r, err := l.accounts.RequestHarnessImport(t.Context(), l.platform, key, controlplane.HarnessImportInput{Reference: ref})
	var v controlplane.HarnessImport
	if err != nil || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("request", err)
	}
	return v
}

func (l *importLab) state(t *testing.T, id string) controlplane.HarnessImport {
	t.Helper()
	v, err := l.accounts.GetHarnessImport(t.Context(), l.platform, id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (l *importLab) importOne(t *testing.T) {
	t.Helper()
	if worked, err := l.importer.ImportOne(t.Context()); err != nil || !worked {
		t.Fatal("import", worked, err)
	}
	if entries, err := os.ReadDir(filepath.Join(l.cache, ".staging")); err != nil || len(entries) != 0 {
		t.Fatal("staging left behind", len(entries), err)
	}
}

func TestWorkerImportsVerifiedPackagesIntoTheCache(t *testing.T) {
	l := newImportLab(t)
	ref := l.publish(t, "echo", "1.0.0")
	imp := l.request(t, "ok", ref.String())
	l.importOne(t)
	done := l.state(t, imp.ID)
	if done.State != "READY" || done.ReleaseID == "" {
		t.Fatal("import", done)
	}
	dir := l.importer.PackageDir(ref.Digest)
	for _, name := range []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm()&0o222 != 0 {
			t.Fatal("cached file missing or writable", name, err)
		}
	}
	if worked, err := l.importer.ImportOne(t.Context()); err != nil || worked {
		t.Fatal("work left", worked, err)
	}

	// A repository outside the policy is refused before any connection.
	pulls := l.reg.Pulls.Load()
	blocked := l.request(t, "blocked", l.reg.Host()+"/other/echo@sha256:"+strings.Repeat("b", 64))
	l.importOne(t)
	if v := l.state(t, blocked.ID); v.State != "REJECTED" || v.ErrorCode != "policy" || l.reg.Pulls.Load() != pulls {
		t.Fatal("unapproved repository", v, l.reg.Pulls.Load()-pulls)
	}

	// Content altered in transit is rejected and never cached.
	tampered := l.publish(t, "echo", "2.0.0")
	l.reg.Tamper = func(_ string, b []byte) []byte {
		if len(b) > 4096 {
			c := append([]byte(nil), b...)
			c[3000] ^= 0xff
			return c
		}
		return b
	}
	bad := l.request(t, "tampered", tampered.String())
	l.importOne(t)
	l.reg.Tamper = nil
	if v := l.state(t, bad.ID); v.State != "REJECTED" || v.ErrorCode != "integrity" {
		t.Fatal("tampered package", v)
	}
	if _, err := os.Stat(l.importer.PackageDir(tampered.Digest)); !os.IsNotExist(err) {
		t.Fatal("a rejected package reached the cache", err)
	}

	// A registry that is down is retried later, not rejected.
	later := l.publish(t, "echo", "3.0.0")
	l.reg.Server.CloseClientConnections()
	l.reg.Server.Close()
	pending := l.request(t, "down", later.String())
	l.importOne(t)
	if v := l.state(t, pending.ID); v.State != "IMPORTING" || v.Attempts != 1 {
		t.Fatal("transient failure", v)
	}
}
