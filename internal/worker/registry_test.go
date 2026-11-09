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

func TestPrivateRegistryImportsNeedCredentials(t *testing.T) {
	l := newImportLab(t)
	ref := l.publish(t, "private", "1.0.0")
	// The registry turns private: tokens only for these credentials.
	l.reg.Token, l.reg.Username, l.reg.Password = "pull-token", "ci-bot", "test-password-not-a-secret" // gitleaks:allow

	denied := l.request(t, "anonymous", ref.String())
	l.importOne(t)
	if v := l.state(t, denied.ID); v.State != "REJECTED" || v.ErrorCode != "access_denied" || v.Attempts != 1 {
		t.Fatal("anonymous import of a private package", v)
	}

	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, []byte(`{"username":"ci-bot","password":"test-password-not-a-secret"}`), 0o600); err != nil { // gitleaks:allow
		t.Fatal(err)
	}
	c := ServiceConfig{Root: t.TempDir(), Registry: &ServiceRegistry{Cache: l.cache, MaxHarnessMiB: 64,
		Rules: []RegistryRule{{Rule: l.rule, CredentialsFile: path}}}}
	importer, err := c.OpenRegistry(l.store, "importer-credentials")
	if err != nil {
		t.Fatal(err)
	}
	l.importer = importer
	again := l.request(t, "with-credentials", ref.String())
	l.importOne(t)
	if v := l.state(t, again.ID); v.State != "READY" || v.ReleaseID == "" {
		t.Fatal("import with credentials", v)
	}
	if l.reg.BasicSeen.Load() != 0 {
		t.Fatal("credentials sent to the registry API instead of the token service")
	}
}

func TestEvictionKeepsEveryPackageAnAgentMayBoot(t *testing.T) {
	l := newImportLab(t)
	ctx := t.Context()
	released := map[string]controlplane.HarnessImport{}
	digests := map[string]string{}
	for _, name := range []string{"approved", "pinned", "unused", "booting"} {
		ref := l.publish(t, name, "1.0.0")
		imp := l.request(t, "import-"+name, ref.String())
		l.importOne(t)
		released[name] = l.state(t, imp.ID)
		digests[name] = ref.Digest
	}
	// A legacy agent of this host is pinned to "pinned".
	secret, err := l.store.BootstrapService(ctx, "evict-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := l.store.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.accounts.CreateUser(ctx, service, "owner", controlplane.CreateUserInput{DisplayName: "Owner"})
	var owner controlplane.User
	if err != nil || json.Unmarshal(r.Body, &owner) != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewAgentCatalog(l.accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.store.ConfigureHostStorage(ctx, "local", 1024); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Reserve(ctx, service, "agent", controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: "Pinned",
		Harness:   controlplane.HarnessReference{Name: "pinned", Version: "1.0.0"},
		Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pinned", "unused", "booting"} {
		if _, err = l.accounts.DeprecateHarnessRelease(ctx, l.platform, released[name].ReleaseID, "deprecate-"+name); err != nil {
			t.Fatal(err)
		}
	}
	// An import in flight: its package reaches the cache before its release.
	inFlight := "sha256:" + strings.Repeat("e", 64)
	l.request(t, "in-flight", l.reg.Host()+"/acme/later@"+inFlight)
	if err = os.Mkdir(l.importer.PackageDir(inFlight), 0o555); err != nil {
		t.Fatal(err)
	}
	// A download interrupted by a crash, with a sealed subdirectory.
	leftover := filepath.Join(l.cache, ".staging", "crashed", "pkg")
	if err = os.MkdirAll(leftover, 0o755); err != nil || os.Chmod(leftover, 0o555) != nil {
		t.Fatal(err)
	}

	// Without the runtime's view of the images in use, nothing is evicted.
	if evicted, err := l.importer.Evict(ctx); err != nil || len(evicted) != 0 {
		t.Fatal("evicted without knowing which images may boot", evicted, err)
	}
	booting := filepath.Join(l.importer.PackageDir(digests["booting"]), harnesspkg.RootfsFile)
	inUse := func(context.Context) (map[string]bool, error) { return map[string]bool{booting: true}, nil }
	l.importer.host = "local"
	l.importer.inUse.Store(&inUse)
	evicted, err := l.importer.Evict(ctx)
	if err != nil || len(evicted) != 1 || evicted[0] != digests["unused"] {
		t.Fatal("eviction", evicted, err)
	}
	for _, name := range []string{"approved", "pinned", "booting"} {
		if _, err = os.Stat(filepath.Join(l.importer.PackageDir(digests[name]), harnesspkg.RootfsFile)); err != nil {
			t.Fatal("a package an agent may boot was evicted", name, err)
		}
	}
	if _, err = os.Stat(l.importer.PackageDir(inFlight)); err != nil {
		t.Fatal("an import in flight lost its package", err)
	}
	if _, err = os.Stat(l.importer.PackageDir(digests["unused"])); !os.IsNotExist(err) {
		t.Fatal("the unused package is still cached", err)
	}
	if entries, err := os.ReadDir(filepath.Join(l.cache, ".staging")); err != nil || len(entries) != 0 {
		t.Fatal("staging leftovers kept", len(entries), err)
	}
	// Once its agent is gone from the host's records and the database, a
	// deprecated package goes too; an approved one never does.
	if _, err = l.db.Exec(ctx, "UPDATE agents SET phase='DELETED' WHERE id=(SELECT agent_id FROM agent_specs WHERE name='Pinned')"); err != nil {
		t.Fatal(err)
	}
	none := func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }
	l.importer.inUse.Store(&none)
	if evicted, err = l.importer.Evict(ctx); err != nil || len(evicted) != 2 {
		t.Fatal("second eviction", evicted, err)
	}
	if _, err = os.Stat(l.importer.PackageDir(digests["approved"])); err != nil {
		t.Fatal("an approved release was evicted", err)
	}
}
