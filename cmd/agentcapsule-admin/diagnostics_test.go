//go:build linux && cgo

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// operatorDatabase is a migrated schema of its own, which the commands reach
// through AGENTCAPSULE_DATABASE_URL.
func operatorDatabase(t *testing.T) (*controlplane.Store, *pgxpool.Pool) {
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
	schema := "admin_" + hex.EncodeToString(id)
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
	return s, db
}

func secret(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// The diagnostic export (API-02) holds what an operator needs and nothing
// else: secrets, content and personal data planted in the database, the
// worker's configuration, its metrics endpoint and Prometheus's alerts never
// reach the archive.
func TestDiagnosticsLeakNoSecretContentOrPersonalData(t *testing.T) {
	s, db := operatorDatabase(t)
	ctx := t.Context()
	platformSecret, serviceSecret := secret("acpp_"), secret("acp_")
	if err := s.BootstrapPlatformToken(ctx, "planted-platform", platformSecret, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapServiceToken(ctx, "planted-service", serviceSecret, time.Hour); err != nil {
		t.Fatal(err)
	}
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	platform, err := s.Authenticate(ctx, platformSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.CreateOrganization(ctx, platform, "planted-org", controlplane.CreateOrganizationInput{Name: "Planted Organization Name",
		InitialOwner: controlplane.InitialOrganizationOwner{Issuer: "https://planted-idp.example", Subject: "planted.person@example.test", DisplayName: "Planted Person"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.RequestHarnessImport(ctx, platform, "planted-import", controlplane.HarnessImportInput{
		Reference: "ghcr.io/planted-private-publisher/echo@sha256:" + strings.Repeat("e", 64)}); err != nil {
		t.Fatal(err)
	}
	content := "PLANTED-CONVERSATION-CONTENT"
	hash := sha256.Sum256([]byte(content))
	if _, err = db.Exec(ctx, "INSERT INTO transit_keys(id,key_hash) VALUES('planted-key',$1)", hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO transit_payloads(id,kind,ref_id,key_id,content_hash,ciphertext) VALUES('planted-payload','instruction','planted-ref','planted-key',$1,$2)",
		hash[:], []byte(content)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(ctx, "kvm-01", 4096); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordStoragePressure(ctx, "kvm-01", true, false); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	config := filepath.Join(dir, "worker.json")
	if err = os.WriteFile(config, []byte(`{"version":1,"host_id":"kvm-01","root":"/srv/plantedperson/agentcapsule","max_active":4,
		"boot_timeout":"30s","initrd":{"path":"/srv/planted/initrd","sha256":"`+strings.Repeat("a", 64)+`"},
		"llm":{"api_key":"sk-planted-provider-key"},"database_url":"postgres://ops:planted-db-pass@db.example/agentcapsule",
		"registry":{"rules":[{"host":"ghcr.io","repositories":["plantedperson/"],"password":"planted-registry-password"}]},
		"metrics_listen":"127.0.0.1:9465"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "# HELP agentcapsule_worker_jobs Jobs of this host, by kind.\n# TYPE agentcapsule_worker_jobs gauge\n")
		fmt.Fprintf(w, "agentcapsule_worker_jobs{kind=\"delivery\"} 3\nagentcapsule_authority_replication_lag_records 2\n")
		fmt.Fprintf(w, "agentcapsule_worker_jobs{kind=\"%s\"} 1\n", serviceSecret)
		fmt.Fprintf(w, "agentcapsule_worker_jobs{kind=\"planted person\"} 1\n")
		fmt.Fprintf(w, "# HELP other_exporter_secret %s\nother_exporter_secret{token=\"%s\"} 1\n", platformSecret, platformSecret)
	}))
	defer metrics.Close()
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/alerts" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"alerts":[{"labels":{"alertname":"AgentCapsuleDiskPressure","severity":"warning",
			"job":"agentcapsule-worker","instance":"planted-host.example:9465","member":"planted.person@example.test"},
			"annotations":{"summary":"PLANTED-ANNOTATION"},"state":"firing","activeAt":"2026-11-16T10:00:00Z","value":"8.5e-01"}]}}`)
	}))
	defer prometheus.Close()

	archive := filepath.Join(dir, "diagnostics.tar.gz")
	if out, code := trimmed(t, "diagnostics", "-output", archive, "-worker-config", config, "-worker-metrics", metrics.URL+"/metrics",
		"-api-metrics", "http://127.0.0.1:1/metrics", "-prometheus", prometheus.URL); code != 0 || out != "diagnostics_written" {
		t.Fatal("diagnostics", out, code)
	}
	if st, err := os.Stat(archive); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("archive mode", st, err)
	}
	files := readArchive(t, archive)
	var all strings.Builder
	for name, body := range files {
		all.WriteString(name + "\n" + body + "\n")
	}
	everything := all.String()
	for _, planted := range []string{platformSecret, serviceSecret, platformSecret[5:15], serviceSecret[4:14], content, "Planted Organization Name",
		"Planted Person", "planted.person@example.test", "planted-idp", "plantedperson", "sk-planted-provider-key", "planted-db-pass",
		"planted-registry-password", "planted-private-publisher", "planted-host", "PLANTED-ANNOTATION", "planted person", "/srv/planted", "other_exporter"} {
		if strings.Contains(everything, planted) {
			t.Errorf("the archive holds %q", planted)
		}
	}
	for name, want := range map[string]string{
		"agentcapsule-diagnostics/database.json":                     `"expected_migration": `,
		"agentcapsule-diagnostics/metrics/worker.prom":               `agentcapsule_worker_jobs{kind="delivery"} 3`,
		"agentcapsule-diagnostics/worker-authority-replication.json": `"agentcapsule_authority_replication_lag_records": "2"`,
		"agentcapsule-diagnostics/alerts.json":                       `"alertname": "AgentCapsuleDiskPressure"`,
		"agentcapsule-diagnostics/worker-config.json":                `"max_active": 4`,
		"agentcapsule-diagnostics/versions.json":                     `"go": "go`,
		"agentcapsule-diagnostics/manifest.json":                     `"api_metrics": "unreachable"`,
	} {
		if !strings.Contains(files[name], want) {
			t.Errorf("%s lacks %s:\n%s", name, want, files[name])
		}
	}
	var d controlplane.Diagnostics
	if err = json.Unmarshal([]byte(files["agentcapsule-diagnostics/database.json"]), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Hosts) != 1 || d.Hosts[0].HostID != "kvm-01" || !d.Hosts[0].DataPressure || len(d.Migrations) != d.ExpectedMigration || len(d.Imports) != 1 {
		t.Fatal("database diagnostics", d)
	}
	var cfg map[string]any
	if err = json.Unmarshal([]byte(files["agentcapsule-diagnostics/worker-config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["host_id"] != "kvm-01" || cfg["boot_timeout"] != "30s" || cfg["root"] != "redacted" || cfg["metrics_listen"] != "127.0.0.1:9465" {
		t.Fatal("configuration", cfg)
	}
	// An existing file is never overwritten.
	if out, code := trimmed(t, "diagnostics", "-output", archive); code == 0 || out != "diagnostics_output_failed" {
		t.Fatal("overwrote", out, code)
	}
}

func readArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	files := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = string(b)
	}
}
