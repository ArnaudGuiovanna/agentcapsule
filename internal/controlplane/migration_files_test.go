package controlplane

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"
)

// migrationSQL is the SQL of the migration called name.
func migrationSQL(t *testing.T, name string) string {
	t.Helper()
	for _, m := range controlPlaneMigrations {
		if m.name == name {
			return m.sql
		}
	}
	t.Fatal("no migration called", name)
	return ""
}

// installedMigrations are the names of the migrations an installation may
// hold in its ledger since the list was derived from the files (audit finding
// A-08). Renaming one would stop every such installation: a file is never
// renamed, and later files add to this history without being listed here.
var installedMigrations = []string{
	"control-plane-baseline", "organization-identity", "platform-organizations", "delegated-identity", "tenant-members",
	"tenant-teams", "placement-control-contract", "token-issuer", "receipt-expiry-index", "tenant-agents",
	"service-accounts", "llm-providers", "llm-budgets", "instruction-queues", "lifecycle-audit",
	"scheduling", "attachments", "async-completion", "harness-registry", "registry-access-denied",
	"agent-release-change", "release-signatures", "agent-directory", "agent-inbound", "held-requests",
	"peer-wakes", "operation-request-id", "volume-archives", "volume-restores", "invocation-reruns",
	"restart-budgets", "llm-access-and-cost", "peer-redeliveries", "operator-bootstrap", "capacity-queue-and-replays",
	"capabilities", "operations", "host-takeovers", "audit-retention-indexes", "access-revocations",
	"receipt-key-days", "authority-reconciliations", "tenant-refusal-audit", "trace-pseudonym-key", "garbage-collection-audit",
	"organization-quotas", "unresponsive-guests", "directory-trigger-search-path", "deployments", "applications",
	"provider-auth", "rollouts", "volume-growth", "personal-volume-holds", "agent-resize",
	"invocation-streams", "llm-operations", "source-credentials", "corpus-mounts", "corpus-builds",
	"corpus-builder", "corpus-extensions", "corpus-build-streams", "corpus-file-progress-search-path", "service-roles",
	"access-revocation-recording", "organization-suspension", "llm-request-policy", "revocation-scope-indexes", "work-notifications",
	"open-state-indexes", "finished-record-retention", "service-privileges-activity-retention", "refusal-attempts", "application-clients",
	"platform-session-chains", "append-only-audit", "llm-budget-windows", "model-call-retention", "service-privileges-model-calls",
}

// Each migration is declared once, by its file: its version and its name come
// from the file name, and the derived history keeps the names the ledgers of
// installed hosts hold.
func TestEachMigrationIsDeclaredOnceByItsFile(t *testing.T) {
	if len(controlPlaneMigrations) < len(installedMigrations) {
		t.Fatal("migrations missing", len(controlPlaneMigrations))
	}
	for i, name := range installedMigrations {
		if m := controlPlaneMigrations[i]; m.version != int64(i+1) || m.name != name {
			t.Errorf("migration %d is %d %q, want %q", i+1, m.version, m.name, name)
		}
	}
	files, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(controlPlaneMigrations)-1 || controlPlaneMigrations[0].sql != schemaSQL {
		t.Fatal("the history is not schema.sql and every file", len(files), len(controlPlaneMigrations))
	}
	for i, f := range files {
		m := controlPlaneMigrations[i+1]
		if want := fmt.Sprintf("%04d_%s.sql", m.version, underscored(m.name)); f.Name() != want {
			t.Errorf("migration %d %q comes from %s, want %s", m.version, m.name, f.Name(), want)
		}
	}
}

func underscored(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}

// The next migration is its file alone (here the one FIX-2 adds,
// revocation_subject_stores): the history picks it up at its version, under
// its name, with no other declaration.
func TestANewMigrationFileNeedsNoOtherDeclaration(t *testing.T) {
	dir := embeddedMigrations(t)
	next := len(controlPlaneMigrations) + 1
	dir[fmt.Sprintf("%04d_revocation_subject_stores.sql", next)] = &fstest.MapFile{Data: []byte("ALTER TABLE revocation_catalogue ADD COLUMN stores text[];\n")}
	got, err := loadMigrations(schemaSQL, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != next || !slices.Equal(got[:next-1], controlPlaneMigrations) {
		t.Fatal("the existing history changed", len(got))
	}
	if last := got[next-1]; last.version != int64(next) || last.name != "revocation-subject-stores" || last.sql != "ALTER TABLE revocation_catalogue ADD COLUMN stores text[];\n" {
		t.Fatal("the new file was not picked up", last.version, last.name)
	}
}

// A file whose name is of another form, a version taken twice and a skipped
// version stop the history from loading: every binary refuses to start, and
// every test of this package fails, before any database is touched.
func TestAMigrationFileOutOfFormOrOrderIsRefused(t *testing.T) {
	next := len(controlPlaneMigrations) + 1
	for name, files := range map[string]map[string]string{
		"gap":            {fmt.Sprintf("%04d_after_a_gap.sql", next+1): "SELECT 1;"},
		"repeat":         {fmt.Sprintf("%04d_first.sql", next): "SELECT 1;", fmt.Sprintf("%04d_second.sql", next): "SELECT 1;"},
		"taken":          {fmt.Sprintf("%04d_again.sql", next-1): "SELECT 1;"},
		"three digits":   {fmt.Sprintf("%03d_short.sql", next): "SELECT 1;"},
		"upper case":     {fmt.Sprintf("%04d_Upper.sql", next): "SELECT 1;"},
		"hyphens":        {fmt.Sprintf("%04d_with-hyphens.sql", next): "SELECT 1;"},
		"no name":        {fmt.Sprintf("%04d_.sql", next): "SELECT 1;"},
		"doubled join":   {fmt.Sprintf("%04d_two__joins.sql", next): "SELECT 1;"},
		"another suffix": {fmt.Sprintf("%04d_name.sql.orig", next): "SELECT 1;"},
		"empty":          {fmt.Sprintf("%04d_empty.sql", next): " \n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := embeddedMigrations(t)
			for file, sql := range files {
				dir[file] = &fstest.MapFile{Data: []byte(sql)}
			}
			if _, err := loadMigrations(schemaSQL, dir); !errors.Is(err, ErrMigrationHistory) {
				t.Fatal("history loaded", err)
			}
		})
	}
	dir := embeddedMigrations(t)
	dir[fmt.Sprintf("%04d_directory.sql", next)] = &fstest.MapFile{Mode: fs.ModeDir | 0o755}
	if _, err := loadMigrations(schemaSQL, dir); !errors.Is(err, ErrMigrationHistory) {
		t.Fatal("a directory loaded as a migration", err)
	}
}

// embeddedMigrations is a copy of the embedded migration files.
func embeddedMigrations(t *testing.T) fstest.MapFS {
	t.Helper()
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	dir := fstest.MapFS{}
	for _, e := range entries {
		data, err := fs.ReadFile(migrationFiles, "migrations/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		dir[e.Name()] = &fstest.MapFile{Data: data}
	}
	return dir
}
