package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func migrationStore(t *testing.T) *Store {
	t.Helper()
	dsn := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := newID("migration")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	s, err := Open(t.Context(), scopedURL(t, dsn, schema))
	if err != nil {
		admin.Close()
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
	return s
}

// Only used to reconstruct the historical installation in migration tests.
// Production must never delete a ledger to retry or repair an applied change.
func simulatePreLedgerSchema(t *testing.T, s *Store) {
	t.Helper()
	revertTenantAgents(t, s)
	if _, err := s.pool.Exec(t.Context(), `DROP TABLE placement_control_contracts,tenant_team_audit,tenant_http_receipts,tenant_member_audit,delegation_audit,delegation_admin_receipts,delegation_revocations,delegation_trusts,delegation_issuers,organization_audit,platform_credentials,team_memberships,teams,memberships,principals,organizations,schema_migrations;
        ALTER TABLE api_tokens DROP COLUMN IF EXISTS issued_by_token_id;
        ALTER TABLE http_receipts DROP CONSTRAINT http_receipts_actor_kind_check;
        ALTER TABLE http_receipts ADD CONSTRAINT http_receipts_actor_kind_check CHECK (actor_kind IN ('user','service'))`); err != nil {
		t.Fatal(err)
	}
}

func TestVersionedMigrationsAdoptLegacyAndPreserveData(t *testing.T) {
	s := migrationStore(t)
	// A deployed pre-ledger schema and its actual data, not an empty database.
	if _, err := s.pool.Exec(t.Context(), schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO agents(id,owner_user_id,next_seq)
        VALUES('legacy-agent','legacy-owner',17)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT applied_at FROM schema_migrations WHERE version=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var after time.Time
	var owner string
	var seq int64
	if err := s.pool.QueryRow(t.Context(), "SELECT applied_at FROM schema_migrations WHERE version=1").Scan(&after); err != nil || !after.Equal(before) {
		t.Fatal("migration receipt changed", before, after, err)
	}
	if err := s.pool.QueryRow(t.Context(), "SELECT owner_user_id,next_seq FROM agents WHERE id='legacy-agent'").Scan(&owner, &seq); err != nil || owner != "legacy-owner" || seq != 17 {
		t.Fatal("legacy identity or data changed", owner, seq, err)
	}
	if count(t, s, "organizations") != 0 || count(t, s, "principals") != 0 {
		t.Fatal("legacy ownership silently converted into a tenant")
	}
}

func TestVersionedMigrationsConcurrentAndExactlyOnce(t *testing.T) {
	s := migrationStore(t)
	migrations := append([]schemaMigration(nil), controlPlaneMigrations...)
	migrations = append(migrations, schemaMigration{version: int64(len(migrations) + 1), name: "test-once", sql: `
        CREATE TABLE migration_once (n integer NOT NULL);
        INSERT INTO migration_once VALUES(1)`})
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- s.migrate(t.Context(), migrations)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := count(t, s, "migration_once"); got != 1 {
		t.Fatalf("migration applied %d times", got)
	}
	if got := count(t, s, "schema_migrations"); got != len(migrations) {
		t.Fatalf("history length %d, want %d", got, len(migrations))
	}
	if err := s.Migrate(t.Context()); !errors.Is(err, ErrMigrationHistory) {
		t.Fatal("older binary accepted a newer schema", err)
	}
}

func TestVersionedMigrationsRollbackAndRetry(t *testing.T) {
	for _, mode := range []string{"statement-error", "canceled", "backend-terminated"} {
		t.Run(mode, func(t *testing.T) {
			s := migrationStore(t)
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			migrations := append([]schemaMigration(nil), controlPlaneMigrations...)
			body := "CREATE TABLE migration_atomic (n integer); INSERT INTO migration_atomic VALUES(1);"
			tail := "SELECT 1/0"
			marker := newID("migration_wait")
			if mode != "statement-error" {
				tail = "SELECT pg_sleep(30) /* " + marker + " */"
			}
			migrations = append(migrations, schemaMigration{version: int64(len(migrations) + 1), name: "test-atomic", sql: body + tail})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- s.migrate(ctx, migrations) }()
			if mode != "statement-error" {
				// Observe the backend inside pg_sleep, after both DDL and data
				// writes. A timeout before reaching that boundary is not evidence
				// that cancellation rolled back an in-progress migration.
				var pid int
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					err := s.pool.QueryRow(t.Context(), `SELECT pid FROM pg_stat_activity
                        WHERE datname=current_database() AND pid<>pg_backend_pid()
                        AND wait_event='PgSleep' AND strpos(query,$1)>0`, marker).Scan(&pid)
					if err == nil {
						break
					}
					if !errors.Is(err, pgx.ErrNoRows) {
						cancel()
						<-result
						t.Fatal(err)
					}
					time.Sleep(10 * time.Millisecond)
				}
				if pid == 0 {
					cancel()
					<-result
					t.Fatal("migration never reached its post-write interruption boundary")
				}
				if mode == "canceled" {
					cancel()
				} else {
					var terminated bool
					if err := s.pool.QueryRow(t.Context(), "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil || !terminated {
						cancel()
						<-result
						t.Fatal("backend termination failed", err)
					}
				}
			}
			if err := <-result; err == nil {
				t.Fatal("injected migration failure accepted")
			}
			var present bool
			if err := s.pool.QueryRow(t.Context(), "SELECT to_regclass('migration_atomic') IS NOT NULL").Scan(&present); err != nil || present {
				t.Fatal("failed migration left a partial table", present, err)
			}
			if got := count(t, s, "schema_migrations"); got != len(controlPlaneMigrations) {
				t.Fatal("failed migration recorded as applied", got)
			}
			migrations[len(migrations)-1].sql = body
			if err := s.migrate(t.Context(), migrations); err != nil {
				t.Fatal("retry after rollback", err)
			}
			if count(t, s, "migration_atomic") != 1 {
				t.Fatal("retry did not commit its data")
			}
		})
	}
}

func TestVersionedMigrationsRejectChangedHistory(t *testing.T) {
	for _, mode := range []string{"checksum", "name", "gap", "future", "missing-table", "unlogged-history"} {
		t.Run(mode, func(t *testing.T) {
			s := migrationStore(t)
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			query := map[string]string{
				"checksum":         "UPDATE schema_migrations SET checksum=decode(repeat('00',32),'hex') WHERE version=1",
				"name":             "UPDATE schema_migrations SET name='changed' WHERE version=1",
				"gap":              "UPDATE schema_migrations SET version=100 WHERE version=1",
				"future":           "INSERT INTO schema_migrations SELECT 100,'future',checksum,applied_at FROM schema_migrations WHERE version=1",
				"missing-table":    "DROP TABLE api_receipt_key",
				"unlogged-history": "ALTER TABLE schema_migrations SET UNLOGGED",
			}[mode]
			if _, err := s.pool.Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			want := ErrMigrationHistory
			if mode == "missing-table" || mode == "unlogged-history" {
				want = ErrUnsafeDatabase
			}
			if err := s.Migrate(t.Context()); !errors.Is(err, want) {
				t.Fatal("unsafe migration history accepted", err)
			}
		})
	}
}

func TestVersionedMigrationsRejectRewrittenSource(t *testing.T) {
	s := migrationStore(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	migrations := append([]schemaMigration(nil), controlPlaneMigrations...)
	migrations[0].sql += "\n-- rewritten baseline"
	if err := s.migrate(t.Context(), migrations); !errors.Is(err, ErrMigrationHistory) {
		t.Fatal("changed installed migration accepted", err)
	}
	want := sha256.Sum256([]byte(schemaSQL))
	var got []byte
	if err := s.pool.QueryRow(t.Context(), "SELECT checksum FROM schema_migrations WHERE version=1").Scan(&got); err != nil || string(got) != string(want[:]) {
		t.Fatal("refusal overwrote installed history", err)
	}
}

func TestOrganizationIdentityConstraints(t *testing.T) {
	s := migrationStore(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `
        INSERT INTO organizations(id,name) VALUES('org-a','A'),('org-b','B');
        INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name) VALUES
            ('principal-a','org-a','user','https://issuer.example','alice','Alice'),
            ('principal-b','org-b','user','https://issuer.example','alice','Alice');
        INSERT INTO memberships(tenant_id,principal_id,role) VALUES
            ('org-a','principal-a','org_owner'),('org-b','principal-b','agent_user');
        INSERT INTO teams(id,tenant_id,name) VALUES('team-a','org-a','Team A');
        INSERT INTO team_memberships(tenant_id,team_id,principal_id)
            VALUES('org-a','team-a','principal-a')`); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"foreign-membership": `INSERT INTO memberships(tenant_id,principal_id,role) VALUES('org-a','principal-b','org_owner')`,
		"foreign-team":       `INSERT INTO team_memberships(tenant_id,team_id,principal_id) VALUES('org-b','team-a','principal-b')`,
		"foreign-principal":  `INSERT INTO team_memberships(tenant_id,team_id,principal_id) VALUES('org-a','team-a','principal-b')`,
		"unknown-role":       `UPDATE memberships SET role='superuser' WHERE principal_id='principal-a'`,
		"missing-tenant":     `INSERT INTO principals(id,kind,issuer,subject,display_name) VALUES('missing','user','issuer','subject','Name')`,
		"duplicate-subject":  `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name) VALUES('duplicate','org-a','user','https://issuer.example','alice','Duplicate')`,
		"unverified-user":    `INSERT INTO principals(id,tenant_id,kind,display_name) VALUES('unverified','org-a','user','User')`,
		"service-impersonation": `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name)
            VALUES('service','org-a','service','issuer','alice','Service')`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), query); err == nil {
				t.Fatal("invalid identity relationship accepted")
			}
		})
	}
	if count(t, s, "principals") != 2 || count(t, s, "memberships") != 2 || count(t, s, "team_memberships") != 1 {
		t.Fatal("rejected identity mutation changed the graph")
	}
}

func TestReadyChecksInstalledMigrationLedger(t *testing.T) {
	s := migrationStore(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(t.Context()); err != nil {
		t.Fatal("migrated database is not ready:", err)
	}
	for name, query := range map[string]string{
		"behind":   "DELETE FROM schema_migrations WHERE version=(SELECT max(version) FROM schema_migrations)",
		"future":   "INSERT INTO schema_migrations SELECT 100,'future',checksum,applied_at FROM schema_migrations WHERE version=1",
		"checksum": "UPDATE schema_migrations SET checksum=decode(repeat('00',32),'hex') WHERE version=2",
	} {
		t.Run(name, func(t *testing.T) {
			s := migrationStore(t)
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			if err := s.Ready(t.Context()); !errors.Is(err, ErrMigrationHistory) {
				t.Fatal("readiness accepted a ledger that does not match this binary:", err)
			}
		})
	}
}

// revertTenantAgents removes migration 0010 from an isolated test schema so that
// fixtures simulating an older installation can replay it. Test-only: a ledger
// row is never removed to repair a production database.
func revertTenantAgents(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), `
        DROP TABLE IF EXISTS volume_restore_losses, volume_restores;
        DROP FUNCTION IF EXISTS preserve_restore_loss(), preserve_volume_restore();
        ALTER TABLE store_initializations DROP CONSTRAINT IF EXISTS store_initializations_pkey,
          ADD PRIMARY KEY (agent_id);
        ALTER TABLE store_enrollments DROP CONSTRAINT IF EXISTS store_enrollments_stage_check;
        ALTER TABLE store_enrollments ADD CONSTRAINT store_enrollments_stage_check CHECK (stage IN ('INSTALLING','FENCING','READY'));
        DROP TABLE IF EXISTS volume_archives;
        DROP TABLE IF EXISTS peer_wakes;
        ALTER TABLE platform_operations DROP COLUMN IF EXISTS request_id;
        DROP INDEX IF EXISTS agent_requests_held;
        DROP TABLE IF EXISTS agent_directory;
        DROP TRIGGER IF EXISTS agent_directory_follow_agent ON agents;
        DROP TRIGGER IF EXISTS agent_directory_follow_organization ON organizations;
        DROP FUNCTION IF EXISTS agent_directory_follow_agent(), agent_directory_follow_organization();
        DROP TABLE IF EXISTS harness_audit, harness_imports;
        DROP INDEX IF EXISTS harness_releases_package;
        ALTER TABLE harness_releases DROP CONSTRAINT IF EXISTS harness_releases_oci, DROP CONSTRAINT IF EXISTS harness_releases_deprecation,
          DROP COLUMN IF EXISTS reference, DROP COLUMN IF EXISTS rootfs_digest, DROP COLUMN IF EXISTS rootfs_bytes, DROP COLUMN IF EXISTS deprecated_at,
          DROP COLUMN IF EXISTS signer;
        ALTER TABLE owner_instructions DROP CONSTRAINT IF EXISTS owner_instructions_working,
          DROP COLUMN IF EXISTS work_timeout_seconds, DROP COLUMN IF EXISTS working_since, DROP COLUMN IF EXISTS result_due_at,
          DROP COLUMN IF EXISTS completion_key, DROP COLUMN IF EXISTS completion_hash;
        DROP TABLE IF EXISTS attachment_segments, attachments;
        ALTER TABLE queue_limits DROP COLUMN IF EXISTS max_attachment_bytes;
        DROP TABLE IF EXISTS agent_idle_watch;
        ALTER TABLE agent_specs DROP COLUMN IF EXISTS idle_timeout_seconds, DROP COLUMN IF EXISTS idle_policy_by;
        ALTER TABLE platform_operations DROP COLUMN IF EXISTS cause;
        ALTER TABLE owner_instructions DROP COLUMN IF EXISTS run_at, DROP COLUMN IF EXISTS released_at, DROP COLUMN IF EXISTS ttl_micros;
        DROP TABLE IF EXISTS queue_audit, queue_limits;
        ALTER TABLE owner_instructions DROP COLUMN IF EXISTS close_reason;
        DROP TABLE IF EXISTS llm_usage, llm_budgets, llm_audit, llm_model_aliases, llm_providers;
        DROP TABLE IF EXISTS tenant_service_audit, service_tokens;
        DROP TABLE IF EXISTS tenant_agent_audit, agent_assignments;
        ALTER TABLE platform_operations DROP CONSTRAINT IF EXISTS platform_operations_requester;
        ALTER TABLE platform_operations DROP COLUMN IF EXISTS requested_by_principal_id;
        ALTER TABLE platform_operations ALTER COLUMN owner_user_id SET NOT NULL;
        DROP INDEX IF EXISTS agents_tenant;
        DROP INDEX IF EXISTS agents_legacy_owner;
        ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_one_domain;
        ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_tenant_identity;
        ALTER TABLE agents DROP COLUMN IF EXISTS tenant_id;
        ALTER TABLE agents ALTER COLUMN owner_user_id SET NOT NULL;
        ALTER TABLE agents ADD CONSTRAINT agents_owner_user_id_key UNIQUE (owner_user_id)`); err != nil {
		t.Fatal(err)
	}
}
