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

// A trigger runs with the search path of the session that changes its row:
// the store's, an operator's psql, a test's administration pool. A trigger
// function that names another table pins the search path of its migration
// (SET search_path FROM CURRENT), as preserve_sealed_agent does; otherwise a
// change made from another session fails, or reaches a table of the same
// name in another schema.
func TestTriggerFunctionsFindTheirTablesFromAnySession(t *testing.T) {
	s := migrationStore(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(t.Context(), `SELECT p.proname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
        WHERE p.pronamespace=current_schema()::regnamespace AND l.lanname='plpgsql'
          AND NOT EXISTS(SELECT 1 FROM unnest(coalesce(p.proconfig,'{}')) c WHERE c LIKE 'search_path=%')
          AND EXISTS(SELECT 1 FROM pg_class r WHERE r.relnamespace=p.pronamespace AND r.relkind IN ('r','p','v')
            AND p.prosrc ~ ('\m'||r.relname||'\M'))
        ORDER BY p.proname`)
	if err != nil {
		t.Fatal(err)
	}
	unpinned, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(unpinned) != 0 {
		t.Error("trigger functions that name a table without pinning their search path:", unpinned)
	}
	var schema string
	if err = s.pool.QueryRow(t.Context(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `INSERT INTO organizations(id,name) VALUES ('org-a','A');
        INSERT INTO agents(id,tenant_id) VALUES ('agent-a','org-a');
        INSERT INTO agent_directory(agent_id,tenant_id,description,skills) VALUES ('agent-a','org-a','An agent','{1}')`); err != nil {
		t.Fatal(err)
	}
	// An operator's session: the default search path, which does not hold
	// this schema, and names qualified by it.
	operator, err := pgxpool.New(t.Context(), databaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	for _, change := range []string{
		"UPDATE " + pgx.Identifier{schema, "agents"}.Sanitize() + " SET discoverable=NOT discoverable WHERE id='agent-a'",
		"UPDATE " + pgx.Identifier{schema, "organizations"}.Sanitize() + " SET status='disabled' WHERE id='org-a'",
	} {
		if _, err = operator.Exec(t.Context(), change); err != nil {
			t.Fatal(change, err)
		}
	}
	var revision int64
	if err = s.pool.QueryRow(t.Context(), "SELECT revision FROM agent_directory WHERE agent_id='agent-a'").Scan(&revision); err != nil || revision != 3 {
		t.Fatal("the directory record did not follow both changes:", revision, err)
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
        DROP INDEX IF EXISTS platform_operations_finished, agent_requests_finished, agent_requests_mandate, agent_mailboxes_reference,
          idempotency_keys_response, inbox_items_reference, owner_messages_request, peer_wakes_request, tenant_agent_audit_request,
          corpus_builds_invocation, corpus_extensions_invocation;
        DROP TABLE IF EXISTS agent_activity;
        DROP FUNCTION IF EXISTS agent_activity_from_operations(), agent_activity_from_requests(), agent_activity_from_model_calls() CASCADE;
        DROP FUNCTION IF EXISTS agent_activity_upsert(text[], timestamptz[], timestamptz[]);
        DROP INDEX IF EXISTS agent_placements_host, platform_operations_open, platform_operations_open_host, platform_operations_sleeps,
          agent_requests_open_sender, agent_requests_open_recipient, request_closures_fencing, llm_usage_reserved,
          transit_payloads_purge_due, transit_payloads_unstarted;
        DROP FUNCTION IF EXISTS work_notify_outbox(), work_notify_mailbox(), work_notify_operation(), work_notify_closure(),
          work_notify_deletion(), work_notify_placement() CASCADE;
        DROP FUNCTION IF EXISTS work_notify_agent(text), work_notify_host(text);
        ALTER TABLE agents DROP COLUMN IF EXISTS enricher_id CASCADE;
        DROP FUNCTION IF EXISTS corpus_remember_conversion(), corpus_notify_build(), corpus_notify_file_progress() CASCADE;
        ALTER TABLE IF EXISTS corpus_builds DROP COLUMN IF EXISTS conversion_invocation_id;
        DROP TABLE IF EXISTS corpus_audit, corpus_extensions, corpus_enrichers, corpus_review_segments, corpus_review_files, agent_corpora, corpus_releases, corpus_builds, corpora, source_credentials;
        DROP FUNCTION IF EXISTS protect_corpus_release();
        ALTER TABLE agents DROP COLUMN IF EXISTS kind CASCADE, DROP COLUMN IF EXISTS builder_principal CASCADE;
        ALTER TABLE organization_quotas DROP COLUMN IF EXISTS max_corpus_builds, DROP COLUMN IF EXISTS max_corpus_storage_mib;
        ALTER TABLE harness_releases DROP COLUMN IF EXISTS base;
        DROP TABLE IF EXISTS invocation_stream_chunks, invocation_streams;
        DROP FUNCTION IF EXISTS invocation_stream_notify_operation(), invocation_stream_notify_status(), organization_policy_notify() CASCADE;
        ALTER TABLE owner_instructions DROP COLUMN IF EXISTS attempt;
        ALTER TABLE transit_payloads DROP CONSTRAINT IF EXISTS transit_payloads_kind_check;
        ALTER TABLE transit_payloads ADD CONSTRAINT transit_payloads_kind_check
          CHECK (kind IN ('instruction','instruction_result','request','reply','owner_message'));
        DROP TABLE IF EXISTS agent_volume_growth, deployment_audit;
        ALTER TABLE IF EXISTS agent_specs DROP COLUMN IF EXISTS reserved_growth_mib;
        ALTER TABLE IF EXISTS volume_restores DROP COLUMN IF EXISTS grow_to_mib;
        DROP TABLE IF EXISTS agent_rollout_steps, agent_rollouts;
        ALTER TABLE agent_specs DROP COLUMN IF EXISTS template_grant_id, DROP COLUMN IF EXISTS system_image;
        DROP VIEW IF EXISTS agent_pool_inventory, available_pool_members;
        ALTER TABLE agent_assignments DROP COLUMN IF EXISTS policy_id;
        ALTER TABLE team_memberships DROP COLUMN IF EXISTS source_app_id;
        DROP TABLE IF EXISTS app_personal_reservations, app_invitations, app_activations, app_policies, application_audit, applications;
        DROP TABLE IF EXISTS agent_pool_members, agent_pools, agent_deployment_members, agent_deployments,
          agent_template_revisions, host_system_images, deployment_hosts, system_images;
        ALTER TABLE worker_jobs DROP COLUMN IF EXISTS capacity_wait;
        DROP TABLE IF EXISTS organization_quotas;
        ALTER TABLE IF EXISTS organization_audit DROP CONSTRAINT IF EXISTS organization_audit_action_check;
        ALTER TABLE IF EXISTS organization_audit ADD CONSTRAINT organization_audit_action_check
          CHECK (action IN ('organization.created','organization.disabled'));
        DROP TABLE IF EXISTS trace_pseudonym_key;
        DROP TABLE IF EXISTS tenant_refusal_audit;
        DROP INDEX IF EXISTS instruction_replays_tenant;
        DROP TABLE IF EXISTS authority_reconciliations;
        ALTER TABLE http_receipts DROP COLUMN IF EXISTS key_day;
        ALTER TABLE tenant_http_receipts DROP COLUMN IF EXISTS key_day;
        DROP VIEW IF EXISTS personal_volume_holds;
        DROP TABLE IF EXISTS access_revocations;
        DROP FUNCTION IF EXISTS preserve_access_revocation();
        DROP TABLE IF EXISTS volume_relocations, host_takeovers;
        DROP FUNCTION IF EXISTS preserve_volume_relocation(), preserve_host_takeover();
        DROP TABLE IF EXISTS operator_audit, audit_retention;
        ALTER TABLE worker_hosts DROP COLUMN IF EXISTS data_pressure, DROP COLUMN IF EXISTS image_pressure,
          DROP COLUMN IF EXISTS pressure_observed_at;
        DROP INDEX IF EXISTS organization_audit_created, delegation_audit_created, tenant_member_audit_created,
          tenant_team_audit_created, tenant_agent_audit_created, tenant_service_audit_created, llm_audit_created,
          queue_audit_created, harness_audit_created;
        DROP TABLE IF EXISTS capability_audit, agent_capability_policies, organization_capability_policies;
        ALTER TABLE harness_releases DROP COLUMN IF EXISTS capabilities;
        DROP TABLE IF EXISTS instruction_replays, capacity_waits;
        ALTER TABLE worker_jobs DROP CONSTRAINT IF EXISTS worker_jobs_kind_check;
        ALTER TABLE worker_jobs ADD CONSTRAINT worker_jobs_kind_check
          CHECK (kind IN ('delivery','closure','deletion','expiration','provision','lifecycle'));
        DROP TABLE IF EXISTS platform_audit, delegation_keys;
        DROP INDEX IF EXISTS organizations_active_name, delegation_trusts_issuer_audience;
        ALTER TABLE IF EXISTS delegation_audit DROP COLUMN IF EXISTS key_id, DROP CONSTRAINT IF EXISTS delegation_audit_action_check;
        ALTER TABLE IF EXISTS delegation_audit ADD CONSTRAINT delegation_audit_action_check CHECK (action IN ('install','rotate','revoke-trust','revoke-token'));
        ALTER TABLE IF EXISTS delegation_trusts DROP COLUMN IF EXISTS allowed_scopes, DROP COLUMN IF EXISTS max_ttl_nanoseconds;
        DROP TABLE IF EXISTS peer_redeliveries;
        DROP FUNCTION IF EXISTS preserve_peer_redelivery();
        DROP TABLE IF EXISTS failed_agents, guest_failures;
        DROP TABLE IF EXISTS llm_alias_grants;
        DROP TABLE IF EXISTS invocation_reruns;
        DROP FUNCTION IF EXISTS preserve_invocation_rerun();
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
