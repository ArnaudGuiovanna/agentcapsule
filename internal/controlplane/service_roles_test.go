package controlplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// serviceRoleNames are the login roles of the API and the worker (migration
// 0065).
var serviceRoleNames = []string{"agentcapsule_api", "agentcapsule_worker"}

// serviceRoles creates the service roles in the test cluster, as the
// installer does on a host, before a test migrates its schema. Roles belong
// to the cluster: tests running at once may create them together.
func serviceRoles(t *testing.T) {
	t.Helper()
	admin, err := pgxpool.New(t.Context(), databaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, role := range serviceRoleNames {
		_, err := admin.Exec(t.Context(), `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+role+`') THEN CREATE ROLE `+role+` LOGIN; END IF; END $$`)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "42710") {
			err = nil // another test created it meanwhile
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// asRole runs fn in a transaction of its own as role, on the test's schema.
func asRole(t *testing.T, s *Store, role string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(t.Context(), "SET LOCAL ROLE "+role); err != nil {
		t.Fatal(err)
	}
	return fn(tx)
}

// refused reports whether err is PostgreSQL's refusal for want of a
// privilege or of ownership, or a guard trigger's.
func refused(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "42501" || pgErr.Code == "23514")
}

// Each service role reads every table and holds, on each, exactly the write
// privileges that the code its process runs uses (serviceRoleWrites): no
// fewer, or a path would fail in production, and no more. No role truncates,
// references, triggers, creates in the schema or owns anything.
func TestServiceRolesHoldWhatTheirProcessWrites(t *testing.T) {
	serviceRoles(t)
	s, _ := freshStore(t, "auto", 3)
	need := serviceRoleWrites(t)
	var schema string
	if err := s.pool.QueryRow(t.Context(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(t.Context(), `SELECT c.relname,c.relkind FROM pg_class c
        WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind IN ('r','p','v') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	type relation struct{ name, kind string }
	relations, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (relation, error) {
		var v relation
		return v, r.Scan(&v.name, &v.kind)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(relations) < len(durableTables) {
		t.Fatal("the schema lacks tables", len(relations))
	}
	for _, role := range serviceRoleNames {
		for _, rel := range relations {
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
				var held bool
				if err := s.pool.QueryRow(t.Context(), `SELECT has_table_privilege($1,$2,$3)`, role, pgx.Identifier{schema, rel.name}.Sanitize(), privilege).Scan(&held); err != nil {
					t.Fatal(err)
				}
				want := privilege == "SELECT" || need[role][rel.name][privilege]
				if held != want {
					t.Errorf("%s %s on %s: held %v, its process needs %v", role, privilege, rel.name, held, want)
				}
			}
		}
		var create, usage bool
		if err := s.pool.QueryRow(t.Context(), `SELECT has_schema_privilege($1,current_schema(),'CREATE'),has_schema_privilege($1,current_schema(),'USAGE')`, role).Scan(&create, &usage); err != nil {
			t.Fatal(err)
		}
		if create || !usage {
			t.Errorf("%s on the schema: CREATE %v, USAGE %v", role, create, usage)
		}
		var owned int
		if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relowner=$1::regrole)
            + (SELECT count(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proowner=$1::regrole)
            + (SELECT count(*) FROM pg_type WHERE typnamespace=current_schema()::regnamespace AND typowner=$1::regrole)`, role).Scan(&owned); err != nil {
			t.Fatal(err)
		}
		if owned != 0 {
			t.Errorf("%s owns %d objects", role, owned)
		}
	}
}

// A service role cannot get past the permanent guards: it cannot truncate
// a table, disable, drop or replace a trigger or its function, alter or drop
// a table, create one, or turn triggers off for its session. What it may
// write, it writes through the guards. Before the roles, the API and the
// worker connected as the owner, who can do all of it.
func TestServiceRolesCannotTruncateAlterDropOrDisableTheGuards(t *testing.T) {
	serviceRoles(t)
	s, _ := freshStore(t, "auto", 3)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO revocation_catalogue(subject) VALUES ('agent/a')`); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(t.Context(), `SELECT c.relname,t.tgname,p.proname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_proc p ON p.oid=t.tgfoid WHERE c.relnamespace=current_schema()::regnamespace AND NOT t.tgisinternal ORDER BY 1,2`)
	if err != nil {
		t.Fatal(err)
	}
	type trigger struct{ table, name, function string }
	triggers, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (trigger, error) {
		var v trigger
		return v, r.Scan(&v.table, &v.name, &v.function)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []string{"revocation_catalogue_guard", "access_revocation_guard", "store_seal_guard", "store_removal_guard",
		"store_initialization_guard", "host_takeover_guard", "invocation_rerun_guard", "volume_restore_guard", "corpus_release_immutable"} {
		if !slices.ContainsFunc(triggers, func(tr trigger) bool { return tr.name == guard }) {
			t.Fatal("missing guard trigger", guard)
		}
	}
	tables := slices.Clone(durableTables)
	for _, role := range serviceRoleNames {
		// The role works: it reads the guarded table.
		if err := asRole(t, s, role, func(tx pgx.Tx) error {
			var n int
			return tx.QueryRow(t.Context(), `SELECT count(*) FROM revocation_catalogue`).Scan(&n)
		}); err != nil {
			t.Fatalf("%s cannot read: %v", role, err)
		}
		var attempts []string
		for _, table := range tables {
			id := pgx.Identifier{table}.Sanitize()
			attempts = append(attempts, "TRUNCATE "+id, "TRUNCATE "+id+" CASCADE", "ALTER TABLE "+id+" DISABLE TRIGGER ALL",
				"ALTER TABLE "+id+" ADD COLUMN intruder text", "DROP TABLE "+id+" CASCADE", "ALTER TABLE "+id+" OWNER TO "+role)
		}
		for _, tr := range triggers {
			table, name := pgx.Identifier{tr.table}.Sanitize(), pgx.Identifier{tr.name}.Sanitize()
			attempts = append(attempts, "ALTER TABLE "+table+" DISABLE TRIGGER "+name, "DROP TRIGGER "+name+" ON "+table,
				"ALTER TABLE "+table+" ENABLE REPLICA TRIGGER "+name,
				"CREATE OR REPLACE FUNCTION "+pgx.Identifier{tr.function}.Sanitize()+"() RETURNS trigger LANGUAGE plpgsql AS $f$BEGIN RETURN NEW; END$f$",
				"DROP FUNCTION "+pgx.Identifier{tr.function}.Sanitize()+"() CASCADE")
		}
		attempts = append(attempts, "SET session_replication_role = replica", "CREATE TABLE intruder(id int)",
			"CREATE FUNCTION intruder() RETURNS int LANGUAGE sql AS 'SELECT 1'", "SELECT agentcapsule_service_grants()",
			"DELETE FROM revocation_catalogue", "UPDATE revocation_catalogue SET subject='agent/b'",
			"DELETE FROM store_seals", "DELETE FROM access_revocations", "UPDATE schema_migrations SET name='intruder'",
			"DELETE FROM schema_migrations", "INSERT INTO schema_migrations(version,name,checksum) VALUES (1000,'intruder','\\x00')")
		for _, statement := range attempts {
			err := asRole(t, s, role, func(tx pgx.Tx) error {
				_, err := tx.Exec(context.WithoutCancel(t.Context()), statement)
				return err
			})
			if !refused(err) {
				t.Errorf("%s: %s: %v, want a refusal", role, statement, err)
			}
		}
	}
	var subjects int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM revocation_catalogue WHERE subject='agent/a'`).Scan(&subjects); err != nil || subjects != 1 {
		t.Fatal("the catalogue changed", subjects, err)
	}
	var enabled int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relnamespace=current_schema()::regnamespace AND NOT t.tgisinternal AND t.tgenabled='O'`).Scan(&enabled); err != nil || enabled != len(triggers) {
		t.Fatal("a trigger is no longer enabled", enabled, len(triggers), err)
	}
}

// agentcapsule-admin migrate gives a role created after the migrations its
// privileges: the run checks the ledger, applies nothing, and states the
// grants again.
func TestMigrateGrantsARoleCreatedLater(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	serviceRoles(t)
	var schema string
	if err := s.pool.QueryRow(t.Context(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// Other tests may have created the roles before this schema migrated:
	// take them back to make the case.
	for _, role := range serviceRoleNames {
		if _, err := s.pool.Exec(t.Context(), fmt.Sprintf("REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM %s",
			pgx.Identifier{schema}.Sanitize(), role)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, role := range serviceRoleNames {
		var read, write bool
		if err := s.pool.QueryRow(t.Context(), `SELECT has_table_privilege($1,'agents','SELECT'),has_table_privilege($1,'agents','UPDATE')`, role).Scan(&read, &write); err != nil {
			t.Fatal(err)
		}
		if !read || !write {
			t.Errorf("%s after migrate: read %v, update %v", role, read, write)
		}
	}
	if !strings.HasPrefix(schema, "test_") {
		t.Fatal("unexpected schema", schema)
	}
}
