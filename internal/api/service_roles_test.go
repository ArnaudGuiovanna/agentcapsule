package api

import (
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// serviceRoles creates the login roles of the API and the worker in the
// test cluster, as the installer does on a host, before a test migrates its
// schema (migration service-roles grants them their privileges then).
func serviceRoles(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL missing")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, role := range []string{"agentcapsule_api", "agentcapsule_worker"} {
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
