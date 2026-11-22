package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReadyDuringExpandAndAfterContract(t *testing.T) {
	s := migrationStore(t)
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	next := int64(len(controlPlaneMigrations) + 1)
	expanded := append(append([]schemaMigration{}, controlPlaneMigrations...), schemaMigration{version: next, name: "test-expand", sql: "-- agentcapsule:expand\nCREATE TABLE rolling_probe (id bigint);"})
	// An API or worker transaction already owns the normal shared gate.
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	ready, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := s.migrate(ready, expanded); err != nil {
		t.Fatal("expand with an active reader:", err)
	}
	retry, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	if err := s.migrate(retry, expanded); err != nil {
		t.Fatal("second host checking an applied expand with an active reader:", err)
	}
	rollback(tx)
	if err := s.Ready(ctx); err != nil {
		t.Fatal("older service after expand:", err)
	}
	// The older admin must never manage a newer ledger, even for an expand.
	if err := s.Migrate(ctx); !errors.Is(err, ErrMigrationHistory) {
		t.Fatal("older admin:", err)
	}
	contracted := append(expanded, schemaMigration{version: next + 1, name: "test-contract", sql: "DROP TABLE rolling_probe"})
	if err := s.migrate(ctx, contracted); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); !errors.Is(err, ErrMigrationHistory) {
		t.Fatal("older service after contract:", err)
	}
}

func TestExpandIndexResumesAndChecksTheDefinition(t *testing.T) {
	s := migrationStore(t)
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "CREATE TABLE rolling_jobs (id bigint, state text)"); err != nil {
		t.Fatal(err)
	}
	next := int64(len(controlPlaneMigrations) + 1)
	sql := "-- agentcapsule:expand-index\nCREATE INDEX CONCURRENTLY rolling_jobs_state ON rolling_jobs (state, id);"
	m := append(append([]schemaMigration{}, controlPlaneMigrations...), schemaMigration{version: next, name: "rolling-jobs-state", sql: sql})
	// A crash after the concurrent build can leave a complete index before its receipt.
	if _, err := s.pool.Exec(ctx, "CREATE INDEX rolling_jobs_state ON rolling_jobs (id)"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx, m); !errors.Is(err, ErrMigrationHistory) {
		t.Fatalf("unrelated index accepted: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DROP INDEX rolling_jobs_state"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", next); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx, m); err != nil {
		t.Fatal("retry after completed index:", err)
	}
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRollingMigrationDeclarationsRefuseAmbiguousIndexBuilds(t *testing.T) {
	for _, sql := range []string{
		"-- agentcapsule:expnad\nSELECT 1",
		expandHeader + "CREATE INDEX jobs_id ON jobs(id);",
		indexHeader + "CREATE INDEX jobs_id ON jobs (id);",
		indexHeader + "CREATE INDEX CONCURRENTLY jobs_id ON jobs (id); SELECT 1;",
	} {
		if err := (schemaMigration{version: 84, name: "jobs", sql: sql}).checkDeclaration(); !errors.Is(err, ErrMigrationHistory) {
			t.Fatal("unsafe migration declaration accepted", sql, err)
		}
	}
}

func TestRollingMigrationRepairsInterruptedConcurrentBuild(t *testing.T) {
	s := migrationStore(t)
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "CREATE TABLE rolling_queue (id bigint)"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, "INSERT INTO rolling_queue VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	n := int64(len(controlPlaneMigrations) + 1)
	m := append(append([]schemaMigration{}, controlPlaneMigrations...), schemaMigration{version: n, name: "rolling-queue-index", sql: indexHeader + "CREATE INDEX CONCURRENTLY rolling_queue_id ON rolling_queue (id);"})
	build, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.migrate(build, m) }()
	// PostgreSQL has committed the invalid catalogue entry and is waiting
	// for the writer. Cancel at this boundary; a later retry must repair it.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var building bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_index WHERE indexrelid=to_regclass('rolling_queue_id') AND NOT indisvalid)").Scan(&building); err != nil {
			t.Fatal(err)
		}
		if building {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("index build finished before its writer: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent build never reached the invalid index")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled build succeeded")
	}
	rollback(tx)
	if got := count(t, s, "schema_migrations"); got != len(controlPlaneMigrations) {
		t.Fatal("interrupted index recorded", got)
	}
	if err := s.migrate(ctx, m); err != nil {
		t.Fatal("retry after canceled build", err)
	}
	var definition string
	if err := s.pool.QueryRow(ctx, "SELECT pg_get_indexdef(indexrelid) FROM pg_index WHERE indexrelid=to_regclass('rolling_queue_id') AND indisvalid").Scan(&definition); err != nil || !strings.Contains(definition, "rolling_queue") {
		t.Fatal(definition, err)
	}
}
