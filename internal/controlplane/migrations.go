package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrMigrationHistory refuses an unknown, modified or incomplete migration
// history. Retrying with the correct binary is safe; deleting history is not a
// repair procedure. Database owners remain trusted to preserve this metadata.
var ErrMigrationHistory = errors.New("database migration history does not match this binary")

type schemaMigration struct {
	version int64
	name    string
	sql     string
}

// MigrationRecord describes the ledger row the binary expects after a migration.
type MigrationRecord struct {
	Version int64  `json:"version"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
}

// MigrationManifest returns the ordered history compiled into the admin binary.
func MigrationManifest() []MigrationRecord {
	records := make([]MigrationRecord, len(controlPlaneMigrations))
	for i, migration := range controlPlaneMigrations {
		records[i] = MigrationRecord{migration.version, migration.name, fmt.Sprintf("%x", sha256.Sum256([]byte(migration.sql)))}
	}
	return records
}

// Append migrations; never edit an installed migration. The original schema
// also upgrades pre-ledger installations, preserving its historical backfills.
// Later calls validate its checksum without replaying DDL or those backfills.
//
// Each migration is declared once, by its file (audit finding A-08): version
// 1 is schema.sql, named control-plane-baseline; then migrations/NNNN_name.sql
// is version NNNN, named name with hyphens for its underscores. The ledger
// stores these names: a file is never renamed. A file name of another form, a
// version taken twice or a version skipped stops every binary and test at
// start (loadMigrations).
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

var controlPlaneMigrations = mustLoadMigrations()

func mustLoadMigrations() []schemaMigration {
	files, err := fs.Sub(migrationFiles, "migrations")
	if err == nil {
		var migrations []schemaMigration
		if migrations, err = loadMigrations(schemaSQL, files); err == nil {
			return migrations
		}
	}
	panic(err)
}

// migrationFile is the form of a migration's file name: its four-digit
// version, then its name in lower-case words joined by underscores.
var migrationFile = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// loadMigrations is the history whose first migration is baseline and whose
// others are the files of dir, in the order of their names. The versions must
// follow each other from 2, without a gap or a repeat.
func loadMigrations(baseline string, dir fs.FS) ([]schemaMigration, error) {
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		return nil, err
	}
	migrations := []schemaMigration{{version: 1, name: "control-plane-baseline", sql: baseline}}
	for _, e := range entries {
		parts := migrationFile.FindStringSubmatch(e.Name())
		if parts == nil || !e.Type().IsRegular() {
			return nil, fmt.Errorf("%w: migration file %q is not NNNN_name.sql", ErrMigrationHistory, e.Name())
		}
		version, _ := strconv.ParseInt(parts[1], 10, 64)
		if want := int64(len(migrations) + 1); version != want {
			return nil, fmt.Errorf("%w: migration file %q has version %d where %d comes next (a gap or a repeated version)", ErrMigrationHistory, e.Name(), version, want)
		}
		sql, err := fs.ReadFile(dir, e.Name())
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(sql)) == 0 {
			return nil, fmt.Errorf("%w: migration file %q is empty", ErrMigrationHistory, e.Name())
		}
		migrations = append(migrations, schemaMigration{version: version, name: strings.ReplaceAll(parts[2], "_", "-"), sql: string(sql)})
	}
	return migrations, nil
}

func (s *Store) migrate(ctx context.Context, migrations []schemaMigration) error {
	if len(migrations) == 0 {
		return ErrMigrationHistory
	}
	for i, m := range migrations {
		if m.version != int64(i+1) || m.name == "" || m.sql == "" {
			return ErrMigrationHistory
		}
	}
	tx, err := s.beginCensus(ctx, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	// A migration may build indexes and backfill tables for minutes, and
	// waits for another to end: no session bound applies (P-08).
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout = 0; SET LOCAL lock_timeout = 0"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610042)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version bigint PRIMARY KEY CHECK (version > 0),
        name text NOT NULL CHECK (name <> ''),
        checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return err
	}
	applied := 0
	for rows.Next() {
		var version int64
		var name string
		var checksum []byte
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return err
		}
		if applied >= len(migrations) || version != int64(applied+1) {
			rows.Close()
			return ErrMigrationHistory
		}
		m := migrations[applied]
		want := sha256.Sum256([]byte(m.sql))
		if name != m.name || !bytes.Equal(checksum, want[:]) {
			rows.Close()
			return fmt.Errorf("%w: version %d", ErrMigrationHistory, version)
		}
		applied++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, m := range migrations[applied:] {
		if _, err = tx.Exec(ctx, m.sql); err != nil {
			return fmt.Errorf("apply schema migration %d: %w", m.version, err)
		}
		checksum := sha256.Sum256([]byte(m.sql))
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum)
            VALUES($1,$2,$3)`, m.version, m.name, checksum[:]); err != nil {
			return err
		}
	}
	// The service roles' privileges (migration service-roles), again, at the
	// end of every run once the function exists: a role created since the
	// last run gets them now, and a relation a migration of this run created
	// gets the policy's, also when this run applied service-roles itself (a
	// fresh install), whose own grants came before that relation existed.
	var grants bool
	if err = tx.QueryRow(ctx, `SELECT to_regprocedure('agentcapsule_service_grants()') IS NOT NULL`).Scan(&grants); err != nil {
		return err
	}
	if grants {
		if _, err = tx.Exec(ctx, `SELECT agentcapsule_service_grants()`); err != nil {
			return err
		}
	}
	var count int
	var durable bool
	if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_and(relpersistence='p' AND relkind='r'),false)
        FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY($1)`,
		durableTables).Scan(&count, &durable); err != nil {
		return err
	}
	if count != len(durableTables) || !durable {
		return ErrUnsafeDatabase
	}
	return commit(ctx, tx)
}

// checkMigrationLedger is the read-only counterpart of migrate. The API never
// migrates, so readiness must fail when the installed ledger is behind, ahead of
// or different from the migrations compiled into this binary.
func checkMigrationLedger(ctx context.Context, tx pgx.Tx, migrations []schemaMigration) error {
	rows, err := tx.Query(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return err
	}
	defer rows.Close()
	applied := 0
	for rows.Next() {
		var version int64
		var name string
		var checksum []byte
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			return err
		}
		if applied >= len(migrations) || version != int64(applied+1) {
			return fmt.Errorf("%w: unexpected installed version %d", ErrMigrationHistory, version)
		}
		want := sha256.Sum256([]byte(migrations[applied].sql))
		if name != migrations[applied].name || !bytes.Equal(checksum, want[:]) {
			return fmt.Errorf("%w: version %d differs from this binary", ErrMigrationHistory, version)
		}
		applied++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if applied != len(migrations) {
		return fmt.Errorf("%w: schema at version %d, binary requires %d", ErrMigrationHistory, applied, len(migrations))
	}
	return nil
}
