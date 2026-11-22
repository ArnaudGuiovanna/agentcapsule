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
	Version                int64  `json:"version"`
	Name                   string `json:"name"`
	SHA256                 string `json:"sha256"`
	CompatibleWithPrevious bool   `json:"compatible_with_previous,omitempty"`
}

// MigrationManifest returns the ordered history compiled into the admin binary.
func MigrationManifest() []MigrationRecord {
	records := make([]MigrationRecord, len(controlPlaneMigrations))
	for i, migration := range controlPlaneMigrations {
		records[i] = MigrationRecord{migration.version, migration.name, fmt.Sprintf("%x", sha256.Sum256([]byte(migration.sql))), migration.expands()}
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
	online := false
	for i, m := range migrations {
		if m.version != int64(i+1) || m.name == "" || m.sql == "" {
			return ErrMigrationHistory
		}
		if err := m.checkDeclaration(); err != nil {
			return err
		}
		online = online || m.expands()
	}
	if online {
		return s.migrateRolling(ctx, migrations)
	}
	tx, err := s.beginCensus(ctx, true)
	if err != nil {
		return err
	}
	return migrateBatch(ctx, tx, migrations, true)
}

// migrateBatch commits transactional DDL, receipts and grants together. A
// concurrent index has already been built on the migration session.
func migrateBatch(ctx context.Context, tx pgx.Tx, migrations []schemaMigration, final bool) error {
	var err error
	defer rollback(tx)
	// Offline maintenance can wait for locks. An expand that cannot get its
	// DDL lock promptly releases it for a later retry, so queued writers resume.
	settings := "SET LOCAL statement_timeout = 0; SET LOCAL lock_timeout = 0"
	if migrations[len(migrations)-1].expands() {
		settings = "SET LOCAL statement_timeout = 0; SET LOCAL lock_timeout = '5s'"
	}
	if _, err = tx.Exec(ctx, settings); err != nil {
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
	applied, err := migrationLedger(ctx, tx, migrations, false)
	if err != nil {
		return err
	}
	for _, m := range migrations[applied:] {
		if !m.concurrentIndex() {
			if _, err = tx.Exec(ctx, m.sql); err != nil {
				return fmt.Errorf("apply schema migration %d: %w", m.version, err)
			}
		}
		checksum := sha256.Sum256([]byte(m.sql))
		insert := "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)"
		if m.expands() {
			insert = "INSERT INTO schema_migrations(version,name,checksum,compatible_with_previous) VALUES($1,$2,$3,true)"
		}
		if _, err = tx.Exec(ctx, insert, m.version, m.name, checksum[:]); err != nil {
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
	if !final {
		return commit(ctx, tx)
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

// Readiness accepts a newer contiguous suffix if every step explicitly
// preserved the preceding binary's reads and writes.
func checkMigrationLedger(ctx context.Context, tx pgx.Tx, migrations []schemaMigration) error {
	applied, err := migrationLedger(ctx, tx, migrations, true)
	if err == nil && applied < len(migrations) {
		return fmt.Errorf("%w: schema at version %d, binary requires %d", ErrMigrationHistory, applied, len(migrations))
	}
	return err
}

type ledgerReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func migrationLedger(ctx context.Context, db ledgerReader, migrations []schemaMigration, allowExpand bool) (int, error) {
	// Converting the row also works before 0083 adds the declaration column.
	rows, err := db.Query(ctx, `SELECT version,name,checksum,
        coalesce((to_jsonb(m)->>'compatible_with_previous')::boolean,false)
        FROM schema_migrations AS m ORDER BY version`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	applied := 0
	for rows.Next() {
		var version int64
		var name string
		var checksum []byte
		var expands bool
		if err := rows.Scan(&version, &name, &checksum, &expands); err != nil {
			return 0, err
		}
		if version != int64(applied+1) || (applied >= len(migrations) && !(allowExpand && expands)) {
			return 0, fmt.Errorf("%w: unexpected installed version %d", ErrMigrationHistory, version)
		}
		if applied < len(migrations) {
			m := migrations[applied]
			want := sha256.Sum256([]byte(m.sql))
			if name != m.name || !bytes.Equal(checksum, want[:]) || expands != m.expands() {
				return 0, fmt.Errorf("%w: version %d differs from this binary", ErrMigrationHistory, version)
			}
		}
		applied++
	}
	return applied, rows.Err()
}
