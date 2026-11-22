package controlplane

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const expandHeader = "-- agentcapsule:expand\n"
const indexHeader = "-- agentcapsule:expand-index\n"

func (m schemaMigration) concurrentIndex() bool { return strings.HasPrefix(m.sql, indexHeader) }
func (m schemaMigration) expands() bool {
	return m.concurrentIndex() || strings.HasPrefix(m.sql, expandHeader)
}

var createIndex = regexp.MustCompile(`(?is)\bcreate\s+(?:unique\s+)?index\b`)

// An online index migration is one ordinary btree index on named columns.
// The restricted grammar lets a retry compare the complete PostgreSQL
// definition before reusing or repairing an index of the same name.
var onlineIndex = regexp.MustCompile(`^CREATE INDEX CONCURRENTLY ([a-z_][a-z0-9_]{0,62}) ON ([a-z_][a-z0-9_]{0,62}) \(([a-z_][a-z0-9_]{0,62}(?:, [a-z_][a-z0-9_]{0,62})*)\);$`)

func (m schemaMigration) checkDeclaration() error {
	if m.concurrentIndex() {
		if !onlineIndex.MatchString(strings.TrimSpace(strings.TrimPrefix(m.sql, indexHeader))) {
			return fmt.Errorf("%w: version %d must declare one concurrent index on named columns", ErrMigrationHistory, m.version)
		}
	} else if m.expands() {
		if createIndex.MatchString(m.sql) {
			return fmt.Errorf("%w: version %d requires an expand-index migration", ErrMigrationHistory, m.version)
		}
	} else if strings.HasPrefix(strings.TrimSpace(m.sql), "-- agentcapsule:") {
		return fmt.Errorf("%w: version %d has an unknown migration declaration", ErrMigrationHistory, m.version)
	}
	return nil
}

// migrateRolling owns a connection until the entire migration plan ends.
// The per-schema session lock spans concurrent builds outside a transaction.
// Closing that connection releases the lock even after cancellation or crash.
func (s *Store) migrateRolling(ctx context.Context, migrations []schemaMigration) error {
	reserved, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := reserved.Hijack()
	defer func() {
		end, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(end)
	}()
	if _, err = conn.Exec(ctx, `SET statement_timeout=0; SET lock_timeout=0; SET synchronous_commit=on;
        SELECT pg_advisory_lock(hashtextextended(current_schema()::text,756610048))`); err != nil {
		return err
	}
	var exists bool
	if err = conn.QueryRow(ctx, "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
		return err
	}
	applied := 0
	if exists {
		applied, err = migrationLedger(ctx, conn, migrations, false)
		if err != nil {
			return err
		}
	}
	for {
		end := applied
		expand := applied < len(migrations) && migrations[applied].expands()
		if expand {
			m := migrations[applied]
			if m.concurrentIndex() {
				if err := ensureOnlineIndex(ctx, conn, m); err != nil {
					return err
				}
			}
			end++
		} else {
			for end < len(migrations) && !migrations[end].expands() {
				end++
			}
		}
		// The old offline migrations remain one atomic group. An expand
		// shares the normal store gate and commits its own receipt.
		options := pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
		// A second host may have applied the entire release already. Its
		// final ledger and grant checks can run alongside active readers.
		options.BeginQuery = preamble(ctx, !expand && end > applied, options, true)
		tx, err := conn.BeginTx(ctx, options)
		if err != nil {
			return err
		}
		if err = migrateBatch(ctx, tx, migrations[:end], end == len(migrations)); err != nil {
			return err
		}
		if end == len(migrations) {
			return nil
		}
		applied = end
	}
}

func ensureOnlineIndex(ctx context.Context, conn *pgx.Conn, m schemaMigration) error {
	sql := strings.TrimSpace(strings.TrimPrefix(m.sql, indexHeader))
	parts := onlineIndex.FindStringSubmatch(sql)
	index, table, columns := parts[1], parts[2], strings.Split(parts[3], ", ")
	// The build itself runs outside the transaction that records it. Check
	// the same durability settings before allowing any index DDL.
	if _, err := conn.Exec(ctx, durabilityQuery); err != nil {
		return err
	}
	// Compare the schema, table, access method, order and every column.
	var matches, valid bool
	err := conn.QueryRow(ctx, `SELECT coalesce(pg_get_indexdef(c.oid)=format('CREATE INDEX %I ON %I.%I USING btree (%s)',
            $1::text,current_schema(),$2::text,
            (SELECT string_agg(quote_ident(col),', ' ORDER BY n) FROM unnest($3::text[]) WITH ORDINALITY AS x(col,n))),false),
            coalesce(i.indisvalid,false)
        FROM pg_class c LEFT JOIN pg_index i ON i.indexrelid=c.oid
        WHERE c.relnamespace=current_schema()::regnamespace AND c.relname=$1`, index, table, columns).Scan(&matches, &valid)
	if err == nil {
		if !matches {
			return fmt.Errorf("%w: index %s has a different definition", ErrMigrationHistory, index)
		}
		if valid {
			return nil
		}
		if _, err = conn.Exec(ctx, "DROP INDEX CONCURRENTLY "+pgx.Identifier{index}.Sanitize()); err != nil {
			return err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err = conn.Exec(ctx, sql); err != nil {
		return fmt.Errorf("build index for migration %d: %w", m.version, err)
	}
	return nil
}
