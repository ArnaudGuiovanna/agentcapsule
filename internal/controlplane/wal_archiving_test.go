package controlplane

import (
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/diagnostics"
	"github.com/jackc/pgx/v5"
)

// The archiving state as the worker's metrics read it, against the real
// pg_stat_archiver: any role reads it without a grant, the settings match, and
// a completed segment is either archived (archiving on) or waits.
func TestWALArchivingForMetrics(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	ctx := t.Context()
	var mode, command, library string
	var timeout int64
	if err := s.pool.QueryRow(ctx, `SELECT current_setting('archive_mode'), current_setting('archive_command'),
        current_setting('archive_library'), (SELECT setting::bigint FROM pg_settings WHERE name='archive_timeout')`).Scan(&mode, &command, &library, &timeout); err != nil {
		t.Fatal(err)
	}
	enabled := mode != "off" && (command != "" || library != "")
	first, err := s.WALArchiving(ctx)
	if err != nil || first.Enabled != enabled || first.Timeout != time.Duration(timeout)*time.Second || first.Age < 0 {
		t.Fatal("archiving state", first, err, mode, timeout)
	}

	// A role with no grant at all reads the same state.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{newID("archiver_reader")}.Sanitize()
	if _, err = tx.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN NOSUPERUSER NOINHERIT"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
		t.Fatal(err)
	}
	unprivileged, err := diagnostics.ReadWALArchiving(ctx, tx)
	if rollback := tx.Rollback(ctx); err != nil || rollback != nil || unprivileged.Enabled != enabled || unprivileged.Timeout != first.Timeout {
		t.Fatal("as a role without grants", unprivileged, err, rollback)
	}

	// Close a segment holding a change.
	for _, sql := range []string{"CREATE TABLE wal_probe(n int)", "INSERT INTO wal_probe VALUES (1)", "SELECT pg_switch_wal()"} {
		if _, err = s.pool.Exec(ctx, sql); err != nil {
			t.Fatal(sql, err)
		}
	}
	if !enabled {
		// Nothing archives it: it waits, and the age only grows.
		state, err := s.WALArchiving(ctx)
		if err != nil || !state.Pending || state.Age < first.Age {
			t.Fatal("archiving off, a completed segment", first, state, err)
		}
		return
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		state, err := s.WALArchiving(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !state.Pending && !state.Failing && state.Age < time.Minute {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the completed segment was not archived within a minute", state)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
