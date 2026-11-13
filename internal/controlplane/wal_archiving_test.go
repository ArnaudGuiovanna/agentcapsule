package controlplane

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// How pg_stat_archiver's row becomes the archiving state, NULLs included: no
// archive or no failure since the statistics began, no completed segment.
func TestWALArchivingStateFromStatistics(t *testing.T) {
	text := func(s string) *string { return &s }
	seconds := func(f float64) *float64 { return &f }
	const s5, s6 = "000000010000000000000005", "000000010000000000000006"
	for _, c := range []struct {
		name string
		row  archiverRow
		want WALArchiving
	}{
		{"nothing archived since the statistics began", archiverRow{enabled: true, timeout: 300, statisticsAge: 1200, lastComplete: text(s5)},
			WALArchiving{Enabled: true, Timeout: 5 * time.Minute, Age: 20 * time.Minute, Pending: true}},
		{"every completed segment archived", archiverRow{enabled: true, timeout: 300, lastArchived: text(s5), archivedAge: seconds(42), statisticsAge: 9000, lastComplete: text(s5)},
			WALArchiving{Enabled: true, Timeout: 5 * time.Minute, Age: 42 * time.Second}},
		{"an idle database: old archive, nothing pending", archiverRow{enabled: true, lastArchived: text(s5), archivedAge: seconds(86400), statisticsAge: 90000, lastComplete: text(s5)},
			WALArchiving{Enabled: true, Age: 24 * time.Hour}},
		{"a completed segment waits", archiverRow{enabled: true, lastArchived: text(s5), archivedAge: seconds(1000), statisticsAge: 9000, lastComplete: text(s6)},
			WALArchiving{Enabled: true, Age: 1000 * time.Second, Pending: true}},
		{"the latest attempt failed", archiverRow{enabled: true, lastArchived: text(s5), archivedAge: seconds(1000), failedAge: seconds(30), statisticsAge: 9000, lastComplete: text(s6)},
			WALArchiving{Enabled: true, Age: 1000 * time.Second, Pending: true, Failing: true}},
		{"a failure a retry archived", archiverRow{enabled: true, lastArchived: text(s6), archivedAge: seconds(10), failedAge: seconds(70), statisticsAge: 9000, lastComplete: text(s6)},
			WALArchiving{Enabled: true, Age: 10 * time.Second}},
		{"failing since the statistics began", archiverRow{enabled: true, failedAge: seconds(5), statisticsAge: 600, lastComplete: text(s5)},
			WALArchiving{Enabled: true, Age: 10 * time.Minute, Pending: true, Failing: true}},
		{"a backup label refers to its segment", archiverRow{lastArchived: text(s5 + ".00000028.backup"), archivedAge: seconds(1), lastComplete: text(s5)},
			WALArchiving{Age: time.Second}},
		{"after a backup label, the next segment waits", archiverRow{lastArchived: text(s5 + ".00000028.backup"), archivedAge: seconds(1), lastComplete: text(s6)},
			WALArchiving{Age: time.Second, Pending: true}},
		{"a segment of a newer timeline waits", archiverRow{lastArchived: text(s6), archivedAge: seconds(1), lastComplete: text("000000020000000000000006")},
			WALArchiving{Age: time.Second, Pending: true}},
		{"after a history file, the new timeline's segment waits", archiverRow{lastArchived: text("00000002.history"), archivedAge: seconds(1), lastComplete: text("000000020000000000000006")},
			WALArchiving{Age: time.Second, Pending: true}},
		{"no completed segment (a standby)", archiverRow{statisticsAge: 60},
			WALArchiving{Age: time.Minute}},
		{"archiving off; no negative duration", archiverRow{timeout: -1, statisticsAge: -0.5, lastComplete: text(s5)},
			WALArchiving{Pending: true}},
	} {
		if got := c.row.state(); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

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
	unprivileged, err := readWALArchiving(ctx, tx)
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
