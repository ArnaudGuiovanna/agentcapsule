//go:build linux && cgo

package restoreauthority

import (
	"database/sql"
	"testing"
)

// A commit in DELETE journal mode is the deletion of the journal. Only
// synchronous=EXTRA syncs the directory after it, so that a power loss right
// after an acknowledgment cannot roll the record back (SYNC_ACK).
func TestAuthorityDatabasesSyncTheJournalDeletion(t *testing.T) {
	p := replicated(t)
	reopened := reopen(t, p.catalog)
	for name, db := range map[string]*sql.DB{
		"catalogue":          p.catalog.db,
		"reopened catalogue": reopened.db,
		"replica":            p.replica.db,
	} {
		var journal string
		var synchronous int
		if err := db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatal(name, err)
		}
		if err := db.QueryRowContext(t.Context(), "PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(name, err)
		}
		if journal != "delete" || synchronous != 3 {
			t.Fatalf("%s: journal_mode=%s synchronous=%d, want delete and 3 (EXTRA)", name, journal, synchronous)
		}
	}
}
