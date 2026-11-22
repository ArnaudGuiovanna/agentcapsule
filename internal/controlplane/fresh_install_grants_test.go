package controlplane

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// FIX-1: a run of the migrations that applies the service roles' migration
// and later ones, as a fresh install does, states the grants again at its
// end. A relation that a later migration of the same run creates then holds
// the policy's privileges at once, not the default ones (read and write
// rows) until the next migrate: here a view, which the policy lets the
// services read only. Before, the run skipped the final grants once it had
// applied the service roles' migration.
func TestAFreshInstallGrantsWhatLaterMigrationsCreate(t *testing.T) {
	serviceRoles(t)
	s := migrationStore(t)
	migrations := append(slices.Clone(controlPlaneMigrations), schemaMigration{version: int64(len(controlPlaneMigrations) + 1),
		name: "test-later-relation", sql: `CREATE TABLE later_rows (n integer NOT NULL);
        CREATE VIEW later_view AS SELECT n FROM later_rows`})
	if err := s.migrate(t.Context(), migrations); err != nil {
		t.Fatal(err)
	}
	for _, role := range serviceRoleNames {
		for relation, want := range map[string][]bool{
			"later_view": {true, false, false, false},
			"later_rows": {true, true, true, true},
			"agents":     {true, true, true, false},
		} {
			for i, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				var held bool
				if err := s.pool.QueryRow(t.Context(), `SELECT has_table_privilege($1,$2,$3)`, role, relation, privilege).Scan(&held); err != nil {
					t.Fatal(err)
				}
				if held != want[i] {
					t.Errorf("%s %s on %s after a fresh install: held %v, want %v", role, privilege, relation, held, want[i])
				}
			}
		}
		// As the role: it reads the view and cannot write through it.
		if err := asRole(t, s, role, func(tx pgx.Tx) error {
			var n int
			return tx.QueryRow(t.Context(), `SELECT count(*) FROM later_view`).Scan(&n)
		}); err != nil {
			t.Fatalf("%s cannot read the view: %v", role, err)
		}
		err := asRole(t, s, role, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.WithoutCancel(t.Context()), `INSERT INTO later_view VALUES (1)`)
			return err
		})
		if !refused(err) {
			t.Errorf("%s wrote through the view after a fresh install: %v", role, err)
		}
	}
}
