package controlplane

import (
	"regexp"
	"slices"
	"testing"
)

// Every table the migrations create is in durableTables, the list each
// transaction checks for UNLOGGED tables and each migration checks for
// missing ones; and the list names no table that no migration creates.
// peer_redeliveries, host_takeovers and volume_relocations, among others,
// were missing: an UNLOGGED copy of them went unnoticed.
func TestEveryTableIsDurable(t *testing.T) {
	created := map[string]bool{"schema_migrations": true} // created by migrate itself
	pattern := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	for _, m := range controlPlaneMigrations {
		for _, match := range pattern.FindAllStringSubmatch(m.sql, -1) {
			created[match[1]] = true
		}
	}
	for table := range created {
		if !slices.Contains(durableTables, table) {
			t.Error("a migration creates a table missing from durableTables:", table)
		}
	}
	for _, table := range durableTables {
		if !created[table] {
			t.Error("durableTables names a table no migration creates:", table)
		}
	}
	if len(slices.Compact(slices.Sorted(slices.Values(durableTables)))) != len(durableTables) {
		t.Error("durableTables names a table twice")
	}
}
