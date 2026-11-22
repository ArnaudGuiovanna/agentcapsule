package controlplane

import (
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// ageAudit changes events of an audit table, which its guard refuses, to
// make them look older: test fixtures only. The guard is off for this
// transaction alone.
func ageAudit(t *testing.T, s *Store, table, change string, args ...any) {
	t.Helper()
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	guard := pgx.Identifier{table + "_append_only"}.Sanitize()
	if _, err = tx.Exec(t.Context(), "ALTER TABLE "+table+" DISABLE TRIGGER "+guard); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "UPDATE "+table+" SET "+change, args...); err != nil {
		t.Fatal(table, change, err)
	}
	if _, err = tx.Exec(t.Context(), "ALTER TABLE "+table+" ENABLE TRIGGER "+guard); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Every audit table is append-only (finding L-03): no role changes or
// deletes an event, nor truncates the table, outside the retention purge,
// which deletes only events older than the retention. Only the schema's
// owner sets the retention.
func TestAuditTrailIsAppendOnly(t *testing.T) {
	serviceRoles(t)
	l, c, owner := agentLab(t)
	createTenantAgent(t, c, owner, "audited")
	for _, a := range auditTables {
		rows, err := l.s.pool.Query(t.Context(), `SELECT tgname::text FROM pg_trigger WHERE tgrelid=$1::regclass AND NOT tgisinternal ORDER BY 1`, a.table)
		if err != nil {
			t.Fatal(err)
		}
		guards, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{a.table + "_append_only", a.table + "_no_truncate"} {
			if !slices.Contains(guards, want) {
				t.Error(a.table, "lacks its guard", want, guards)
			}
		}
	}
	var event string
	if err := l.s.pool.QueryRow(t.Context(), `SELECT id FROM tenant_agent_audit WHERE tenant_id=$1 LIMIT 1`, owner.TenantID).Scan(&event); err != nil {
		t.Fatal(err)
	}
	attempts := []string{
		"UPDATE tenant_agent_audit SET action='agent.deleted' WHERE id=$1",
		"UPDATE tenant_agent_audit SET created_at=created_at-interval '400 days' WHERE id=$1",
		"DELETE FROM tenant_agent_audit WHERE id=$1",
	}
	for _, role := range []string{"the owner", "agentcapsule_api", "agentcapsule_worker"} {
		for _, attempt := range attempts {
			run := func(tx pgx.Tx) error { _, err := tx.Exec(t.Context(), attempt, event); return err }
			var err error
			if strings.HasPrefix(role, "agentcapsule") {
				err = asRole(t, l.s, role, run)
			} else {
				err = pgx.BeginFunc(t.Context(), l.s.pool, run)
			}
			if !refused(err) {
				t.Error("as", role, attempt, "was not refused:", err)
			}
		}
	}
	if _, err := l.s.pool.Exec(t.Context(), "TRUNCATE tenant_agent_audit"); !refused(err) {
		t.Error("the owner truncated an audit table", err)
	}

	// The retention: the worker, which purges, cannot set it.
	if err := asRole(t, l.s, "agentcapsule_worker", func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO audit_retention(singleton,retention_days) VALUES(true,30)
            ON CONFLICT (singleton) DO UPDATE SET retention_days=30`)
		return err
	}); !refused(err) {
		t.Error("the worker set the audit retention", err)
	}
	thirty := 30
	if out, err := l.s.SetAuditRetention(t.Context(), testOperator, &thirty); err != nil || out.Outcome != "done" {
		t.Fatal("the owner's retention", out, err)
	}
	if err := asRole(t, l.s, "agentcapsule_worker", func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), "UPDATE audit_retention SET retention_days=31")
		return err
	}); !refused(err) {
		t.Error("the worker changed the audit retention", err)
	}
	// Within the retention an event stays, even for the purge's role; past
	// it, the purge deletes it, as the worker.
	if err := asRole(t, l.s, "agentcapsule_worker", func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), "DELETE FROM tenant_agent_audit WHERE id=$1", event)
		return err
	}); !refused(err) {
		t.Error("the worker deleted an event within the retention", err)
	}
	before := count(t, l.s, "tenant_agent_audit")
	ageAudit(t, l.s, "tenant_agent_audit", "created_at=created_at-interval '31 days' WHERE id=$1", event)
	if n, err := roleStore(t, l.s, "agentcapsule_worker").PurgeAudit(t.Context(), 100); err != nil || n != 1 {
		t.Fatal("the worker's purge", n, err)
	}
	var left bool
	if err := l.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM tenant_agent_audit WHERE id=$1)", event).Scan(&left); err != nil || left {
		t.Fatal("the purge kept an event older than the retention", left, err)
	}
	if after := count(t, l.s, "tenant_agent_audit"); after != before-1 {
		t.Fatal("the purge deleted", before-after, "events, want 1")
	}
}
