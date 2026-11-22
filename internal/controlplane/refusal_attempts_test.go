package controlplane

import (
	"errors"
	"testing"
)

// Migration 74 on a trail that already holds refused attempts (v0.1.0 audit,
// L-04): each stands for one attempt; the count of a window is recorded with
// its number and the organization as target; the schema and RecordRefusal
// refuse a count out of bounds; done events carry none.
func TestRefusalAttemptsMigrationKeepsExistingRefusals(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	if _, err := il.s.pool.Exec(ctx, `ALTER TABLE tenant_refusal_audit DROP CONSTRAINT tenant_refusal_audit_attempts_check, DROP COLUMN attempts`); err != nil {
		t.Fatal("revert", err)
	}
	if _, err := il.s.pool.Exec(ctx, `INSERT INTO tenant_refusal_audit(id,tenant_id,actor_principal_id,action,target,reference,reason)
        VALUES('audit_before',$1,$2,'member.created',$1,'','forbidden')`, il.owner.TenantID, il.owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := il.s.pool.Exec(ctx, migrationSQL(t, "refusal-attempts")); err != nil {
		t.Fatal("migrate", err)
	}
	if err := il.a.RecordRefusal(ctx, il.owner, RefusedAttempt{Action: "member.created", Target: "agt_" + "0123456789abcdef0123456789abcdef", Reason: "forbidden"}); err != nil {
		t.Fatal(err)
	}
	if err := il.a.RecordRefusal(ctx, il.owner, RefusedAttempt{Action: "member.created", Reason: "forbidden", Attempts: 41}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int{-1, maxRefusalAttempts + 1} {
		if err := il.a.RecordRefusal(ctx, il.owner, RefusedAttempt{Action: "member.created", Reason: "forbidden", Attempts: bad}); !errors.Is(err, ErrInput) {
			t.Fatal("a count out of bounds", bad, err)
		}
	}
	events, _ := auditTrail(t, il)
	var got []AuditEvent
	for _, e := range events {
		switch {
		case e.Outcome == "refused":
			got = append(got, e)
		case e.Attempts != 0:
			t.Fatal("a done event with attempts", e)
		}
	}
	if len(got) != 3 || got[0].ID != "audit_before" || got[0].Attempts != 1 || got[1].Attempts != 1 || got[1].Target == il.owner.TenantID ||
		got[2].Attempts != 41 || got[2].Target != il.owner.TenantID || got[2].Reference != "" || got[2].Actor != il.owner.ID {
		t.Fatalf("refusals after the migration: %+v", got)
	}
	if _, err := il.s.pool.Exec(ctx, `UPDATE tenant_refusal_audit SET attempts=0 WHERE id='audit_before'`); err == nil {
		t.Fatal("the schema accepted a refusal that stands for no attempt")
	}
}
