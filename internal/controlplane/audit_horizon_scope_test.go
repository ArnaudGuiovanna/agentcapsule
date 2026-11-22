package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// holdAuditFeedLock opens a transaction on s that writes an audit event of
// tenant, and so holds that organization's feed lock until the test ends.
func holdAuditFeedLock(t *testing.T, s *Store, tenant, actor string) {
	t.Helper()
	open, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rollback(open) })
	if _, err = open.Exec(t.Context(), `INSERT INTO application_audit(id,tenant_id,actor,target,action) VALUES($1,$2,$3,'open','application.registered')`,
		newID("audit"), tenant, actor); err != nil {
		t.Fatal(err)
	}
}

// The feed lock belongs to one schema, as the store's gate does (FIX-2): a
// page waits only for the audited transactions of its own installation.
// Until then the lock's key was the organization's ID alone, so a page of
// one schema waited for another schema's writers of an organization with
// the same ID, then answered 503 after five seconds.
func TestAuditFeedWaitsOnlyForItsOwnSchemasWriters(t *testing.T) {
	l, _, owner := agentLab(t)
	other, _ := freshStore(t, "auto", 1)
	if _, err := other.pool.Exec(t.Context(), `INSERT INTO organizations(id,name) VALUES ($1,'Same ID, another schema')`, owner.TenantID); err != nil {
		t.Fatal(err)
	}
	holdAuditFeedLock(t, other, owner.TenantID, "someone")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := l.a.ListAudit(ctx, owner, "", 10); err != nil {
		t.Fatalf("a page waited for another schema's writer: %v after %v", err, time.Since(started))
	}
	// Its own schema's writer still holds it back.
	holdAuditFeedLock(t, l.s, owner.TenantID, owner.ID)
	short, stop := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer stop()
	if page, err := l.a.ListAudit(short, owner, "", 10); err == nil {
		t.Fatal("a page was read while an audited transaction of its schema was open:", page.Items)
	}
}

// A caller who may not read the trail is refused at once (FIX-2): ListAudit
// checks the caller's rights before it waits for the trail's horizon. Until
// then it waited first, up to five seconds, so that any caller of the
// organization could hold an API connection that long.
func TestAuditFeedRefusesBeforeItWaits(t *testing.T) {
	l, _, owner := agentLab(t)
	addMember(t, l, owner, "usr", authorization.AgentUser)
	user := agentPrincipal(t, l, "usr", agentScopes)
	holdAuditFeedLock(t, l.s, owner.TenantID, owner.ID)
	started := time.Now()
	if _, err := l.a.ListAudit(t.Context(), user, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("a caller without audit rights:", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatal("a caller without audit rights waited for the trail's horizon:", waited)
	}
	// Without the scope, too.
	if _, err := l.a.ListAudit(t.Context(), agentPrincipal(t, l, "usr", "org:read"), "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("a caller without the scope:", err)
	}
}
