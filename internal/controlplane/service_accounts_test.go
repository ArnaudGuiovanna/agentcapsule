package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func newServiceAccount(t *testing.T, l *tenantLab, p Principal, key, name string, role authorization.Role) ServiceAccount {
	t.Helper()
	r, err := l.a.CreateServiceAccount(t.Context(), p, key, CreateServiceAccountInput{Name: name, Role: role})
	var s ServiceAccount
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &s) != nil {
		t.Fatal("create service account", err, r.Status)
	}
	return s
}

func issueServiceToken(t *testing.T, l *tenantLab, p Principal, id, key string, scopes ...string) IssuedServiceToken {
	t.Helper()
	r, err := l.a.IssueServiceToken(t.Context(), p, id, key, IssueServiceTokenInput{Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour)})
	var token IssuedServiceToken
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &token) != nil || !strings.HasPrefix(token.Token, "acps_") {
		t.Fatal("issue service token", err, r.Status)
	}
	return token
}

func TestServiceAccountRolesAndTokenBounds(t *testing.T) {
	l, _, owner := agentLab(t)
	addMember(t, l, owner, "boss", authorization.OrgAdmin)
	admin := agentPrincipal(t, l, "boss", agentScopes)
	// Nobody creates a technical owner; an administrator creates no administrator.
	if _, err := l.a.CreateServiceAccount(t.Context(), owner, "own", CreateServiceAccountInput{Name: "x", Role: authorization.OrgOwner}); !errors.Is(err, ErrForbidden) {
		t.Fatal("technical owner accepted", err)
	}
	if _, err := l.a.CreateServiceAccount(t.Context(), admin, "adm", CreateServiceAccountInput{Name: "x", Role: authorization.OrgAdmin}); !errors.Is(err, ErrForbidden) {
		t.Fatal("administrator created an administrator account", err)
	}
	if _, err := l.a.CreateServiceAccount(t.Context(), owner, "bad", CreateServiceAccountInput{Name: "x", Role: "root"}); !errors.Is(err, ErrInput) {
		t.Fatal("invalid role accepted", err)
	}
	newServiceAccount(t, l, owner, "ok-admin", "admin bot", authorization.OrgAdmin)
	op := newServiceAccount(t, l, admin, "ok-op", "operator bot", authorization.AgentOperator)

	in := func(scopes ...string) IssueServiceTokenInput {
		return IssueServiceTokenInput{Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour)}
	}
	for name, bad := range map[string]IssueServiceTokenInput{
		"identity scope": in("identity:manage"),
		"platform scope": in("platform:admin"),
		"unknown scope":  in("agent:everything"),
		"wildcard":       in("*"),
		"duplicate":      in("agent:read", "agent:read"),
		"none":           in(),
		"past expiry":    {Scopes: []string{"agent:read"}, ExpiresAt: time.Now().Add(-time.Minute)},
		"too far expiry": {Scopes: []string{"agent:read"}, ExpiresAt: time.Now().Add(400 * 24 * time.Hour)},
		"missing expiry": {Scopes: []string{"agent:read"}},
	} {
		if _, err := l.a.IssueServiceToken(t.Context(), owner, op.ID, "bad-"+name, bad); !errors.Is(err, ErrInput) {
			t.Fatal("accepted:", name, err)
		}
	}
	// A token cannot carry a scope its issuer did not hold.
	narrow := agentPrincipal(t, l, "boss", "org:read identity:manage agent:read")
	if _, err := l.a.IssueServiceToken(t.Context(), narrow, op.ID, "wide", in("agent:read", "agent:create")); !errors.Is(err, ErrInput) {
		t.Fatal("token exceeds its issuer's scopes", err)
	}
	// The secret is stored only as a hash.
	token := issueServiceToken(t, l, admin, op.ID, "good", "org:read", "agent:read", "agent:create")
	want := sha256.Sum256([]byte(token.Token))
	var stored []byte
	if err := l.s.pool.QueryRow(t.Context(), `SELECT token_hash FROM service_tokens WHERE id=$1`, token.ID).Scan(&stored); err != nil || !bytes.Equal(stored, want[:]) {
		t.Fatal("token not stored as a SHA-256 hash", err)
	}
	// Service accounts are not human members.
	if r, err := l.a.ListMembers(t.Context(), owner, "", 100); err != nil || bytes.Contains(mustJSON(r), []byte("operator bot")) {
		t.Fatal("technical account listed among members", err)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestServiceTokenActsWithinItsRoleAndScopesOnly(t *testing.T) {
	l, c, owner := agentLab(t)
	op := newServiceAccount(t, l, owner, "op", "operator bot", authorization.AgentOperator)
	token := issueServiceToken(t, l, owner, op.ID, "tok", "org:read", "agent:read", "agent:create", "member:manage")

	bot, err := l.s.Authenticate(t.Context(), token.Token)
	if err != nil || bot.Kind != "tenant" || bot.TenantID != l.org.ID || bot.ID != op.ID {
		t.Fatal("technical account does not authenticate as a tenant principal", err)
	}
	// Role and scope allow creating agents.
	if _, err = c.Reserve(t.Context(), bot, "bot-agent", tenantAgentInput("bot-made")); err != nil {
		t.Fatal("operator account cannot create an agent:", err)
	}
	// Scope present but role insufficient: member management is for owners and admins.
	if _, err = l.a.CreateMember(t.Context(), bot, "bot-member", memberInput(l, "intruder", authorization.AgentUser)); !errors.Is(err, ErrForbidden) {
		t.Fatal("operator account managed members", err)
	}
	// Role would allow, scope absent: deleting needs agent:delete.
	if _, err = c.Delete(t.Context(), bot, "agt_any", "del"); !errors.Is(err, ErrForbidden) {
		t.Fatal("token without the delete scope deleted", err)
	}
	// A technical account never touches identities, including its own credentials.
	if _, err = l.a.CreateServiceAccount(t.Context(), bot, "bot-svc", CreateServiceAccountInput{Name: "child", Role: authorization.AgentUser}); !errors.Is(err, ErrForbidden) {
		t.Fatal("technical account created another account", err)
	}
	if _, err = l.a.IssueServiceToken(t.Context(), bot, op.ID, "bot-tok", IssueServiceTokenInput{Scopes: []string{"agent:read"}, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrForbidden) {
		t.Fatal("technical account issued a token", err)
	}
	// Wrong or forged secrets do not authenticate.
	for _, bad := range []string{"acps_" + strings.Repeat("A", 43), "acps_short", token.Token[:47] + "x", "acps_" + strings.Repeat("!", 43)} {
		if _, err = l.s.Authenticate(t.Context(), bad); !errors.Is(err, ErrAuthentication) {
			t.Fatal("bad secret accepted", bad, err)
		}
	}
}

func TestServiceTokenRevocationDisablingAndCascade(t *testing.T) {
	l, c, owner := agentLab(t)
	boss := addMember(t, l, owner, "boss", authorization.OrgAdmin)
	admin := agentPrincipal(t, l, "boss", agentScopes)
	op := newServiceAccount(t, l, owner, "op", "operator bot", authorization.AgentOperator)
	other := newServiceAccount(t, l, owner, "op2", "second bot", authorization.AgentUser)

	// Revoking a token ends it, including for a principal authenticated earlier.
	first := issueServiceToken(t, l, owner, op.ID, "t1", "org:read", "agent:read")
	early, err := l.s.Authenticate(t.Context(), first.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.RevokeServiceToken(t.Context(), owner, op.ID, first.ID, "rev1"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.RevokeServiceToken(t.Context(), owner, op.ID, first.ID, "rev1b"); err != nil {
		t.Fatal("revocation is not idempotent", err)
	}
	if _, err = l.s.Authenticate(t.Context(), first.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked token authenticates", err)
	}
	if _, err = c.ListTenantAgents(t.Context(), early, "", 10); err == nil {
		t.Fatal("revoked token still works through an earlier authentication")
	}

	// Offboarding the human who issued a token revokes it; the account remains.
	issued := issueServiceToken(t, l, admin, op.ID, "t2", "org:read", "agent:read")
	if _, err = l.s.Authenticate(t.Context(), issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.RevokeMember(t.Context(), owner, boss.PrincipalID, "fire-boss"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.Authenticate(t.Context(), issued.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("token outlived the person who issued it", err)
	}
	if list, err := l.a.ListServiceAccounts(t.Context(), owner, "", 100); err != nil || len(list) != 2 {
		t.Fatal("offboarding removed a technical account", len(list), err)
	}

	// Demoting an administrator revokes tokens of accounts it can no longer manage.
	addMember(t, l, owner, "boss2", authorization.OrgAdmin)
	admin2 := agentPrincipal(t, l, "boss2", agentScopes)
	adminBot := newServiceAccount(t, l, owner, "ab", "admin bot", authorization.OrgAdmin)
	byAdmin2 := issueServiceToken(t, l, admin2, op.ID, "t3", "org:read")
	byOwner := issueServiceToken(t, l, owner, adminBot.ID, "t4", "org:read")
	boss2 := lookupMember(t, l, owner, "boss2")
	if _, err = l.a.ChangeMemberRole(t.Context(), owner, boss2, "demote", ChangeMemberRoleInput{Role: authorization.AgentUser}); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.Authenticate(t.Context(), byAdmin2.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("token survived its issuer's demotion", err)
	}
	if _, err = l.s.Authenticate(t.Context(), byOwner.Token); err != nil {
		t.Fatal("an owner-issued token was revoked by someone else's demotion", err)
	}

	// Disabling an account revokes all its tokens and blocks new ones.
	live := issueServiceToken(t, l, owner, other.ID, "t5", "org:read")
	if _, err = l.a.DisableServiceAccount(t.Context(), owner, other.ID, "disable"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.Authenticate(t.Context(), live.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("disabled account still authenticates", err)
	}
	if _, err = l.a.IssueServiceToken(t.Context(), owner, other.ID, "t6", IssueServiceTokenInput{Scopes: []string{"org:read"}, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrTransition) {
		t.Fatal("token issued for a disabled account", err)
	}
	var audits int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM tenant_service_audit WHERE tenant_id=$1`, l.org.ID).Scan(&audits); err != nil || audits < 8 {
		t.Fatal("audit trail incomplete", audits, err)
	}
}

func lookupMember(t *testing.T, l *tenantLab, p Principal, subject string) string {
	t.Helper()
	var id string
	if err := l.s.pool.QueryRow(t.Context(), `SELECT id FROM principals WHERE tenant_id=$1 AND subject=$2`, l.org.ID, subject).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
