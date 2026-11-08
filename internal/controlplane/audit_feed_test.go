package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func TestAuditFeedIsCompletePagedAndMetadataOnly(t *testing.T) {
	l, c, owner := agentLab(t)
	id := createTenantAgent(t, c, owner, "audited")
	member := addMember(t, l, owner, "grace", authorization.AgentUser)
	team := createTeam(t, l, owner, "audit-team")
	assign(t, l, owner, id, CreateAssignmentInput{TeamID: team.ID, Permissions: []string{"read_metadata"}}, "audit-asg")
	svc := newServiceAccount(t, l, owner, "audit-svc", "audit bot", authorization.Auditor)
	issueServiceToken(t, l, owner, svc.ID, "audit-tok", "audit:read")

	// Page through with a tiny limit and rebuild the whole trail.
	var all []AuditEvent
	cursor := ""
	for range 50 {
		page, err := l.a.ListAudit(t.Context(), owner, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Items...)
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	seen := map[string]bool{}
	actions := map[string]bool{}
	var last time.Time
	for _, e := range all {
		if e.ID == "" || e.Actor == "" || e.Target == "" || e.Action == "" || seen[e.ID] {
			t.Fatal("malformed or duplicated audit event", e)
		}
		if e.CreatedAt.Before(last) {
			t.Fatal("audit events are not in order")
		}
		seen[e.ID], actions[e.Action], last = true, true, e.CreatedAt
	}
	for _, want := range []string{"organization.created", "agent.created", "member.created", "team.created", "assignment.created", "service_account.created", "token.issued"} {
		if !actions[want] {
			t.Fatal("audit trail lacks", want, actions)
		}
	}
	_ = member
	// A single page of everything agrees with the paged walk.
	whole, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil || len(whole.Items) != len(all) {
		t.Fatal("paged and whole listings disagree", len(whole.Items), len(all), err)
	}
	if _, err = l.a.ListAudit(t.Context(), owner, "not-a-cursor!", 10); !errors.Is(err, ErrInput) {
		t.Fatal("garbage cursor accepted", err)
	}
	if _, err = l.a.ListAudit(t.Context(), owner, "", 0); !errors.Is(err, ErrInput) {
		t.Fatal("zero limit accepted", err)
	}
}

func TestAuditFeedFollowsRoleAndScope(t *testing.T) {
	l, _, owner := agentLab(t)
	for subject, role := range map[string]authorization.Role{"aud": authorization.Auditor, "opr": authorization.AgentOperator, "usr": authorization.AgentUser} {
		addMember(t, l, owner, subject, role)
	}
	for subject, want := range map[string]bool{"aud": true, "opr": false, "usr": false} {
		_, err := l.a.ListAudit(t.Context(), agentPrincipal(t, l, subject, agentScopes), "", 10)
		if want && err != nil || !want && !errors.Is(err, ErrForbidden) {
			t.Fatal("audit access for", subject, "want", want, "got", err)
		}
	}
	if _, err := l.a.ListAudit(t.Context(), agentPrincipal(t, l, "aud", "org:read"), "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("audit read without its scope", err)
	}
	// A technical account with the auditor role and the scope may read the trail.
	svc := newServiceAccount(t, l, owner, "feed", "feed bot", authorization.Auditor)
	token := issueServiceToken(t, l, owner, svc.ID, "feed-tok", "audit:read")
	bot, err := l.s.Authenticate(t.Context(), token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.ListAudit(t.Context(), bot, "", 10); err != nil {
		t.Fatal("auditor technical account cannot read the trail:", err)
	}
}
