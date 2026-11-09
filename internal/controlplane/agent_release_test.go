package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func TestAgentReleaseChangesAreGovernedAndAudited(t *testing.T) {
	l, c, owner := agentLab(t)
	if _, err := l.s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "2.0.0"}, "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "0.9.0"}, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE harness_releases SET enabled=false,deprecated_at=clock_timestamp()
        WHERE name='reference' AND version='0.9.0'`); err != nil {
		t.Fatal(err)
	}
	id := activateTenantAgent(t, l, c, owner, "upgraded")
	pending := createTenantAgent(t, c, owner, "still-provisioning")
	people := map[string]Principal{}
	for subject, role := range map[string]authorization.Role{"operator": authorization.AgentOperator, "plain": authorization.AgentUser,
		"auditor": authorization.Auditor, "admin": authorization.OrgAdmin} {
		addMember(t, l, owner, subject, role)
		people[subject] = agentPrincipal(t, l, subject, agentScopes)
	}
	to := func(version string) ReleaseChange {
		return ReleaseChange{Harness: HarnessReference{"reference", version}}
	}
	for _, subject := range []string{"plain", "auditor"} {
		if _, err := c.ChangeAgentRelease(t.Context(), people[subject], id, "x-"+subject, to("2.0.0")); !errors.Is(err, ErrForbidden) {
			t.Fatal("changed the release without configure rights", subject, err)
		}
	}
	if _, err := c.ChangeAgentRelease(t.Context(), people["operator"], id, "deprecated", to("0.9.0")); !errors.Is(err, ErrRelease) {
		t.Fatal("pinned to a deprecated release", err)
	}
	if _, err := c.ChangeAgentRelease(t.Context(), people["operator"], id, "unknown", to("9.9.9")); !errors.Is(err, ErrRelease) {
		t.Fatal("pinned to an unknown release", err)
	}
	if _, err := c.ChangeAgentRelease(t.Context(), people["operator"], pending, "early", to("2.0.0")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("changed the release of an agent still provisioning", err)
	}

	// Upgrade by an operator; the same key replays the same answer.
	r, err := c.ChangeAgentRelease(t.Context(), people["operator"], id, "upgrade", to("2.0.0"))
	again, err2 := c.ChangeAgentRelease(t.Context(), people["operator"], id, "upgrade", to("2.0.0"))
	var up AgentRelease
	if err != nil || err2 != nil || r.Status != 200 || json.Unmarshal(r.Body, &up) != nil || !again.Replayed || string(again.Body) != string(r.Body) {
		t.Fatal("upgrade", err, err2, r.Status, again.Replayed)
	}
	if up.Harness.Version != "2.0.0" || up.Previous.Version != "1.0.0" || up.Applies != "next_boot" {
		t.Fatalf("upgrade answer %+v", up)
	}
	view, err := c.GetTenantAgent(t.Context(), owner, id)
	if err != nil || view.Harness.Version != "2.0.0" || view.HarnessDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatal("the agent view does not show the new release", view.Harness, err)
	}

	// Rollback by an administrator; asking for the current release changes nothing.
	r, err = c.ChangeAgentRelease(t.Context(), people["admin"], id, "rollback", to("1.0.0"))
	var back AgentRelease
	if err != nil || json.Unmarshal(r.Body, &back) != nil || back.Previous.Version != "2.0.0" || back.Harness.Version != "1.0.0" {
		t.Fatal("rollback", err, back)
	}
	if r, err = c.ChangeAgentRelease(t.Context(), owner, id, "same", to("1.0.0")); err != nil || r.Status != 200 {
		t.Fatal("no-op change", err)
	}
	rows, err := l.s.pool.Query(t.Context(), `SELECT r.version FROM tenant_agent_audit u JOIN harness_releases r ON r.id=u.release_id
        WHERE u.agent_id=$1 AND u.action='agent.release_changed' ORDER BY u.created_at,u.id`, id)
	if err != nil {
		t.Fatal(err)
	}
	var trail []string
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		trail = append(trail, v)
	}
	rows.Close()
	if strings.Join(trail, ",") != "2.0.0,1.0.0" {
		t.Fatal("release changes not audited once each", trail)
	}
}
