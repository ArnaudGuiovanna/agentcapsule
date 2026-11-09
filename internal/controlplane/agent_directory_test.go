package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

func directoryProfile(description string, visible bool, skills ...int) DirectoryProfile {
	return DirectoryProfile{Visible: visible, Description: description, Skills: skills, Domains: []int{111}}
}

func setProfile(t *testing.T, c *AgentCatalog, p Principal, id, key string, in DirectoryProfile) DirectoryEntry {
	t.Helper()
	r, err := c.SetDirectoryProfile(t.Context(), p, id, key, in)
	var e DirectoryEntry
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &e) != nil {
		t.Fatal("set directory profile", err, r.Status)
	}
	return e
}

func claimOne(t *testing.T, s *Store, agent string) DirectoryWork {
	t.Helper()
	work, err := s.ClaimDirectoryWork(t.Context(), 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range work {
		if w.AgentID == agent {
			return w
		}
	}
	t.Fatalf("no directory work for %s in %+v", agent, work)
	return DirectoryWork{}
}

func publication(t *testing.T, c *AgentCatalog, p Principal, id string) DirectoryEntry {
	t.Helper()
	e, err := c.GetDirectoryProfile(t.Context(), p, id)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func tenantCaller(t *testing.T, s *Store, id string) VMCaller {
	t.Helper()
	_ = s.RegisterPlacement(t.Context(), id, "local")
	p, err := s.ClaimPlacement(t.Context(), id, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = s.ConfirmPlacement(t.Context(), id, "local", "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return VMCaller{AgentID: id, HostID: "local", VMID: vm, Generation: p.Generation}
}

// An organization describes its agents; only those allowed to configure an
// agent may; the description is validated and audited; every change becomes a
// revision the publisher brings to the Directory, step by step.
func TestDirectoryProfilesAreGovernedAndPublishedByRevision(t *testing.T) {
	l, c, owner := agentLab(t)
	id := activateTenantAgent(t, l, c, owner, "summarizer")
	pending := createTenantAgent(t, c, owner, "still-provisioning")
	people := map[string]Principal{}
	for subject, role := range map[string]authorization.Role{"operator": authorization.AgentOperator, "plain": authorization.AgentUser,
		"auditor": authorization.Auditor} {
		addMember(t, l, owner, subject, role)
		people[subject] = agentPrincipal(t, l, subject, agentScopes)
	}
	summary := directoryProfile("Summarizes long documents.", true, 10302, 10301)
	for _, subject := range []string{"plain", "auditor"} {
		if _, err := c.SetDirectoryProfile(t.Context(), people[subject], id, "x-"+subject, summary); !errors.Is(err, ErrForbidden) {
			t.Fatal("described an agent without configure rights", subject, err)
		}
	}
	for label, bad := range map[string]DirectoryProfile{
		"empty description":   directoryProfile("  ", true, 10302),
		"control character":   directoryProfile("a\x00b", true, 10302),
		"no skill":            directoryProfile("d", true),
		"repeated skill":      directoryProfile("d", true, 10302, 10302),
		"negative skill":      directoryProfile("d", true, -1),
		"too many skills":     directoryProfile("d", true, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21),
		"description too big": directoryProfile(string(make([]rune, 1001)), true, 10302),
	} {
		if _, err := c.SetDirectoryProfile(t.Context(), owner, id, "bad", bad); !errors.Is(err, ErrInput) {
			t.Fatal(label, "accepted", err)
		}
	}
	if _, err := c.SetDirectoryProfile(t.Context(), owner, pending, "early", summary); !errors.Is(err, ErrUnavailable) {
		t.Fatal("described an agent still provisioning", err)
	}
	if e := publication(t, c, owner, id); e.Publication != "unpublished" || e.Visible || len(e.Skills) != 0 {
		t.Fatal("an agent never described", e)
	}

	// Described by an operator; the same key replays the same answer.
	e := setProfile(t, c, people["operator"], id, "describe", summary)
	again, err := c.SetDirectoryProfile(t.Context(), people["operator"], id, "describe", summary)
	if err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	if !e.Visible || e.Publication != "pending" || !reflect.DeepEqual(e.Skills, []int{10301, 10302}) || e.RecordCID != nil {
		t.Fatalf("described %+v", e)
	}
	if got := publication(t, c, people["auditor"], id); got.Description != summary.Description {
		t.Fatal("an auditor cannot read the description", got)
	}

	// The publisher takes the revision once, then records each step.
	w := claimOne(t, l.s, id)
	if !w.Publish || w.Revision != 1 || w.TenantID != owner.TenantID || w.Description != summary.Description || w.PublishedCID != "" {
		t.Fatalf("work %+v", w)
	}
	if more, _ := l.s.ClaimDirectoryWork(t.Context(), 100, time.Minute); len(more) != 0 {
		t.Fatal("leased work claimed twice", more)
	}
	if err = l.s.RecordDirectoryPublished(t.Context(), w, "cid-1"); err != nil {
		t.Fatal(err)
	}
	if got := publication(t, c, owner, id); got.Publication != "published" || got.RecordCID == nil || *got.RecordCID != "cid-1" {
		t.Fatalf("published %+v", got)
	}
	if err = l.s.RecordDirectoryPublished(t.Context(), w, "cid-1"); !errors.Is(err, ErrConflict) {
		t.Fatal("a step applied twice", err)
	}

	// The same description is not a new revision; a new one is.
	if setProfile(t, c, owner, id, "same", summary).Publication != "published" {
		t.Fatal("an unchanged description was published again")
	}
	setProfile(t, c, owner, id, "reword", directoryProfile("Summarizes documents in French.", true, 10302))
	w = claimOne(t, l.s, id)
	if w.Revision != 2 || w.PublishedCID != "cid-1" || w.PublishedRevision != 1 {
		t.Fatalf("second revision %+v", w)
	}
	if err = l.s.RecordDirectoryPublished(t.Context(), w, "cid-2"); err != nil {
		t.Fatal(err)
	}
	// The record replaced is retired: due until deleted.
	w = claimOne(t, l.s, id)
	if w.RetiredCID != "cid-1" || w.Revision != w.PublishedRevision {
		t.Fatalf("retired %+v", w)
	}
	if err = l.s.RecordDirectoryRetired(t.Context(), id, "cid-1"); err != nil {
		t.Fatal(err)
	}
	if more, _ := l.s.ClaimDirectoryWork(t.Context(), 100, time.Minute); len(more) != 0 {
		t.Fatal("nothing should be due", more)
	}

	// An outage defers the work; the lease no longer holds it.
	setProfile(t, c, owner, id, "again", directoryProfile("Summarizes documents.", true, 10302))
	w = claimOne(t, l.s, id)
	if err = l.s.DeferDirectoryWork(t.Context(), id, time.Hour); err != nil {
		t.Fatal(err)
	}
	if more, _ := l.s.ClaimDirectoryWork(t.Context(), 100, time.Minute); len(more) != 0 {
		t.Fatal("deferred work claimed early")
	}
	if _, err = l.s.pool.Exec(t.Context(), "UPDATE agent_directory SET next_attempt_at=clock_timestamp() WHERE agent_id=$1", id); err != nil {
		t.Fatal(err)
	}
	// The schema refuses it: no record any more, and the reason is shown.
	w = claimOne(t, l.s, id)
	if w.Attempt != 2 {
		t.Fatal("attempts not counted", w.Attempt)
	}
	if err = l.s.RecordDirectoryUnpublished(t.Context(), w, `ERROR: Unknown "id" value`); err != nil {
		t.Fatal(err)
	}
	got := publication(t, c, owner, id)
	if got.Publication != "invalid" || got.Error == nil || *got.Error != `ERROR: Unknown "id" value` || got.RecordCID != nil {
		t.Fatalf("invalid %+v", got)
	}
	if w = claimOne(t, l.s, id); w.RetiredCID != "cid-2" {
		t.Fatalf("the refused revision did not retire the old record %+v", w)
	}
	_ = l.s.RecordDirectoryRetired(t.Context(), id, "cid-2")

	// Hiding the agent, its deletion and its organization's suspension all
	// become revisions without a record.
	setProfile(t, c, owner, id, "fixed", directoryProfile("Summarizes documents.", true, 10301))
	w = claimOne(t, l.s, id)
	_ = l.s.RecordDirectoryPublished(t.Context(), w, "cid-3")
	for label, change := range map[string]string{
		"hidden":    "UPDATE agents SET discoverable=false WHERE id=$1",
		"deleted":   "UPDATE agents SET discoverable=true,phase='QUIESCING' WHERE id=$1",
		"suspended": "UPDATE organizations SET status='disabled' WHERE id=(SELECT tenant_id FROM agents WHERE id=$1)",
	} {
		_, _ = l.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true,phase='LIVE' WHERE id=$1", id)
		_, _ = l.s.pool.Exec(t.Context(), "UPDATE organizations SET status='active' WHERE id=(SELECT tenant_id FROM agents WHERE id=$1)", id)
		if _, err = l.s.pool.Exec(t.Context(), change, id); err != nil {
			t.Fatal(err)
		}
		if w = claimOne(t, l.s, id); w.Publish {
			t.Fatal(label, "agent still to be published", w)
		}
		_ = l.s.DeferDirectoryWork(t.Context(), id, 0)
	}
	_, _ = l.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true,phase='LIVE' WHERE id=$1", id)
	_, _ = l.s.pool.Exec(t.Context(), "UPDATE organizations SET status='active' WHERE id=(SELECT tenant_id FROM agents WHERE id=$1)", id)

	var trail int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND action='agent.directory_changed'
        AND actor_principal_id IS NOT NULL`, id).Scan(&trail); err != nil || trail != 5 {
		t.Fatal("audit trail", trail, err)
	}
}

// A running agent searches its own organization only. The Directory's hits
// count only when they are the current record of a discoverable, live agent
// that still has the skill asked; descriptions come from PostgreSQL.
func TestDirectorySearchFromAVMIsCheckedAgainstPostgreSQL(t *testing.T) {
	l, c, owner := agentLab(t)
	caller := activateTenantAgent(t, l, c, owner, "caller")
	summarizer := activateTenantAgent(t, l, c, owner, "summarizer")
	completer := activateTenantAgent(t, l, c, owner, "completer")
	hidden := activateTenantAgent(t, l, c, owner, "hidden")
	publish := func(id, cid string, in DirectoryProfile) {
		t.Helper()
		setProfile(t, c, owner, id, "describe-"+id+cid, in)
		w := claimOne(t, l.s, id)
		if err := l.s.RecordDirectoryPublished(t.Context(), w, cid); err != nil {
			t.Fatal(err)
		}
	}
	publish(caller, "cid-caller", directoryProfile("Asks others.", true, 10302))
	publish(summarizer, "cid-summarizer", directoryProfile("Summarizes.", true, 10302))
	publish(completer, "cid-completer", directoryProfile("Completes text.", true, 10301))
	publish(hidden, "cid-hidden", directoryProfile("Hidden.", true, 10302))
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=false WHERE id=$1", hidden); err != nil {
		t.Fatal(err)
	}
	// Another organization's agent with the same skill and a record.
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO organizations(id,name) VALUES ('org-other','Other');
        INSERT INTO agents(id,tenant_id,phase,discoverable) VALUES ('agt-other','org-other','LIVE',true);
        INSERT INTO agent_directory(agent_id,tenant_id,description,skills,published_cid,published_revision,state)
          VALUES ('agt-other','org-other','Foreign.','{10302}','cid-other',1,'published')`); err != nil {
		t.Fatal(err)
	}
	vm := tenantCaller(t, l.s, caller)
	scope, err := l.s.DirectoryScopeFromVM(t.Context(), vm)
	if err != nil || scope != owner.TenantID {
		t.Fatal("scope", scope, err)
	}
	all := []string{"cid-caller", "cid-summarizer", "cid-completer", "cid-hidden", "cid-other", "cid-unknown"}
	found, err := l.s.FindDirectoryAgentsFromVM(t.Context(), vm, all, []int{10302})
	if err != nil || len(found) != 1 || found[0].AgentID != summarizer || found[0].Description != "Summarizes." {
		t.Fatalf("search %+v %v", found, err)
	}
	found, _ = l.s.FindDirectoryAgentsFromVM(t.Context(), vm, all, []int{10301, 10302})
	if len(found) != 2 {
		t.Fatalf("any of the skills %+v", found)
	}
	// The Directory still holds the old record, but PostgreSQL says the skill
	// is gone: the hit no longer counts.
	setProfile(t, c, owner, summarizer, "reskill", directoryProfile("Summarizes.", true, 10301))
	if found, _ = l.s.FindDirectoryAgentsFromVM(t.Context(), vm, all, []int{10302}); len(found) != 0 {
		t.Fatalf("stale skill %+v", found)
	}
	if _, err = l.s.FindDirectoryAgentsFromVM(t.Context(), vm, all, nil); !errors.Is(err, ErrInput) {
		t.Fatal("search without skill", err)
	}
	// A stopped boot generation can no longer search.
	if err = l.s.BeginPlacementStop(t.Context(), caller, "local", vm.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.FindDirectoryAgentsFromVM(t.Context(), vm, all, []int{10301}); err == nil {
		t.Fatal("a stopping VM searched")
	}
}
