package controlplane

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// A release records what its harness.yaml requests at import (EXT-003). A
// manifest that says nothing predates the field: every capability.
func TestReleasesRecordTheCapabilitiesTheyRequest(t *testing.T) {
	l, _, owner := agentLab(t)
	imported := map[string]*[]string{"skilled": {"llm.invoke", "agents.discover"}, "silent": {}, "older": nil}
	ids := map[string]string{}
	for i, name := range []string{"skilled", "silent", "older"} {
		requestImport(t, l.a, l.platform, "k-"+name, pinned(string(rune('a'+i))))
		done, err := l.s.CompleteHarnessImport(t.Context(), claimImport(t, l.s), ImportedRelease{Name: name, Version: "1.0.0",
			RootfsDigest: "sha256:" + strings.Repeat("9", 64), RootfsBytes: 1 << 20, Capabilities: imported[name]})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = done.ReleaseID
	}
	requestImport(t, l.a, l.platform, "k-bad", pinned("e"))
	if _, err := l.s.CompleteHarnessImport(t.Context(), claimImport(t, l.s), ImportedRelease{Name: "bad", Version: "1.0.0",
		RootfsDigest: "sha256:" + strings.Repeat("9", 64), RootfsBytes: 1 << 20, Capabilities: &[]string{"files.write"}}); !errors.Is(err, ErrInput) {
		t.Fatal("an unknown capability was recorded", err)
	}
	items, err := l.a.ListHarnessReleases(t.Context(), owner, false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		capabilities []string
		declared     bool
	}{
		"skilled":   {[]string{"agents.discover", "llm.invoke"}, true},
		"silent":    {[]string{}, true},
		"older":     {[]string{"agents.delegate", "agents.discover", "llm.invoke"}, false},
		"reference": {[]string{"agents.delegate", "agents.discover", "llm.invoke"}, false},
	}
	for _, v := range items {
		w, ok := want[v.Name]
		if !ok {
			continue
		}
		if !slices.Equal(v.Capabilities, w.capabilities) || v.Capabilities == nil || v.CapabilitiesDeclared != w.declared {
			t.Error(v.Name, v.Capabilities, v.CapabilitiesDeclared)
		}
		delete(want, v.Name)
	}
	if len(want) != 0 {
		t.Fatal("releases not listed", want)
	}
}

// The effective set is the harness's request ∩ the organization's policy ∩
// the agent's policy (product.md §3). The catalog shows all four; the platform
// channel's check reads the same, at each call.
func TestEffectiveCapabilitiesAreTheIntersection(t *testing.T) {
	l, c, owner := agentLab(t)
	agent := activateTenantAgent(t, l, c, owner, "skilled")
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE harness_releases SET capabilities=ARRAY['llm.invoke','agents.discover']
        WHERE id=(SELECT release_id FROM agent_specs WHERE agent_id=$1)`, agent); err != nil {
		t.Fatal(err)
	}
	for subject, role := range map[string]authorization.Role{"operator": authorization.AgentOperator, "plain": authorization.AgentUser} {
		addMember(t, l, owner, subject, role)
	}
	operator, plain := agentPrincipal(t, l, "operator", agentScopes), agentPrincipal(t, l, "plain", agentScopes)
	caller := VMCaller{AgentID: agent}
	check := func(want []string, denied ...string) {
		t.Helper()
		v, err := c.AgentCapabilities(t.Context(), owner, agent)
		if err != nil || !slices.Equal(v.Effective, want) || !v.Declared || v.Release.Name != "reference" {
			t.Fatal("catalog", v, err)
		}
		for _, name := range want {
			if err := l.s.RequireCapabilityFromVM(t.Context(), caller, name); err != nil {
				t.Fatal(name, "refused", err)
			}
		}
		for _, name := range denied {
			if err := l.s.RequireCapabilityFromVM(t.Context(), caller, name); !errors.Is(err, ErrCapability) {
				t.Fatal(name, "allowed", err)
			}
		}
	}
	// Defaults allow everything: the harness's request decides.
	check([]string{"agents.discover", "llm.invoke"}, "agents.delegate")
	if err := l.s.RequireCapabilityFromVM(t.Context(), caller, "files.write"); !errors.Is(err, ErrInput) {
		t.Fatal("an unknown capability", err)
	}

	// The organization denies discovery.
	if _, err := l.a.SetOrganizationCapabilities(t.Context(), plain, "o-plain", CapabilityPolicy{Allowed: []string{}}); !errors.Is(err, ErrForbidden) {
		t.Fatal("a plain member set the organization's policy", err)
	}
	for _, bad := range [][]string{nil, {"files.write"}, {"llm.invoke", "llm.invoke"}} {
		if _, err := l.a.SetOrganizationCapabilities(t.Context(), owner, "bad", CapabilityPolicy{Allowed: bad}); !errors.Is(err, ErrInput) {
			t.Fatal("accepted", bad, err)
		}
	}
	r, err := l.a.SetOrganizationCapabilities(t.Context(), owner, "o1", CapabilityPolicy{Allowed: []string{"llm.invoke", "agents.delegate"}})
	var org CapabilityPolicy
	if err != nil || json.Unmarshal(r.Body, &org) != nil || !slices.Equal(org.Allowed, []string{"agents.delegate", "llm.invoke"}) {
		t.Fatal(string(r.Body), err)
	}
	if again, err := l.a.SetOrganizationCapabilities(t.Context(), owner, "o1", CapabilityPolicy{Allowed: []string{"agents.delegate", "llm.invoke"}}); err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	if got, err := l.a.OrganizationCapabilities(t.Context(), owner); err != nil || !slices.Equal(got.Allowed, org.Allowed) {
		t.Fatal(got, err)
	}
	check([]string{"llm.invoke"}, "agents.discover", "agents.delegate")

	// The agent denies everything; an operator may set it, a plain member not.
	if _, err = c.SetAgentCapabilities(t.Context(), plain, agent, "a-plain", CapabilityPolicy{Allowed: []string{}}); err == nil {
		t.Fatal("a plain member set the agent's policy")
	}
	if _, err = c.SetAgentCapabilities(t.Context(), operator, agent, "a1", CapabilityPolicy{Allowed: []string{}}); err != nil {
		t.Fatal(err)
	}
	check([]string{}, "llm.invoke")
	v, err := c.AgentCapabilities(t.Context(), owner, agent)
	if err != nil || !slices.Equal(v.Requested, []string{"agents.discover", "llm.invoke"}) || !slices.Equal(v.Organization, []string{"agents.delegate", "llm.invoke"}) ||
		len(v.Agent) != 0 || v.Agent == nil {
		t.Fatal(v, err)
	}
	if _, err = c.AgentCapabilities(t.Context(), plain, agent); !errors.Is(err, ErrNotFound) {
		t.Fatal("an unassigned member read the catalog", err)
	}

	// Who changed what is audited, as an authorization change.
	var audits int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM capability_audit WHERE tenant_id=$1`, owner.TenantID).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("audit", audits, err)
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range page.Items {
		seen[e.Action] = true
	}
	if !seen["organization.capabilities_changed"] || !seen["agent.capabilities_changed"] {
		t.Fatal("audit feed", page.Items)
	}
}
