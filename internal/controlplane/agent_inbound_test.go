package controlplane

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// An organization decides how requests from its other agents reach an agent:
// held for approval by default, delivered at once once it is "auto". Only those
// who may configure the agent change it; each change is audited and, being an
// authorization rule, bumps the organization's policy version.
func TestAnOrganizationSetsHowItsAgentsAcceptRequests(t *testing.T) {
	l, c, owner := agentLab(t)
	sender := activateTenantAgent(t, l, c, owner, "sender")
	recipient := activateTenantAgent(t, l, c, owner, "recipient")
	pending := createTenantAgent(t, c, owner, "still-provisioning")
	people := map[string]Principal{}
	for subject, role := range map[string]authorization.Role{"operator": authorization.AgentOperator, "plain": authorization.AgentUser,
		"auditor": authorization.Auditor} {
		addMember(t, l, owner, subject, role)
		people[subject] = agentPrincipal(t, l, subject, agentScopes)
	}
	policy := func() InboundPolicy {
		t.Helper()
		p, err := c.GetInboundPolicy(t.Context(), owner, recipient)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	version := func() int64 {
		t.Helper()
		var v int64
		if err := l.s.pool.QueryRow(t.Context(), "SELECT policy_version FROM organizations WHERE id=$1", owner.TenantID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if p := policy(); p.Mode != "manual" || p.AgentID != recipient {
		t.Fatal("default", p)
	}
	for _, subject := range []string{"plain", "auditor"} {
		if _, err := c.SetInboundPolicy(t.Context(), people[subject], recipient, "x-"+subject, "auto"); !errors.Is(err, ErrForbidden) {
			t.Fatal("changed the inbound policy without configure rights", subject, err)
		}
	}
	for _, mode := range []string{"", "AUTO", "open"} {
		if _, err := c.SetInboundPolicy(t.Context(), owner, recipient, "bad", mode); !errors.Is(err, ErrInput) {
			t.Fatal("accepted mode", mode, err)
		}
	}
	if _, err := c.SetInboundPolicy(t.Context(), owner, pending, "early", "auto"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("set the policy of an agent still provisioning", err)
	}
	if _, err := c.SetInboundPolicy(t.Context(), owner, "agt_missing", "missing", "auto"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown agent", err)
	}

	// Requests are held for approval until the organization opens the agent.
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true WHERE id=$1", recipient); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('mandate-sender',$1,'evt-sender',3,3,clock_timestamp()+interval '1 hour')`, sender); err != nil {
		t.Fatal(err)
	}
	submit := func(key string) State {
		t.Helper()
		r, err := l.s.Submit(t.Context(), sender, key, Submission{RecipientAgentID: recipient, MandateID: "mandate-sender",
			PayloadRef: "payload-" + key, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return r.State
	}
	if got := submit("first"); got != PendingApproval {
		t.Fatal("a request to a manual agent", got)
	}
	before := version()
	r, err := c.SetInboundPolicy(t.Context(), people["operator"], recipient, "open", "auto")
	var out InboundPolicy
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &out) != nil || out != (InboundPolicy{AgentID: recipient, Mode: "auto"}) {
		t.Fatal("open", err, r.Status, string(r.Body))
	}
	if again, err := c.SetInboundPolicy(t.Context(), people["operator"], recipient, "open", "auto"); err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	if _, err := c.SetInboundPolicy(t.Context(), people["operator"], recipient, "open", "manual"); !errors.Is(err, ErrConflict) {
		t.Fatal("the same key for another policy", err)
	}
	if policy().Mode != "auto" || version() != before+1 {
		t.Fatal("open", policy(), version(), before)
	}
	if got := submit("second"); got != Delivering {
		t.Fatal("a request to an auto agent", got)
	}
	// The request held before stays held.
	var state string
	if err := l.s.pool.QueryRow(t.Context(), "SELECT state FROM agent_requests WHERE sender_agent_id=$1 ORDER BY created_at LIMIT 1", sender).Scan(&state); err != nil || state != "PENDING_APPROVAL" {
		t.Fatal("the earlier request", state, err)
	}
	// Setting the same mode again changes nothing but is audited.
	if _, err := c.SetInboundPolicy(t.Context(), owner, recipient, "open-again", "auto"); err != nil || version() != before+1 {
		t.Fatal("unchanged", err, version())
	}
	var audited int
	if err := l.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND action='agent.inbound_changed'", recipient).Scan(&audited); err != nil || audited != 2 {
		t.Fatal("audit", audited, err)
	}
	// Another organization does not see the agent.
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO organizations(id,name) VALUES ('org-other','Other')`); err != nil {
		t.Fatal(err)
	}
	foreign := owner
	foreign.TenantID = "org-other"
	if _, err := c.SetInboundPolicy(t.Context(), foreign, recipient, "steal", "manual"); err == nil {
		t.Fatal("another organization changed the policy")
	}
}
