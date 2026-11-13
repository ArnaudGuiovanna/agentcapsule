package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// A request between agents of an organization, held by the recipient's manual
// inbound policy, waits for a person of the organization: whoever may configure
// the recipient, or whoever is assigned to it with invoke. Accepting delivers
// it to the recipient's VM; declining tells the sender. The person sees who
// sends, on whose behalf and until when, never the content.
func TestAPersonOfTheOrganizationDecidesOnHeldRequests(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	a := il.agent
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "held-b")
	if _, err := il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vmA := il.vm(t)
	inv, _, err := il.create(t, alice, "ask-b", "ask b")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	var mandate string
	if err = il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", inv.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(ctx, "UPDATE mandates SET max_requests=10,remaining=10 WHERE id=$1", mandate); err != nil {
		t.Fatal(err)
	}
	submit := func(key, question string, within time.Duration) string {
		t.Helper()
		r, err := il.tr.SubmitFromVM(ctx, vmA, key, capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate,
			ExpiresAt: time.Now().Add(within).UTC().Truncate(time.Microsecond), Payload: text(question)})
		if err != nil || r.State != PendingApproval {
			t.Fatal("a request to a manual agent", r, err)
		}
		return r.RequestID
	}
	first := submit("first", "what is the capital of France?", 30*time.Minute)
	second := submit("second", "and of Italy?", 40*time.Minute)
	late := submit("late", "too late", 50*time.Minute)
	if _, err = il.s.pool.Exec(ctx, "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", late); err != nil {
		t.Fatal(err)
	}

	// Who may decide: configure rights, or invoke on the recipient.
	person := func(subject string, role authorization.Role, scopes string, perms ...string) Principal {
		t.Helper()
		m := addMember(t, il.tenantLab, il.owner, subject, role)
		if len(perms) > 0 {
			assign(t, il.tenantLab, il.owner, b, CreateAssignmentInput{PrincipalID: m.PrincipalID, Permissions: perms}, "assign-"+subject)
		}
		return agentPrincipal(t, il.tenantLab, subject, scopes)
	}
	operator := person("operator", authorization.AgentOperator, agentScopes)
	carol := person("carol", authorization.AgentUser, userScopes, "invoke")
	dave := person("dave", authorization.AgentUser, userScopes, "read_metadata")
	erin := person("erin", authorization.AgentUser, userScopes)
	auditor := person("auditor", authorization.Auditor, agentScopes)
	narrow := agentPrincipal(t, il.tenantLab, "operator", "org:read agent:read")
	for name, c := range map[string]struct {
		p    Principal
		want error
	}{"metadata only": {dave, ErrForbidden}, "auditor": {auditor, ErrForbidden}, "no right": {erin, ErrNotFound},
		"neither scope": {narrow, ErrForbidden}, "sender's invoker": {alice, ErrNotFound}} {
		if _, err := il.c.HeldRequests(ctx, c.p, b, "", 10); !errors.Is(err, c.want) {
			t.Fatal(name, "listed held requests", err)
		}
		if _, err := il.c.DecideHeldRequest(ctx, c.p, b, first, "try-"+name, true); !errors.Is(err, c.want) {
			t.Fatal(name, "accepted a held request", err)
		}
	}

	// The list shows the live held requests, nearest deadline first, with the
	// person on whose behalf they were sent, and nothing of their content.
	held, err := il.c.HeldRequests(ctx, carol, b, "", 10)
	if err != nil || len(held) != 2 || held[0].ID != first || held[1].ID != second {
		t.Fatal("held requests", held, err)
	}
	if h := held[0]; h.SenderAgentID != a || h.RequestedBy != alice.ID || !h.ExpiresAt.After(time.Now()) || h.CreatedAt.IsZero() {
		t.Fatal("held request", h)
	}
	page, err := il.c.HeldRequests(ctx, operator, b, "", 1)
	if err != nil || len(page) != 1 || page[0].ID != first {
		t.Fatal("first page", page, err)
	}
	if page, err = il.c.HeldRequests(ctx, operator, b, first, 1); err != nil || len(page) != 1 || page[0].ID != second {
		t.Fatal("second page", page, err)
	}
	for _, limit := range []int{0, 101} {
		if _, err = il.c.HeldRequests(ctx, operator, b, "", limit); !errors.Is(err, ErrInput) {
			t.Fatal("limit", limit, err)
		}
	}

	// carol, assigned with invoke, accepts the first: it is delivered to b.
	r, err := il.c.DecideHeldRequest(ctx, carol, b, first, "yes", true)
	var out HeldRequestDecision
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &out) != nil || out != (HeldRequestDecision{RequestID: first, State: Delivering}) {
		t.Fatal("accept", err, r.Status, string(r.Body))
	}
	if again, err := il.c.DecideHeldRequest(ctx, carol, b, first, "yes", true); err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	if _, err = il.c.DecideHeldRequest(ctx, carol, b, first, "yes", false); !errors.Is(err, ErrConflict) {
		t.Fatal("the same key for the opposite decision", err)
	}
	if _, err = il.c.DecideHeldRequest(ctx, operator, b, first, "twice", false); !errors.Is(err, ErrTransition) {
		t.Fatal("declined an accepted request", err)
	}
	assertRequestState(t, il.s, first, "DELIVERING")
	m := mockStores(t, t.TempDir(), a, b)
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		_, err := capsuleprotocol.DecodePeerEvent(event, target)
		return []byte(`{"received":true}`), err
	})
	rt := &peerRuntime{MockRuntime: m}
	il.runAgent(t, b)
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, first, "request"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if delivered, err := capsuleprotocol.DecodePeerEvent(rt.events[0], b); err != nil || delivered.Payload.Content[0].Text != "what is the capital of France?" {
		t.Fatal("b did not receive the accepted request", err)
	}

	// The operator declines the second: the sender is told.
	if r, err = il.c.DecideHeldRequest(ctx, operator, b, second, "no", false); err != nil || json.Unmarshal(r.Body, &out) != nil || out.State != "DECLINED" {
		t.Fatal("decline", err, string(r.Body))
	}
	assertRequestState(t, il.s, second, "DECLINED")
	mailboxFor(t, il.s, second, "status")

	// A request past its deadline, decided or of another agent, cannot be decided.
	if _, err = il.c.DecideHeldRequest(ctx, operator, b, late, "late", true); !errors.Is(err, ErrTransition) {
		t.Fatal("accepted an expired request", err)
	}
	if _, err = il.c.DecideHeldRequest(ctx, operator, a, first, "elsewhere", true); !errors.Is(err, ErrNotFound) {
		t.Fatal("decided a request through another recipient", err)
	}
	if _, err = il.c.DecideHeldRequest(ctx, operator, b, "arq_missing", "missing", true); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown request", err)
	}
	if held, err = il.c.HeldRequests(ctx, carol, b, "", 10); err != nil || len(held) != 0 {
		t.Fatal("decided and expired requests are still listed", held, err)
	}

	// Both decisions are audited with their request; the feed refers to it.
	var audited int
	if err = il.s.pool.QueryRow(ctx, `SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND
        ((action='agent.request_accepted' AND request_id=$2 AND actor_principal_id=$4) OR
         (action='agent.request_declined' AND request_id=$3 AND actor_principal_id=$5))`, b, first, second, carol.ID, operator.ID).Scan(&audited); err != nil || audited != 2 {
		t.Fatal("audit", audited, err)
	}
	feed, err := il.a.ListAudit(ctx, il.owner, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]string{}
	for _, e := range feed.Items {
		if e.Action == "agent.request_accepted" || e.Action == "agent.request_declined" {
			refs[e.Action] = e.Reference
		}
	}
	if refs["agent.request_accepted"] != first || refs["agent.request_declined"] != second {
		t.Fatal("audit feed", refs)
	}

	// Both agents must still be live; another organization sees nothing.
	pending := submit("pending", "still there?", time.Hour)
	if _, err = il.s.pool.Exec(ctx, "UPDATE agents SET phase='QUIESCING' WHERE id=$1", a); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.DecideHeldRequest(ctx, operator, b, pending, "quiescing", true); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted a request whose sender is quiescing", err)
	}
	if _, err = il.s.pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES ('org-other','Other')`); err != nil {
		t.Fatal(err)
	}
	foreign := il.owner
	foreign.TenantID = "org-other"
	if _, err = il.c.DecideHeldRequest(ctx, foreign, b, pending, "steal", true); err == nil {
		t.Fatal("another organization decided a held request")
	}
	if _, err = il.c.HeldRequests(ctx, foreign, b, "", 10); err == nil {
		t.Fatal("another organization listed held requests")
	}
}
