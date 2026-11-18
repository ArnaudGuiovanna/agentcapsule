package controlplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// auditTrail walks the organization's whole trail through ListAudit and
// returns it with its export and the operator's feed, each as JSON.
func auditTrail(t *testing.T, il *invocationLab) ([]AuditEvent, string) {
	t.Helper()
	var all []AuditEvent
	cursor := ""
	for range 100 {
		page, err := il.a.ListAudit(t.Context(), il.owner, cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Items...)
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	export, err := il.a.ExportAudit(t.Context(), il.owner, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || len(export.Items) != len(all) {
		t.Fatal("export", len(export.Items), len(all), err)
	}
	operator, err := il.s.ListOperatorAudit(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal([]any{all, export, operator})
	if err != nil {
		t.Fatal(err)
	}
	return all, string(b)
}

// TEN-009: after invocations, messages to an agent, their results, a request
// and its reply between two agents, a later completion and a refused attempt
// that carries text, the organization's trail, its export and the operator's
// feed hold none of that content.
func TestAuditTrailHoldsNoConversationContent(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	const planted = "PLANTED-CONVERSATION-7f3a"
	say := func(what string) string { return planted + " " + what }

	// An invocation and a message, delivered, their results returned.
	inv, _, err := il.create(t, alice, "inv-1", say("invocation"))
	if err != nil {
		t.Fatal(err)
	}
	if result := il.complete(t, inv.ID); !strings.Contains(string(result), planted) {
		t.Fatal("the fixture's result does not echo the content")
	}
	msg, err := il.invoke(t, alice, "msg-1", say("message"))
	if err != nil || msg.Status != 202 {
		t.Fatal(err)
	}
	var accepted AgentCreation
	if err = json.Unmarshal(msg.Body, &accepted); err != nil {
		t.Fatal(err)
	}
	il.complete(t, accepted.OperationID)
	// A request and its reply between two agents of the organization, then
	// the invocation that asked completes later.
	a := il.agent
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "peer-b")
	if _, err = il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vmA, vmB := il.vm(t), il.runAgent(t, b)
	working, _, err := il.create(t, alice, "inv-2", say("ask b"))
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, working.ID)
	var mandate string
	if err = il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", working.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	req, err := il.tr.SubmitFromVM(ctx, vmA, "peer-1", capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), Payload: text(say("question to b"))})
	if err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), a, b)
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		_, err := capsuleprotocol.DecodePeerEvent(event, target)
		return []byte(`{"received":true}`), err
	})
	rt := &peerRuntime{MockRuntime: m}
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, req.RequestID, "request"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ReplyFromVM(ctx, vmB, req.RequestID, "answer-1", capsuleprotocol.Reply{Outcome: "completed", Payload: text(say("answer from b"))}); err != nil {
		t.Fatal(err)
	}
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, req.RequestID, "reply"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt.events[0].Body)+string(rt.events[1].Body), planted) {
		t.Fatal("the agents did not exchange the content")
	}
	if _, err = il.tr.CompleteInvocationFromVM(ctx, vmA, "done-2", answer(working.ID, say("final answer"))); err != nil {
		t.Fatal(err)
	}
	// A refused attempt whose path carried text: the text is not kept.
	if err = il.a.RecordRefusal(ctx, il.owner, RefusedAttempt{Action: "llm.alias.prices_set", Target: planted, Reference: planted, Reason: "invalid_request"}); err != nil {
		t.Fatal(err)
	}

	events, trail := auditTrail(t, il)
	if strings.Contains(trail, planted) {
		t.Fatal("the audit trail holds conversation content")
	}
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action+"/"+e.Outcome] = true
		if e.Action == "llm.alias.prices_set" && (e.Target != il.owner.TenantID || e.Reference != "" || e.Actor != il.owner.ID) {
			t.Fatal("a refusal kept what its path named", e)
		}
	}
	for _, want := range []string{"agent.created/done", "assignment.created/done", "llm.alias.prices_set/refused"} {
		if !actions[want] {
			t.Fatal("the trail lacks", want, actions)
		}
	}
	// The content is stored, encrypted, where it belongs.
	var payloads int
	if err = il.s.pool.QueryRow(ctx, "SELECT count(*) FROM transit_payloads").Scan(&payloads); err != nil || payloads < 6 {
		t.Fatal("the conversations were not stored", payloads, err)
	}
}

// TEN-009: the replays of dead letters join the trail of their agent's
// organization, by its administrator or by the operator, and the operator's
// own replays and the platform's harness imports and deprecations join the
// operator's feed. A refused attempt records only what its rule allows.
func TestReplaysAndHarnessImportsJoinTheAuditFeeds(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	addMember(t, il.tenantLab, il.owner, "admin", authorization.OrgAdmin)
	admin := agentPrincipal(t, il.tenantLab, "admin", agentScopes)
	first, _, err := il.create(t, alice, "first", "one")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := il.create(t, alice, "second", "two")
	if err != nil {
		t.Fatal(err)
	}
	il.kill(t, first.ID, false)
	il.kill(t, second.ID, false)
	if _, _, err = il.replay(t, admin, first.ID, "k", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.ReplayDeadInstruction(ctx, second.ID, "op-1", ReplayInput{}); err != nil {
		t.Fatal(err)
	}
	// The platform imports a harness and deprecates a release.
	platform := il.platform
	imp, _ := requestImport(t, il.a, platform, "imp", pinned("c"))
	release, err := il.s.RegisterLocalRelease(ctx, HarnessReference{Name: "spare", Version: "1.0.0"}, "sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.a.DeprecateHarnessRelease(ctx, platform, release, "dep"); err != nil {
		t.Fatal(err)
	}

	events, _ := auditTrail(t, il)
	replays := map[string]AuditEvent{}
	for _, e := range events {
		if e.Action == "invocation.replayed" {
			replays[e.Reference] = e
		}
	}
	if e := replays[first.ID]; e.Actor != admin.ID || e.Target != il.agent || e.Outcome != "done" {
		t.Fatal("the administrator's replay in the trail", replays)
	}
	if e := replays[second.ID]; e.Actor != "operator" || e.Target != il.agent || e.Outcome != "done" {
		t.Fatal("the operator's replay in the trail", replays)
	}
	operator, err := il.s.ListOperatorAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]OperatorAuditEvent{}
	for _, e := range operator {
		seen[e.Action+"/"+e.Target] = e
	}
	if e, ok := seen["invocation.replayed/"+il.agent]; !ok || e.Actor != "operator" || e.Reference != second.ID || e.TenantID != il.owner.TenantID {
		t.Fatal("the operator's replay in its feed", seen)
	}
	for _, e := range operator {
		if e.Action == "invocation.replayed" && e.Reference == first.ID {
			t.Fatal("an organization's replay in the operator's feed", e)
		}
	}
	if e, ok := seen["harness.import.requested/"+imp.ID]; !ok || e.Actor != "platform:"+platform.ID || e.Reference != platform.TokenID {
		t.Fatal("the harness import in the operator's feed", seen)
	}
	if _, ok := seen["harness.release.deprecated/"+release]; !ok {
		t.Fatal("the deprecation in the operator's feed", seen)
	}
}
