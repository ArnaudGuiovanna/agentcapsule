package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func (il *invocationLab) runAgent(t *testing.T, agent string) VMCaller {
	t.Helper()
	_ = il.s.RegisterPlacement(t.Context(), agent, "local")
	p, err := il.s.ClaimPlacement(t.Context(), agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = il.s.ConfirmPlacement(t.Context(), agent, "local", "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: p.Generation}
}

func (il *invocationLab) payloadOwners(t *testing.T, kind, ref string) map[string]string {
	t.Helper()
	rows, err := il.s.pool.Query(t.Context(), `SELECT p.agent_id,p.owner_user_id FROM transit_parties p
        JOIN transit_payloads t ON t.id=p.payload_id WHERE t.kind=$1 AND t.ref_id=$2`, kind, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var agent, owner string
		if err = rows.Scan(&agent, &owner); err != nil {
			t.Fatal(err)
		}
		out[agent] = owner
	}
	return out
}

func text(s string) *capsuleprotocol.PeerPayload {
	return &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: s}}}
}

// Two agents of one organization exchange private content: the request and its
// reply reach the other agent's VM, and both are bound, on both sides, to the
// person whose invocation granted the mandate (D-02). Found by the KVM journey
// of two A2A agents: without it, such a request was refused as invalid.
func TestTenantAgentsExchangePrivateContentForTheirRequester(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	a := il.agent
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "peer-b")
	if _, err := il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vmA := il.vm(t)
	vmB := il.runAgent(t, b)
	inv, _, err := il.create(t, alice, "ask-b", "ask b about France")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	var mandate string
	if err = il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", inv.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	in := capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond),
		Payload: text("what is the capital of France?")}
	r, err := il.tr.SubmitFromVM(ctx, vmA, "peer-1", in)
	if err != nil || r.State != Delivering {
		t.Fatal("submission between agents of an organization", r, err)
	}
	if got := il.payloadOwners(t, "request", r.RequestID); len(got) != 2 || got[a] != alice.ID || got[b] != alice.ID {
		t.Fatal("the request is not bound to its requester", got)
	}

	m := mockStores(t, t.TempDir(), a, b)
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		_, err := capsuleprotocol.DecodePeerEvent(event, target)
		return []byte(`{"received":true}`), err
	})
	rt := &peerRuntime{MockRuntime: m}
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, r.RequestID, "request"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	delivered, err := capsuleprotocol.DecodePeerEvent(rt.events[0], b)
	if err != nil || delivered.Payload.Content[0].Text != "what is the capital of France?" {
		t.Fatal("b did not receive the question", err)
	}
	assertRequestState(t, il.s, r.RequestID, "PROCESSING")

	if _, err = il.tr.ReplyFromVM(ctx, vmB, r.RequestID, "answer-1", capsuleprotocol.Reply{Outcome: "completed", Payload: text("Paris")}); err != nil {
		t.Fatal("reply between agents of an organization", err)
	}
	if got := il.payloadOwners(t, "reply", r.RequestID); len(got) != 2 || got[a] != alice.ID || got[b] != alice.ID {
		t.Fatal("the reply is not bound to the requester", got)
	}
	if err = il.tr.DispatchMailbox(ctx, mailboxFor(t, il.s, r.RequestID, "reply"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	answer, err := capsuleprotocol.DecodePeerEvent(rt.events[1], a)
	if err != nil || answer.Kind != "reply" || answer.Payload.Content[0].Text != "Paris" {
		t.Fatal("a did not receive b's answer", err)
	}

	// A mandate no invocation granted names nobody: content cannot be bound,
	// and the request is refused without spending it.
	if _, err = il.s.pool.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES('mdt_orphan',$1,'evt_orphan',3,3,clock_timestamp()+interval '1 hour')`, a); err != nil {
		t.Fatal(err)
	}
	orphan := in
	orphan.MandateID = "mdt_orphan"
	if _, err = il.tr.SubmitFromVM(ctx, vmA, "peer-orphan", orphan); !errors.Is(err, ErrMandate) {
		t.Fatal("content bound to nobody", err)
	}
	if remaining(t, il.s, "mdt_orphan") != 3 {
		t.Fatal("a refused request spent its mandate")
	}
}
