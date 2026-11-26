package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func (il *invocationLab) create(t *testing.T, p Principal, key, text string) (Invocation, APIReceipt, error) {
	t.Helper()
	r, err := il.c.CreateInvocation(t.Context(), p, il.agent, key, InvocationInput{OwnerInstruction: privateInstruction(text)})
	if err != nil {
		return Invocation{}, r, err
	}
	return decodeInvocation(t, r), r, nil
}

func decodeInvocation(t *testing.T, r APIReceipt) Invocation {
	t.Helper()
	var v Invocation
	if r.Status != 202 || json.Unmarshal(r.Body, &v) != nil || v.ID == "" {
		t.Fatal("unexpected invocation receipt", r.Status, string(r.Body))
	}
	return v
}

func TestInvocationResourceFollowsTheRequestWithoutExposingContent(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	all := []string{"read_metadata", "invoke", "read_content"}
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: all}, "a")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: all}, "b")

	// The owner holds no invoke right, even on the new resource.
	if _, _, err := il.create(t, il.owner, "owner", "x"); !errors.Is(err, ErrForbidden) {
		t.Fatal("an administrative role created an invocation", err)
	}
	v, r, err := il.create(t, aliceP, "k1", "alice secret question")
	if err != nil || v.State != "accepted" || v.AgentID != il.agent || v.ResultAvailable {
		t.Fatal("bad accepted invocation", v, err)
	}
	// Same key and body replays; a different body conflicts; the messages route
	// does not replay a response of the other shape.
	again, ar, err := il.create(t, aliceP, "k1", "alice secret question")
	if err != nil || !ar.Replayed || again.ID != v.ID || string(ar.Body) != string(r.Body) {
		t.Fatal("invocation is not idempotent", err)
	}
	if _, _, err = il.create(t, aliceP, "k1", "other"); !errors.Is(err, ErrConflict) {
		t.Fatal("same key, different body accepted", err)
	}
	legacy, err := il.invoke(t, aliceP, "k1", "alice secret question")
	if err != nil || legacy.Replayed {
		t.Fatal("messages route replayed an invocation receipt", err)
	}

	got, err := il.c.GetInvocation(t.Context(), aliceP, v.ID)
	if err != nil || got.State != "accepted" || got.RequestedBy != "" || got.PeerRequests != nil {
		t.Fatal("requester cannot follow own invocation", got, err)
	}
	// Another member never learns that it exists; an administrator sees metadata.
	if _, err = il.c.GetInvocation(t.Context(), bobP, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("a member read someone else's invocation", err)
	}
	adm, err := il.c.GetInvocation(t.Context(), il.owner, v.ID)
	meta, _ := json.Marshal(adm)
	if err != nil || adm.RequestedBy != aliceP.ID || !strings.Contains(string(meta), `"peer_requests":[]`) {
		t.Fatal("administrator cannot see invocation metadata", adm, err)
	}
	limited := agentPrincipal(t, il.tenantLab, organizationInput().InitialOwner.Subject, "org:read agent:read")
	if got, err = il.c.GetInvocation(t.Context(), limited, v.ID); err != nil || got.PeerRequests != nil {
		t.Fatal("agent:read alone must not expose the agent manager's diagnostics", got, err)
	}

	il.complete(t, v.ID)
	got, err = il.c.GetInvocation(t.Context(), aliceP, v.ID)
	if err != nil || got.State != "completed" || !got.ResultAvailable || got.CompletedAt == nil {
		t.Fatal("completion not reflected", got, err)
	}
	for _, p := range []Principal{aliceP, il.owner} {
		body, _ := json.Marshal(mustInvocationList(t, il, p))
		if strings.Contains(string(body), "alice secret question") {
			t.Fatal("invocation metadata leaked the instruction")
		}
	}
	// The result stays behind its own right: the administrator is refused.
	if _, err = il.c.InstructionResult(t.Context(), il.owner, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("administrator read a private result", err)
	}
	if _, err = il.c.InstructionResult(t.Context(), aliceP, v.ID); err != nil {
		t.Fatal(err)
	}
}

func mustInvocationList(t *testing.T, il *invocationLab, p Principal) []Invocation {
	t.Helper()
	items, err := il.c.ListInvocations(t.Context(), p, il.agent, "", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestInvocationManagerTracesHeldAndDeclinedRequests(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	recipient := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "reviewer")
	if _, err := il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true WHERE id=$1", recipient); err != nil {
		t.Fatal(err)
	}
	source, _, err := il.create(t, alice, "review", "ask for a review")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, source.ID)
	other, _, err := il.create(t, alice, "unrelated", "another invocation of the same sender")
	if err != nil {
		t.Fatal(err)
	}
	var mandate string
	if err := il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", source.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	sub, err := il.s.Submit(ctx, il.agent, "review", Submission{RecipientAgentID: recipient, MandateID: mandate,
		PayloadRef: "private-reference", PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || sub.State != PendingApproval {
		t.Fatal("manual consent", sub.State, err)
	}
	check := func(state State) {
		t.Helper()
		got, err := il.c.GetInvocation(ctx, il.owner, source.ID)
		if err != nil || len(got.PeerRequests) != 1 || got.PeerRequests[0] != (InvocationPeerRequest{sub.RequestID, recipient, state}) {
			t.Fatal("scoped request metadata", got.PeerRequests, err)
		}
	}
	check(PendingApproval)
	if _, err := il.c.DecideHeldRequest(ctx, il.owner, recipient, sub.RequestID, "decline", false); err != nil {
		t.Fatal(err)
	}
	check("DECLINED")
	got, err := il.c.GetInvocation(ctx, il.owner, other.ID)
	if err != nil || got.PeerRequests == nil || len(got.PeerRequests) > 0 {
		t.Fatal("unrelated invocation", got.PeerRequests, err)
	}
}

func TestInvocationListIsScopedAndPaginated(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	inv := []string{"read_metadata", "invoke"}
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: inv}, "a")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: inv}, "b")
	var ids []string
	for _, k := range []string{"1", "2", "3"} {
		v, _, err := il.create(t, aliceP, "a"+k, "q"+k)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, v.ID)
	}
	if _, _, err := il.create(t, bobP, "b1", "q"); err != nil {
		t.Fatal(err)
	}
	if got := mustInvocationList(t, il, bobP); len(got) != 1 {
		t.Fatal("a member listed another member's invocations", len(got))
	}
	if got := mustInvocationList(t, il, il.owner); len(got) != 4 {
		t.Fatal("administrator does not see every invocation", len(got))
	}
	page, err := il.c.ListInvocations(t.Context(), aliceP, il.agent, "", "", 2)
	if err != nil || len(page) != 2 || page[0].ID != ids[2] || page[1].ID != ids[1] {
		t.Fatal("newest first pagination broken", page, err)
	}
	next, err := il.c.ListInvocations(t.Context(), aliceP, il.agent, page[1].ID, "", 2)
	if err != nil || len(next) != 1 || next[0].ID != ids[0] {
		t.Fatal("cursor does not continue the list", next, err)
	}
	if _, err = il.c.ListInvocations(t.Context(), aliceP, "agt_missing", "", "", 10); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown agent listed", err)
	}
	if _, err = il.c.ListInvocations(t.Context(), aliceP, il.agent, "", "", 0); !errors.Is(err, ErrInput) {
		t.Fatal("bad limit accepted", err)
	}
}
