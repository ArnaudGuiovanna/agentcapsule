package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

const userScopes = "org:read agent:read agent:invoke agent:content:read"

type invocationLab struct {
	*tenantLab
	c     *AgentCatalog
	tr    *Transit
	owner Principal
	agent string
}

func newInvocationLab(t *testing.T) *invocationLab {
	t.Helper()
	l, _, owner := agentLab(t)
	id := activateTenantAgent(t, l, mustCatalog(t, l), owner, "invokable")
	tr, err := NewTransit(l.s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x73}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, err := NewAgentCatalogWithTransit(l.a, "local", tr)
	if err != nil {
		t.Fatal(err)
	}
	return &invocationLab{tenantLab: l, c: c, tr: tr, owner: owner, agent: id}
}

func mustCatalog(t *testing.T, l *tenantLab) *AgentCatalog {
	t.Helper()
	c, err := NewAgentCatalog(l.a, "local")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// complete plays the worker: claim, authorize, run the harness, acknowledge.
func (il *invocationLab) complete(t *testing.T, op string) []byte {
	t.Helper()
	var mbx string
	if err := il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	attempt, envelope := claimInstruction(t, il.tr, mbx)
	rt := instructionRuntimeLab(t, il.agent)
	r, err := rt.Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mbx, attempt.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	return r.Result
}

func (il *invocationLab) invoke(t *testing.T, p Principal, key, text string) (APIReceipt, error) {
	t.Helper()
	return il.c.Instruct(t.Context(), p, il.agent, key, privateInstruction(text))
}

func (il *invocationLab) person(t *testing.T, subject string) (Member, Principal) {
	t.Helper()
	m := addMember(t, il.tenantLab, il.owner, subject, authorization.AgentUser)
	return m, agentPrincipal(t, il.tenantLab, subject, userScopes)
}

func TestTenantInvocationNeedsAnAssignmentNotARole(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	_, bobP := il.person(t, "bob")

	// An owner can see the agent but holds no right to invoke it.
	if _, err := il.invoke(t, il.owner, "owner-try", "hello"); !errors.Is(err, ErrForbidden) {
		t.Fatal("an administrative role invoked an agent", err)
	}
	// A member with no assignment cannot even tell the agent exists.
	if _, err := il.invoke(t, bobP, "bob-try", "hello"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unassigned member reached the agent", err)
	}
	// Metadata-only assignment is not enough to invoke.
	meta := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata"}}, "meta")
	if _, err := il.invoke(t, aliceP, "meta-try", "hello"); !errors.Is(err, ErrForbidden) {
		t.Fatal("read_metadata allowed an invocation", err)
	}
	// Widening a right is a revocation followed by a new assignment.
	if _, err := meta.revokeBy(t, il); err != nil {
		t.Fatal(err)
	}
	// A scope without the right, and the right without the scope, both fail.
	noScope := agentPrincipal(t, il.tenantLab, "alice", "org:read agent:read")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "full")
	if _, err := il.invoke(t, noScope, "scope-try", "hello"); !errors.Is(err, ErrForbidden) {
		t.Fatal("invocation without the invoke scope", err)
	}
	r, err := il.invoke(t, aliceP, "ok", "hello")
	first := acceptedOperation(t, r, err)
	again, err := il.invoke(t, aliceP, "ok", "hello")
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, r.Body) {
		t.Fatal("invocation is not idempotent", err)
	}
	if _, err = il.invoke(t, aliceP, "ok", "another body"); !errors.Is(err, ErrConflict) {
		t.Fatal("same key with a different body accepted", err)
	}
	var requester string
	if err = il.s.pool.QueryRow(t.Context(), `SELECT requested_by_principal_id FROM platform_operations WHERE id=$1 AND owner_user_id IS NULL`, first.OperationID).Scan(&requester); err != nil || requester != aliceP.ID {
		t.Fatal("operation does not record the requesting principal", requester, err)
	}
}

func TestTenantResultBelongsToTheRequesterAndCurrentRights(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	both := []string{"read_metadata", "invoke", "read_content"}
	asgAlice := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: both}, "b")

	r, err := il.invoke(t, aliceP, "secret", "alice's private question")
	op := acceptedOperation(t, r, err).OperationID
	result := il.complete(t, op)

	// Alice asked, but holds no read_content: she cannot read her own result.
	if _, err = il.c.InstructionResult(t.Context(), aliceP, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("result read without read_content", err)
	}
	// Bob holds read_content but is not the requester.
	if _, err = il.c.InstructionResult(t.Context(), bobP, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member read the requester's result", err)
	}
	// Neither an owner nor an owner holding every permission opens it.
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: il.owner.ID, Permissions: both}, "owner-all")
	if _, err = il.c.InstructionResult(t.Context(), il.owner, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("an administrator read someone else's result", err)
	}
	// Granting the requester read_content opens it; revoking it closes it again.
	if _, err = asgAlice.revokeBy(t, il); err != nil {
		t.Fatal(err)
	}
	grant := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: both}, "grant")
	got, err := il.c.InstructionResult(t.Context(), aliceP, op)
	if err != nil || !bytes.Equal(got, result) {
		t.Fatal("requester with read_content cannot read the result", err)
	}
	if _, err = il.owner.revoke(t, il, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.InstructionResult(t.Context(), aliceP, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("result stayed readable after the assignment was revoked", err)
	}
}

func (p Principal) revoke(t *testing.T, il *invocationLab, assignment string) (APIReceipt, error) {
	t.Helper()
	return il.a.RevokeAgentAssignment(t.Context(), p, il.agent, assignment, "revoke-"+assignment)
}

func (s AgentAssignment) revokeBy(t *testing.T, il *invocationLab) (APIReceipt, error) {
	t.Helper()
	return il.owner.revoke(t, il, s.ID)
}

func TestTenantOffboardingStopsAccessButNotAcceptedWork(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, "all")
	r, err := il.invoke(t, aliceP, "before", "accepted before departure")
	op := acceptedOperation(t, r, err).OperationID

	if _, err = il.a.RevokeMember(t.Context(), il.owner, alice.PrincipalID, "leave"); err != nil {
		t.Fatal(err)
	}
	// No new admission, no result access, and no replay of the old receipt.
	if _, err = il.invoke(t, aliceP, "after", "too late"); err == nil {
		t.Fatal("departed member invoked an agent")
	}
	if _, err = il.invoke(t, aliceP, "before", "accepted before departure"); err == nil {
		t.Fatal("departed member replayed an old receipt")
	}
	// Work accepted before the revocation may still finish for the organization.
	il.complete(t, op)
	if _, err = il.c.InstructionResult(t.Context(), aliceP, op); err == nil {
		t.Fatal("departed member read a result")
	}
	// The agent itself remains in the organization.
	if _, err = il.c.GetTenantAgent(t.Context(), il.owner, il.agent); err != nil {
		t.Fatal("offboarding removed the organization's agent", err)
	}
}

func TestTenantInvocationStaysOutOfTheLegacyDomain(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"invoke", "read_metadata", "read_content"}}, "all")
	r, err := il.invoke(t, aliceP, "k", "x")
	op := acceptedOperation(t, r, err).OperationID
	if _, err = il.c.Instruct(t.Context(), il.legacy, il.agent, "legacy", privateInstruction("x")); err == nil {
		t.Fatal("a legacy credential invoked a tenant agent")
	}
	il.complete(t, op)
	if _, err = il.c.InstructionResult(t.Context(), il.legacy, op); err == nil {
		t.Fatal("a legacy credential read a tenant result")
	}
	var payload []byte
	if err = il.s.pool.QueryRow(t.Context(), `SELECT ciphertext FROM transit_payloads WHERE kind='instruction' AND ref_id=$1`, op).Scan(&payload); err != nil || bytes.Contains(payload, []byte("x")) && len(payload) < 20 {
		t.Fatal("stored content is not encrypted", err)
	}
	_ = json.Marshal
}

func TestReplacingAnAssignmentIsAtomicAndAudited(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata"}}, "narrow")
	if _, err := il.invoke(t, aliceP, "before", "hi"); !errors.Is(err, ErrForbidden) {
		t.Fatal("narrow assignment allowed an invocation", err)
	}

	// Only an administrator may replace, and input is validated.
	if _, err := il.a.ReplaceAgentAssignment(t.Context(), aliceP, il.agent, old.ID, "r0", []string{"invoke"}); err == nil {
		t.Fatal("a plain member replaced an assignment")
	}
	if _, err := il.a.ReplaceAgentAssignment(t.Context(), il.owner, il.agent, old.ID, "r1", []string{"bogus"}); !errors.Is(err, ErrInput) {
		t.Fatal("invalid permission accepted", err)
	}
	r, err := il.a.ReplaceAgentAssignment(t.Context(), il.owner, il.agent, old.ID, "r2", []string{"read_metadata", "invoke"})
	var fresh AgentAssignment
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &fresh) != nil || fresh.ID == old.ID {
		t.Fatal("replace failed", err, r.Status)
	}
	if fresh.PrincipalID == nil || *fresh.PrincipalID != alice.PrincipalID {
		t.Fatal("replacement targets another principal")
	}
	var active int
	if err = il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM agent_assignments WHERE agent_id=$1 AND status='active'`, il.agent).Scan(&active); err != nil || active != 1 {
		t.Fatal("expected exactly one active assignment", active, err)
	}
	if _, err = il.invoke(t, aliceP, "after", "hi"); err != nil {
		t.Fatal("widened right not effective", err)
	}

	// Replay returns the same replacement; the old row cannot be replaced twice.
	again, err := il.a.ReplaceAgentAssignment(t.Context(), il.owner, il.agent, old.ID, "r2", []string{"read_metadata", "invoke"})
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, r.Body) {
		t.Fatal("replace is not idempotent", err)
	}
	if _, err = il.a.ReplaceAgentAssignment(t.Context(), il.owner, il.agent, old.ID, "r3", []string{"invoke"}); !errors.Is(err, ErrTransition) {
		t.Fatal("a revoked assignment was replaced", err)
	}
	var audits int
	if err = il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND assignment_id IN ($2,$3)`, il.agent, old.ID, fresh.ID).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("expected create+revoke of old and create of new", audits, err)
	}
}
