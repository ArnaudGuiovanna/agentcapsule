package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// allPermissions is sorted, as assignments store their permissions.
var allPermissions = []string{"invoke", "read_content", "read_metadata"}

func (il *invocationLab) reassign(t *testing.T, p Principal, assignment, key string, in ReassignAssignmentInput) (AgentAssignment, APIReceipt, error) {
	t.Helper()
	r, err := il.a.ReassignAgentAssignment(t.Context(), p, il.agent, assignment, key, in)
	var s AgentAssignment
	if err == nil && (r.Status != 201 || json.Unmarshal(r.Body, &s) != nil) {
		t.Fatal("reassignment receipt", r.Status, string(r.Body))
	}
	return s, r, err
}

func (il *invocationLab) activeAssignments(t *testing.T) []AgentAssignment {
	t.Helper()
	items, err := il.a.ListAgentAssignments(t.Context(), il.owner, il.agent, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(items, func(s AgentAssignment) bool { return s.Status != "active" })
}

// Reassigning moves the rights, never the results: the old target loses its
// access to the agent and to its own results, the new target reads only what
// it asks itself, work admitted before the move completes, and moving back
// opens the old target's retained results again (ADR 002).
func TestReassignmentMovesAccessButNotResults(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")

	r, err := il.invoke(t, aliceP, "answered", "alice's question")
	answered := acceptedOperation(t, r, err).OperationID
	il.complete(t, answered)
	if _, err = il.c.InstructionResult(t.Context(), aliceP, answered); err != nil {
		t.Fatal("alice cannot read her own result", err)
	}
	r, err = il.invoke(t, aliceP, "pending", "alice's pending question")
	pending := acceptedOperation(t, r, err).OperationID
	file, _, err := il.upload(t, aliceP, "alice-file", "notes.txt", []byte("alice's notes"), 0)
	if err != nil {
		t.Fatal(err)
	}

	// Only an administrator may move an assignment, and only a valid request.
	if _, _, err = il.reassign(t, aliceP, old.ID, "self", ReassignAssignmentInput{PrincipalID: bob.PrincipalID}); !errors.Is(err, ErrForbidden) {
		t.Fatal("a plain member moved an assignment", err)
	}
	for name, in := range map[string]ReassignAssignmentInput{
		"no target":   {},
		"two targets": {PrincipalID: bob.PrincipalID, TeamID: "team"},
		"permission":  {PrincipalID: bob.PrincipalID, Permissions: []string{"admin"}},
		"duplicate":   {PrincipalID: bob.PrincipalID, Permissions: []string{"invoke", "invoke"}},
	} {
		if _, _, err = il.reassign(t, il.owner, old.ID, "bad-"+name, in); !errors.Is(err, ErrInput) {
			t.Fatal(name, err)
		}
	}
	// A target that cannot hold it, or already holds its own, changes nothing.
	if _, _, err = il.reassign(t, il.owner, old.ID, "same", ReassignAssignmentInput{PrincipalID: alice.PrincipalID}); !errors.Is(err, ErrTransition) {
		t.Fatal("moved to the same target", err)
	}
	if _, _, err = il.reassign(t, il.owner, old.ID, "nobody", ReassignAssignmentInput{PrincipalID: "prn_nobody"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("moved to an unknown member", err)
	}
	carol, _ := il.person(t, "carol")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: carol.PrincipalID, Permissions: []string{"read_metadata"}}, "carol")
	if _, _, err = il.reassign(t, il.owner, old.ID, "taken", ReassignAssignmentInput{PrincipalID: carol.PrincipalID}); !errors.Is(err, ErrTransition) {
		t.Fatal("moved onto a target that already holds an assignment", err)
	}
	if active := il.activeAssignments(t); len(active) != 2 {
		t.Fatal("a refused reassignment changed the assignments", active)
	}

	moved, receipt, err := il.reassign(t, il.owner, old.ID, "to-bob", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	if err != nil || moved.ID == old.ID || moved.PrincipalID == nil || *moved.PrincipalID != bob.PrincipalID || !slices.Equal(moved.Permissions, allPermissions) {
		t.Fatal("reassignment", err, moved)
	}
	again, err := il.a.ReassignAgentAssignment(t.Context(), il.owner, il.agent, old.ID, "to-bob", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, receipt.Body) {
		t.Fatal("reassignment is not idempotent", err)
	}
	if _, _, err = il.reassign(t, il.owner, old.ID, "to-bob", ReassignAssignmentInput{PrincipalID: carol.PrincipalID}); !errors.Is(err, ErrConflict) {
		t.Fatal("the same key for another target", err)
	}
	if _, _, err = il.reassign(t, il.owner, old.ID, "again", ReassignAssignmentInput{PrincipalID: carol.PrincipalID}); !errors.Is(err, ErrTransition) {
		t.Fatal("a revoked assignment was moved", err)
	}
	var audits int
	if err = il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM tenant_agent_audit WHERE agent_id=$1 AND
        ((assignment_id=$2 AND action='assignment.revoked') OR (assignment_id=$3 AND action='assignment.created'))`, il.agent, old.ID, moved.ID).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("the move is not audited as a revocation and a creation", audits, err)
	}

	// The old target: no agent, no new or replayed admission, nothing it asked.
	if _, err = il.c.GetTenantAgent(t.Context(), aliceP, il.agent); !errors.Is(err, ErrNotFound) {
		t.Fatal("the old target still sees the agent", err)
	}
	if _, err = il.invoke(t, aliceP, "after", "too late"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the old target invoked", err)
	}
	if _, err = il.invoke(t, aliceP, "answered", "alice's question"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the old target replayed an old receipt", err)
	}
	for name, read := range map[string]func(Principal) error{
		"result":     func(p Principal) error { _, err := il.c.InstructionResult(t.Context(), p, answered); return err },
		"invocation": func(p Principal) error { _, err := il.c.GetInvocation(t.Context(), p, answered); return err },
		"operation":  func(p Principal) error { _, err := il.c.Operation(t.Context(), p, answered); return err },
		"list": func(p Principal) error {
			_, err := il.c.ListInvocations(t.Context(), p, il.agent, "", "", 10)
			return err
		},
		"file": func(p Principal) error { _, err := il.c.GetAttachment(t.Context(), p, file.ID); return err },
	} {
		if err = read(aliceP); !errors.Is(err, ErrNotFound) {
			t.Fatal("the old target read its", name, err)
		}
		// The new target never reads what another member asked.
		if name != "list" {
			if err = read(bobP); !errors.Is(err, ErrNotFound) {
				t.Fatal("the new target read the old target's", name, err)
			}
		}
	}
	if items, err := il.c.ListInvocations(t.Context(), bobP, il.agent, "", "", 10); err != nil || len(items) != 0 {
		t.Fatal("the new target lists the old target's invocations", items, err)
	}
	// Administrators keep the redacted metadata, never the content.
	if v, err := il.c.GetInvocation(t.Context(), il.owner, answered); err != nil || v.RequestedBy != alice.PrincipalID {
		t.Fatal("the requester of an operation changed", v.RequestedBy, err)
	}
	if _, err = il.c.InstructionResult(t.Context(), il.owner, answered); !errors.Is(err, ErrNotFound) {
		t.Fatal("an administrator read a result", err)
	}

	// Work admitted before the move completes for the organization, still
	// under its requester, and nobody reads its result.
	il.complete(t, pending)
	for _, p := range []Principal{aliceP, bobP, il.owner} {
		if _, err = il.c.InstructionResult(t.Context(), p, pending); !errors.Is(err, ErrNotFound) {
			t.Fatal("a result of work admitted before the move was read", err)
		}
	}
	r, err = il.invoke(t, bobP, "bob", "bob's question")
	mine := acceptedOperation(t, r, err).OperationID
	il.complete(t, mine)
	if _, err = il.c.InstructionResult(t.Context(), bobP, mine); err != nil {
		t.Fatal("the new target cannot read its own result", err)
	}

	// Moving back gives the old target its retained results again, and the
	// new target loses its own.
	if _, _, err = il.reassign(t, il.owner, moved.ID, "back", ReassignAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_content", "read_metadata"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.InstructionResult(t.Context(), aliceP, answered); err != nil {
		t.Fatal("the old target does not read its own retained result again", err)
	}
	if _, err = il.invoke(t, aliceP, "narrowed", "x"); !errors.Is(err, ErrForbidden) {
		t.Fatal("explicit permissions were not applied", err)
	}
	if _, err = il.c.InstructionResult(t.Context(), bobP, mine); !errors.Is(err, ErrNotFound) {
		t.Fatal("a target moved away still reads its result", err)
	}
}

// A team can be the target: its active members gain the rights, and the
// previous member's results stay its own.
func TestReassignmentToATeam(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	dana, danaP := il.person(t, "dana")
	team := createTeam(t, il.tenantLab, il.owner, "support")
	if _, err := il.a.AddTeamMember(t.Context(), il.owner, team.ID, "dana-joins", AddTeamMemberInput{PrincipalID: dana.PrincipalID}); err != nil {
		t.Fatal(err)
	}
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")
	r, err := il.invoke(t, aliceP, "q", "alice's question")
	op := acceptedOperation(t, r, err).OperationID
	il.complete(t, op)
	moved, _, err := il.reassign(t, il.owner, old.ID, "to-team", ReassignAssignmentInput{TeamID: team.ID})
	if err != nil || moved.TeamID == nil || *moved.TeamID != team.ID || moved.PrincipalID != nil {
		t.Fatal("reassignment to a team", err, moved)
	}
	if _, err = il.invoke(t, danaP, "dana", "dana's question"); err != nil {
		t.Fatal("a team member cannot invoke", err)
	}
	if _, err = il.c.InstructionResult(t.Context(), danaP, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("a team member read the previous member's result", err)
	}
	if _, err = il.invoke(t, aliceP, "alice", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the previous member still invokes", err)
	}
	if _, _, err = il.reassign(t, il.owner, moved.ID, "to-alice", ReassignAssignmentInput{TeamID: team.ID}); !errors.Is(err, ErrTransition) {
		t.Fatal("moved to the same team", err)
	}
}

// gate holds the organization's row exclusively, as a concurrent authority
// change would, so that the test decides which waiting transaction goes first.
type gate struct {
	tx  pgx.Tx
	pid uint32
}

func holdOrganization(t *testing.T, il *invocationLab) *gate {
	t.Helper()
	tx, err := il.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	g := &gate{tx: tx}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err = tx.Exec(t.Context(), `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, il.org.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&g.pid); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *gate) open(t *testing.T) {
	t.Helper()
	if err := g.tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type outcome struct {
	r   APIReceipt
	err error
}

func async(f func() (APIReceipt, error)) <-chan outcome {
	done := make(chan outcome, 1)
	go func() { r, err := f(); done <- outcome{r, err} }()
	return done
}

func wait(t *testing.T, done <-chan outcome) outcome {
	t.Helper()
	select {
	case o := <-done:
		return o
	case <-time.After(20 * time.Second):
		t.Fatal("a transaction did not finish")
		return outcome{}
	}
}

// An admission authorized before the reassignment holds the organization
// shared until it commits: the reassignment waits for it, and the admitted
// work stays its requester's, with a result neither target reads.
func TestReassignmentWaitsForAnAdmissionAuthorizedBeforeIt(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")

	g := holdOrganization(t, il)
	admission := async(func() (APIReceipt, error) { return il.invoke(t, aliceP, "first", "alice asks first") })
	waitMemberBlock(t, il.s.pool, g.pid, 1)
	move := async(func() (APIReceipt, error) {
		return il.a.ReassignAgentAssignment(context.Background(), il.owner, il.agent, old.ID, "move", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	})
	waitMemberBlock(t, il.s.pool, g.pid, 2)
	g.open(t)

	admitted := wait(t, admission)
	op := acceptedOperation(t, admitted.r, admitted.err).OperationID
	if o := wait(t, move); o.err != nil || o.r.Status != 201 {
		t.Fatal("the reassignment after the admission", o.err)
	}
	var requester string
	if err := il.s.pool.QueryRow(t.Context(), `SELECT requested_by_principal_id FROM platform_operations WHERE id=$1`, op).Scan(&requester); err != nil || requester != alice.PrincipalID {
		t.Fatal("the admitted work changed requester", requester, err)
	}
	il.complete(t, op)
	for _, p := range []Principal{aliceP, bobP} {
		if _, err := il.c.InstructionResult(t.Context(), p, op); !errors.Is(err, ErrNotFound) {
			t.Fatal("a result admitted before the move was read after it", err)
		}
	}
	if _, err := il.invoke(t, aliceP, "first", "alice asks first"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the admitted receipt was replayed after the move", err)
	}
}

// A request that arrived before the reassignment but is authorized after it
// is judged against the new targets: the old target's admission, replay and
// result read are refused, the new target's admission is accepted.
func TestAdmissionWaitingBehindAReassignmentSeesTheNewTarget(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")
	r, err := il.invoke(t, aliceP, "earlier", "alice's earlier question")
	earlier := acceptedOperation(t, r, err).OperationID
	il.complete(t, earlier)

	g := holdOrganization(t, il)
	move := async(func() (APIReceipt, error) {
		return il.a.ReassignAgentAssignment(context.Background(), il.owner, il.agent, old.ID, "move", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	})
	waitMemberBlock(t, il.s.pool, g.pid, 1)
	oldAdmission := async(func() (APIReceipt, error) { return il.invoke(t, aliceP, "late", "alice arrives late") })
	replay := async(func() (APIReceipt, error) { return il.invoke(t, aliceP, "earlier", "alice's earlier question") })
	read := async(func() (APIReceipt, error) {
		_, err := il.c.InstructionResult(context.Background(), aliceP, earlier)
		return APIReceipt{}, err
	})
	newAdmission := async(func() (APIReceipt, error) { return il.invoke(t, bobP, "bob", "bob arrives with the move") })
	waitMemberBlock(t, il.s.pool, g.pid, 5)
	g.open(t)

	if o := wait(t, move); o.err != nil || o.r.Status != 201 {
		t.Fatal("reassignment", o.err)
	}
	for name, done := range map[string]<-chan outcome{"admission": oldAdmission, "replay": replay, "result read": read} {
		if o := wait(t, done); !errors.Is(o.err, ErrNotFound) {
			t.Fatal("the old target's waiting", name, "was not refused", o.err)
		}
	}
	o := wait(t, newAdmission)
	acceptedOperation(t, o.r, o.err)
	var created int
	if err = il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM platform_operations WHERE agent_id=$1 AND kind='instruction' AND requested_by_principal_id=$2`, il.agent, alice.PrincipalID).Scan(&created); err != nil || created != 1 {
		t.Fatal("a refused admission left work behind", created, err)
	}
}

// A target revoked just before the reassignment commits makes the
// reassignment fail as a whole: the old assignment stays active.
func TestReassignmentToATargetRevokedFirstChangesNothing(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, _ := il.person(t, "bob")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")

	g := holdOrganization(t, il)
	revoke := async(func() (APIReceipt, error) {
		return il.a.RevokeMember(context.Background(), il.owner, bob.PrincipalID, "bob-leaves")
	})
	waitMemberBlock(t, il.s.pool, g.pid, 1)
	move := async(func() (APIReceipt, error) {
		return il.a.ReassignAgentAssignment(context.Background(), il.owner, il.agent, old.ID, "move", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	})
	waitMemberBlock(t, il.s.pool, g.pid, 2)
	g.open(t)

	if o := wait(t, revoke); o.err != nil {
		t.Fatal(o.err)
	}
	if o := wait(t, move); !errors.Is(o.err, ErrNotFound) {
		t.Fatal("moved to a revoked member", o.err)
	}
	if active := il.activeAssignments(t); len(active) != 1 || active[0].ID != old.ID {
		t.Fatal("a failed reassignment changed the assignments", active)
	}
	if _, err := il.invoke(t, aliceP, "still", "alice still invokes"); err != nil {
		t.Fatal("the old target lost its rights to a failed reassignment", err)
	}
}

// Under concurrent admissions by both targets, every call returns, each
// accepted admission is the work of a principal that held the right when it
// committed, and every call that starts after the reassignment returned
// follows the new target.
func TestConcurrentAdmissionsAroundAReassignment(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	old := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: allPermissions}, "alice")

	type call struct {
		who   string
		after bool
		done  <-chan outcome
	}
	var calls []call
	moved := make(chan struct{})
	start := func(i int, who string, p Principal) {
		after := false
		select {
		case <-moved:
			after = true
		default:
		}
		key := who + "-" + string(rune('a'+i))
		calls = append(calls, call{who, after, async(func() (APIReceipt, error) { return il.invoke(t, p, key, "concurrent "+key) })})
	}
	move := async(func() (APIReceipt, error) {
		defer close(moved)
		return il.a.ReassignAgentAssignment(context.Background(), il.owner, il.agent, old.ID, "move", ReassignAssignmentInput{PrincipalID: bob.PrincipalID})
	})
	for i := range 12 {
		start(i, "alice", aliceP)
		start(i, "bob", bobP)
	}
	if o := wait(t, move); o.err != nil || o.r.Status != 201 {
		t.Fatal("reassignment", o.err)
	}
	start(12, "alice", aliceP)
	start(12, "bob", bobP)
	accepted := map[string]int{}
	for _, c := range calls {
		o := wait(t, c.done)
		switch {
		case o.err == nil:
			acceptedOperation(t, o.r, nil)
			accepted[c.who]++
			if c.after && c.who == "alice" {
				t.Fatal("the old target was admitted after the reassignment returned")
			}
		case errors.Is(o.err, ErrNotFound):
			if c.after && c.who == "bob" {
				t.Fatal("the new target was refused after the reassignment returned")
			}
		default:
			t.Fatal("unexpected outcome", c.who, o.err)
		}
	}
	for who, id := range map[string]string{"alice": alice.PrincipalID, "bob": bob.PrincipalID} {
		var created int
		if err := il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM platform_operations WHERE agent_id=$1 AND kind='instruction' AND requested_by_principal_id=$2`, il.agent, id).Scan(&created); err != nil || created != accepted[who] {
			t.Fatal(who, "has", created, "operations for", accepted[who], "admissions", err)
		}
	}
	if accepted["bob"] == 0 {
		t.Fatal("the new target was never admitted")
	}
}
