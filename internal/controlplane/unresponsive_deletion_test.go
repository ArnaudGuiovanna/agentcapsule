package controlplane

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// release ends a handler still holding the store when the test ends, so
// that the store can close whatever the test found.
func (r *stuckGuest) release() {
	r.mu.Lock()
	if r.holding {
		close(r.halt)
		r.holding = false
	}
	r.mu.Unlock()
	r.handlers.Wait()
}

// deletionState reads the agent's phase and its deletion's.
func deletionState(t *testing.T, s *Store, agent string) (phase, deletion string) {
	t.Helper()
	if err := s.pool.QueryRow(t.Context(), `SELECT a.phase,d.phase FROM agents a JOIN deletion_operations d ON d.agent_id=a.id
        WHERE a.id=$1`, agent).Scan(&phase, &deletion); err != nil {
		t.Fatal(err)
	}
	return phase, deletion
}

// An owner deletes an agent whose harness never returns from an invocation
// and holds its store (ADR 012, question 7, sub-question 2, option (b)).
// The deletion's fence of the agent's own store is refused by its running
// guest. A platform fault on that fence stops nothing, and the deletion
// tries again. The refused fence then stops the VM and goes through a
// restricted boot: the deletion passes its barrier, the held invocation is
// canceled (agent_unavailable), the store holds the deletion's fence, and
// no guest failure counts against a budget the deleted agent no longer
// needs, even a budget of one.
func TestDeletingAnAgentWhoseHarnessHoldsItsStoreCompletes(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	ctx := t.Context()
	rt := newStuckGuest(t, s, e.AgentID, e.HostID, RestartBudget{Failures: 1, Window: time.Hour})
	t.Cleanup(rt.release)
	held, heldOp := queueInstruction(t, c, owner, e.AgentID, "never-return")
	if err := tr.DispatchMailbox(ctx, held, time.Minute, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("the held attempt", err)
	}
	generation := rt.generation
	if _, err := c.Delete(ctx, owner, e.AgentID, "delete-stuck"); err != nil {
		t.Fatal(err)
	}
	// No attempt is made for an agent being deleted: the invocation stays
	// held until the deletion's barrier cancels it.
	if err := tr.DispatchMailbox(ctx, held, time.Minute, rt); !errors.Is(err, ErrUnavailable) {
		t.Fatal("an attempt for an agent being deleted", err)
	}

	rt.fault = errors.New("authority service unavailable")
	if err := s.ReconcileRevocation(ctx, e.AgentID, rt); err == nil || errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("the deletion fence's platform fault", err)
	}
	if len(rt.stops) != 0 || rt.restricted != 0 {
		t.Fatal("a platform fault stopped the VM", rt.stops, rt.restricted)
	}
	if phase, deletion := deletionState(t, s, e.AgentID); phase != "QUIESCING" || deletion != "FENCING" {
		t.Fatal("the deletion after its fence failed", phase, deletion)
	}

	if err := s.ReconcileRevocation(ctx, e.AgentID, rt); err != nil {
		t.Fatal("the deletion of an agent whose harness holds its store", err)
	}
	if !slices.Equal(rt.stops, []uint64{generation}) || rt.restricted != 1 {
		t.Fatal("stops and restricted boots", rt.stops, generation, rt.restricted)
	}
	if phase, deletion := deletionState(t, s, e.AgentID); phase != "DELETING" || deletion != "TOMBSTONED" {
		t.Fatal("the deletion's barrier", phase, deletion)
	}
	if got := guestFailureKinds(t, s, e.AgentID); len(got) != 0 {
		t.Fatal("a failure counted for an agent being deleted", got)
	}
	if n := count(t, s, "failed_agents"); n != 0 {
		t.Fatal("an agent being deleted was FAILED", n)
	}
	op, err := c.Operation(ctx, owner, heldOp)
	if err != nil || op.Status != "CANCELED" || op.ErrorCode != "agent_unavailable" {
		t.Fatal("the held invocation", op.Status, op.ErrorCode, err)
	}
	if state, _ := heldDelivery(t, s, held); state != "CANCELED" {
		t.Fatal("the held invocation's delivery", state)
	}
	var placement string
	if err = s.pool.QueryRow(ctx, "SELECT state FROM agent_placements WHERE agent_id=$1", e.AgentID).Scan(&placement); err != nil || placement != "STOPPED" {
		t.Fatal("placement after the restricted boot", placement, err)
	}
	// The deletion's fence holds in the store: a delayed delivery of the
	// agent's work is refused.
	late := harnessstore.Event{ID: "late-" + held, Subjects: []string{"agent/" + e.AgentID, "event/" + held}, Body: []byte("{}")}
	if _, err = rt.Send(ctx, e.AgentID, late); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the deletion is not fenced in the store", err)
	}
}

// A deletion stops only the guest of the agent it deletes. Its fence of a
// live agent's store, refused by that agent's guest, stops nothing: that
// agent keeps its VM and its budget, the deletion's barrier waits, and the
// fence is tried again later, as before. A platform fault on the deleted
// agent's own fence stops nothing either; its guest's refusal stops its VM,
// whose store is then fenced as the restricted boot would. An agent with
// no VM is fenced without a stop.
func TestADeletionStopsOnlyTheGuestOfTheAgentItDeletes(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	ctx := t.Context()
	a, b := confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b")
	rt := &refusingGuests{peerRuntime: peerRuntimeLab(t), s: s, host: "host", running: map[string]uint64{"a": a.Generation, "b": b.Generation}}
	if err := s.RequestDeletion(ctx, "user-a", "a"); err != nil {
		t.Fatal(err)
	}

	rt.refusal = errors.New("PostgreSQL unavailable")
	if err := s.ReconcileRevocation(ctx, "a", rt); err == nil || errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("a platform fault", err)
	}
	if len(rt.stops) != 0 {
		t.Fatal("a platform fault stopped a VM", rt.stops)
	}

	rt.refusal = nil
	if err := s.ReconcileRevocation(ctx, "a", rt); !errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("the live agent's refused fence", err)
	}
	if want := []string{fmt.Sprintf("a/%d", a.Generation)}; !slices.Equal(rt.stops, want) {
		t.Fatal("stops", rt.stops, want)
	}
	if _, running := rt.running["b"]; !running {
		t.Fatal("the live agent's VM was stopped")
	}
	if phase, deletion := deletionState(t, s, "a"); phase != "QUIESCING" || deletion != "FENCING" {
		t.Fatal("the deletion past a refused fence of a live agent", phase, deletion)
	}

	delete(rt.running, "b") // its guest answers again
	if err := s.ReconcileRevocation(ctx, "a", rt); err != nil {
		t.Fatal(err)
	}
	if phase, deletion := deletionState(t, s, "a"); phase != "DELETING" || deletion != "TOMBSTONED" {
		t.Fatal("the deletion's barrier", phase, deletion)
	}
	if want := []string{fmt.Sprintf("a/%d", a.Generation)}; !slices.Equal(rt.stops, want) {
		t.Fatal("stops after the barrier", rt.stops, want)
	}
	for _, id := range []string{"a", "b", "c"} {
		if got := guestFailureKinds(t, s, id); len(got) != 0 {
			t.Fatal("guest failures of", id, got)
		}
	}
}

// An ordinary deletion is unchanged: a running guest that answers the
// deletion's fence keeps its VM, which the deletion seals later, and
// nothing is stopped or booted for the barrier.
func TestAnOrdinaryDeletionStopsNoGuest(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	ctx := t.Context()
	rt := newStuckGuest(t, s, e.AgentID, e.HostID, DefaultRestartBudget)
	t.Cleanup(rt.release)
	id, op := queueInstruction(t, c, owner, e.AgentID, "ordinary")
	if err := tr.DispatchMailbox(ctx, id, time.Minute, rt); err != nil {
		t.Fatal("an ordinary invocation", err)
	}
	if v, err := c.Operation(ctx, owner, op); err != nil || v.Status != "SUCCEEDED" {
		t.Fatal("an ordinary invocation", v.Status, v.ErrorCode, err)
	}
	running := rt.generation
	if _, err := c.Delete(ctx, owner, e.AgentID, "delete-ordinary"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(ctx, e.AgentID, rt); err != nil {
		t.Fatal(err)
	}
	if len(rt.stops) != 0 || rt.restricted != 0 || rt.generation != running {
		t.Fatal("an ordinary deletion stopped or booted a VM", rt.stops, rt.restricted, rt.generation, running)
	}
	if phase, deletion := deletionState(t, s, e.AgentID); phase != "DELETING" || deletion != "TOMBSTONED" {
		t.Fatal("the deletion's barrier", phase, deletion)
	}
	if got := guestFailureKinds(t, s, e.AgentID); len(got) != 0 {
		t.Fatal("guest failures", got)
	}
}

// Only the deleted agent's own store, refused by its guest, has its VM
// stopped for the deletion's fence; a refusal wrapped by its caller is
// still one. A platform failure, another agent's store, or a runtime that
// cannot stop a VM stop nothing, and the failure is returned.
func TestOnlyTheDeletedAgentsRefusedFenceStopsItsGuest(t *testing.T) {
	refused := &UnresponsiveGuestError{Generation: 7, Err: capsuleprotocol.ErrTransport}
	for _, c := range []struct {
		name, target string
		err          error
		stops        bool
	}{
		{"its own store refused", "a", refused, true},
		{"a refusal wrapped by its caller", "a", fmt.Errorf("fence: %w", refused), true},
		{"a platform failure", "a", errors.New("PostgreSQL unavailable"), false},
		{"another agent's store refused", "b", refused, false},
		{"no failure", "a", nil, false},
	} {
		f := &fenceOnce{err: c.err}
		err := fenceDeletion(t.Context(), f, "a", c.target)
		if stopped := len(f.stops) == 1; stopped != c.stops {
			t.Error(c.name, "stopped", stopped, err)
		}
		if c.stops && (err != nil || f.fences != 2 || f.stops[0] != refused.Generation) {
			t.Error(c.name, "fence after the stop", f.fences, f.stops, err)
		}
		if !c.stops && (err != c.err || f.fences != 1) { //nolint:errorlint // returned as is
			t.Error(c.name, "the failure is returned", f.fences, err)
		}
	}
	if err := fenceDeletion(t.Context(), cannotStop{}, "a", "a"); !errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("a runtime that cannot stop a VM", err)
	}
}
