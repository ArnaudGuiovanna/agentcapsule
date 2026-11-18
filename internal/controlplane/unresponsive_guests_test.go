package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// stuckGuest stands for an agent's VMs as the product worker drives them,
// over real SQLite stores (MockRuntime) and real placements in PostgreSQL.
// Its harness never returns from an invocation whose text says
// "never-return": the handler holds the store's write transaction, whatever its
// caller's deadline, until the VM stops. As the worker does, it reports a
// fence that the running VM's guest refuses as an UnresponsiveGuestError,
// stops that VM on StopUnresponsiveGuest and counts a guest failure, and
// fences a stopped agent through a restricted boot, claimed like the
// worker's (ClaimFencePlacement).
type stuckGuest struct {
	*vmruntime.MockRuntime
	t           *testing.T
	s           *Store
	agent, host string
	budget      RestartBudget

	mu sync.Mutex
	// generation is the running VM's, booted for work; 0 when none runs.
	generation uint64
	// halt is closed when the running VM stops: its harness goes with it.
	halt chan struct{}
	// holding: the harness holds its store, in a handler that never returns.
	holding  bool
	handlers sync.WaitGroup
	// fault is a platform failure of the next fence (an authority outage).
	fault error
	// stops lists the generations StopUnresponsiveGuest was asked to stop.
	stops []uint64
	// boots counts the restricted boots of fences.
	restricted int
}

func newStuckGuest(t *testing.T, s *Store, agent, host string, budget RestartBudget) *stuckGuest {
	r := &stuckGuest{MockRuntime: mockStores(t, t.TempDir(), agent), t: t, s: s, agent: agent, host: host, budget: budget, halt: make(chan struct{})}
	r.SetHandler(func(ctx context.Context, target string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		i, err := capsuleprotocol.DecodeInvocation(e, target)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS instruction_effects(id TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO instruction_effects VALUES(?)", e.ID); err != nil {
			return nil, err
		}
		if strings.Contains(i.Content[0].Text, "never-return") {
			r.mu.Lock()
			r.holding = true
			halt := r.halt
			r.mu.Unlock()
			<-halt
			return nil, errors.New("the VM stopped under the harness")
		}
		return json.Marshal(i.Content)
	})
	return r
}

func vmIdentifier(generation uint64) string { return fmt.Sprintf("%016x", generation) }

// Invoke boots the agent for work if no VM runs, as the worker's preparation
// does. A handler that holds the store ends the attempt at the host's
// timeout; while it holds the store, the guest answers that it cannot
// (capsuleprotocol.ErrTransport, as a busy store's "unavailable").
func (r *stuckGuest) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	r.mu.Lock()
	if r.generation == 0 {
		p, err := r.s.ClaimPlacement(ctx, r.agent, r.host, "worker", time.Minute)
		if err == nil {
			err = r.s.ConfirmPlacement(ctx, r.agent, r.host, "worker", p.Generation, vmIdentifier(p.Generation))
		}
		if err != nil {
			r.mu.Unlock()
			return harnessstore.Receipt{}, err
		}
		r.generation = p.Generation
	}
	holding := r.holding
	r.mu.Unlock()
	if holding {
		return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
	}
	type sent struct {
		receipt harnessstore.Receipt
		err     error
	}
	done := make(chan sent, 1)
	r.handlers.Add(1)
	go func() {
		defer r.handlers.Done()
		// The harness ignores its caller's deadline.
		receipt, err := r.Send(context.WithoutCancel(ctx), target, e)
		done <- sent{receipt, err}
	}()
	for {
		select {
		case s := <-done:
			return s.receipt, s.err
		case <-time.After(10 * time.Millisecond):
			r.mu.Lock()
			holding = r.holding
			r.mu.Unlock()
			if holding {
				return harnessstore.Receipt{}, errors.Join(capsuleprotocol.ErrTransport, context.DeadlineExceeded)
			}
		}
	}
}

func (r *stuckGuest) Fence(ctx context.Context, target, subject string) error {
	r.mu.Lock()
	fault, generation := r.fault, r.generation
	r.fault = nil
	r.mu.Unlock()
	if fault != nil {
		return fault
	}
	if generation != 0 {
		// The running VM's guest answers, or not: its fence waits for the
		// store's write lock, which a held handler never gives up.
		if err := r.MockRuntime.Fence(ctx, target, subject); err != nil {
			return &UnresponsiveGuestError{Generation: generation, Err: errors.Join(capsuleprotocol.ErrTransport, err)}
		}
		return nil
	}
	p, err := r.s.ClaimFencePlacement(ctx, r.agent, r.host, "worker", time.Minute)
	if err != nil {
		return err
	}
	r.restricted++
	if err = r.s.ConfirmFencePlacement(ctx, r.agent, r.host, "worker", p.Generation, vmIdentifier(p.Generation)); err != nil {
		return err
	}
	err = r.MockRuntime.Fence(ctx, target, subject)
	if stop := r.s.BeginPlacementStop(ctx, r.agent, r.host, p.Generation); stop != nil {
		return errors.Join(err, stop)
	}
	return errors.Join(err, r.s.ObservePlacementStopped(ctx, r.agent, r.host, p.Generation, false))
}

func (r *stuckGuest) StopUnresponsiveGuest(ctx context.Context, target string, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops = append(r.stops, generation)
	if target != r.agent || generation != r.generation {
		return nil
	}
	if err := r.s.BeginPlacementStop(ctx, r.agent, r.host, generation); err != nil {
		return err
	}
	close(r.halt)
	r.handlers.Wait()
	r.halt, r.holding, r.generation = make(chan struct{}), false, 0
	_, err := r.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: r.agent, HostID: r.host, Kind: GuestUnresponsive, Generation: generation}, r.budget)
	return err
}

// stuckInvocation spends the three attempts of the agent's first queued
// invocation, which its harness never answers, and returns its mailbox and
// operation, with the next invocation's waiting behind it.
func stuckInvocation(t *testing.T, s *Store, c *AgentCatalog, tr *Transit, owner Principal, rt *stuckGuest) (first, firstOp, second, secondOp string) {
	t.Helper()
	first, firstOp = queueInstruction(t, c, owner, rt.agent, "never-return")
	second, secondOp = queueInstruction(t, c, owner, rt.agent, "after-it")
	for attempt := range 3 {
		if err := tr.DispatchMailbox(t.Context(), first, time.Minute, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("attempt", attempt+1, err)
		}
		expireLease(t, s, first)
	}
	// The later invocation waits behind it.
	if err := tr.DispatchMailbox(t.Context(), second, time.Minute, rt); !errors.Is(err, ErrNotHead) {
		t.Fatal("the next invocation overtook the held one", err)
	}
	return first, firstOp, second, secondOp
}

func heldDelivery(t *testing.T, s *Store, id string) (state string, closing bool) {
	t.Helper()
	if err := s.pool.QueryRow(t.Context(), "SELECT delivery_state,closing FROM agent_mailboxes WHERE id=$1", id).Scan(&state, &closing); err != nil {
		t.Fatal(err)
	}
	return state, closing
}

func guestFailureKinds(t *testing.T, s *Store, agent string) []string {
	t.Helper()
	rows, err := s.pool.Query(t.Context(), "SELECT kind,generation FROM guest_failures WHERE agent_id=$1 ORDER BY generation", agent)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var kind string
		var generation int64
		if err = rows.Scan(&kind, &generation); err != nil {
			t.Fatal(err)
		}
		found = append(found, fmt.Sprintf("%s/%d", kind, generation))
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return found
}

// A harness that never returns from an invocation (ADR 012, question 7,
// option (b)). Its three attempts end at the host's timeout while it holds
// its store, and the invocation behind it waits. A fence that fails for the
// platform stops nothing. The fence its held store refuses stops its VM,
// counts a guest failure of kind unresponsive for that boot, and goes
// through a restricted boot: the invocation fails with
// delivery_outcome_unknown, the held handler's effect never committed, and
// the next invocation is answered by a new boot.
func TestAHarnessThatNeverAnswersIsStoppedAndItsInvocationEnds(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	ctx := t.Context()
	rt := newStuckGuest(t, s, e.AgentID, e.HostID, DefaultRestartBudget)
	first, firstOp, second, secondOp := stuckInvocation(t, s, c, tr, owner, rt)
	held := rt.generation

	rt.fault = errors.New("authority service unavailable")
	if err := tr.DispatchMailbox(ctx, first, time.Minute, rt); err == nil || errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("the fence's platform fault", err)
	}
	if len(rt.stops) != 0 {
		t.Fatal("a platform fault stopped the VM", rt.stops)
	}
	if state, closing := heldDelivery(t, s, first); state != "PENDING" || !closing {
		t.Fatal("the invocation after its fence failed", state, closing)
	}

	if err := tr.DispatchMailbox(ctx, first, time.Minute, rt); err != nil {
		t.Fatal("the fence of a held store", err)
	}
	if !slices.Equal(rt.stops, []uint64{held}) || rt.restricted != 1 {
		t.Fatal("stops and restricted boots", rt.stops, held, rt.restricted)
	}
	if got := guestFailureKinds(t, s, e.AgentID); !slices.Equal(got, []string{fmt.Sprintf("%s/%d", GuestUnresponsive, held)}) {
		t.Fatal("guest failures", got)
	}
	if state, _ := heldDelivery(t, s, first); state != "DEAD" {
		t.Fatal("the invocation's delivery", state)
	}
	op, err := c.Operation(ctx, owner, firstOp)
	if err != nil || op.Status != "FAILED" || op.ErrorCode != "delivery_outcome_unknown" {
		t.Fatal("the invocation the harness never answered", op.Status, op.ErrorCode, err)
	}
	var reason string
	if err = s.pool.QueryRow(ctx, "SELECT close_reason FROM owner_instructions WHERE operation_id=$1", firstOp).Scan(&reason); err != nil || reason != "attempts_exhausted" {
		t.Fatal("close reason", reason, err)
	}
	var state string
	if err = s.pool.QueryRow(ctx, "SELECT state FROM agent_placements WHERE agent_id=$1", e.AgentID).Scan(&state); err != nil || state != "STOPPED" {
		t.Fatal("placement after the restricted boot", state, err)
	}
	if v, err := c.Get(ctx, owner, e.AgentID); err != nil || v.State != "STOPPED" || v.FailureReason != nil {
		t.Fatal("the agent within its budget", v.State, v.FailureReason, err)
	}

	if err = tr.DispatchMailbox(ctx, second, time.Minute, rt); err != nil {
		t.Fatal("the next invocation", err)
	}
	if op, err = c.Operation(ctx, owner, secondOp); err != nil || op.Status != "SUCCEEDED" {
		t.Fatal("the next invocation", op.Status, op.ErrorCode, err)
	}
	if rt.generation <= held {
		t.Fatal("the next invocation was not answered by a new boot", rt.generation, held)
	}
	// The fence holds in the store, and what the held handler wrote never
	// committed; the next invocation's effect did.
	late := harnessstore.Event{ID: "late-" + first, Subjects: []string{"agent/" + e.AgentID, "event/" + first}, Body: []byte("{}")}
	if _, err = rt.Send(ctx, e.AgentID, late); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the held invocation is not fenced in the store", err)
	}
	var effects []string
	read := harnessstore.Event{ID: "read-effects", Subjects: []string{"agent/" + e.AgentID}, Body: []byte("{}")}
	if _, err = rt.Deliver(ctx, e.AgentID, read, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		rows, err := tx.QueryContext(ctx, "SELECT id FROM instruction_effects ORDER BY id")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				return nil, err
			}
			effects = append(effects, id)
		}
		return []byte("{}"), rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effects, []string{second}) {
		t.Fatal("effects in the store", effects, first, second)
	}
}

// An unresponsive guest's failure counts against the restart budget like
// the others. With a budget of one, the agent is FAILED with the reason
// unresponsive, and the restricted boot that would fence the invocation is
// not claimed: the invocation waits, closing, until a wake gives the agent
// a new budget, then dies behind its fence.
func TestAnUnresponsiveGuestSpendsTheRestartBudget(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	ctx := t.Context()
	rt := newStuckGuest(t, s, e.AgentID, e.HostID, RestartBudget{Failures: 1, Window: time.Hour})
	first, firstOp, _, _ := stuckInvocation(t, s, c, tr, owner, rt)
	held := rt.generation
	if err := tr.DispatchMailbox(ctx, first, time.Minute, rt); !errors.Is(err, ErrAgentFailed) {
		t.Fatal("the restricted boot of a FAILED agent", err)
	}
	if !slices.Equal(rt.stops, []uint64{held}) || rt.restricted != 0 {
		t.Fatal("stops and restricted boots", rt.stops, rt.restricted)
	}
	v, err := c.Get(ctx, owner, e.AgentID)
	if err != nil || v.State != "FAILED" || v.FailureReason == nil || *v.FailureReason != "unresponsive" {
		t.Fatal("the agent after its budget", v.State, v.FailureReason, err)
	}
	if state, closing := heldDelivery(t, s, first); state != "PENDING" || !closing {
		t.Fatal("the invocation of a FAILED agent", state, closing)
	}
	if _, err = c.RequestLifecycle(ctx, owner, e.AgentID, "wake-unresponsive", "wake"); err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(ctx, first, time.Minute, rt); err != nil {
		t.Fatal("after the wake", err)
	}
	if op, err := c.Operation(ctx, owner, firstOp); err != nil || op.Status != "FAILED" || op.ErrorCode != "delivery_outcome_unknown" {
		t.Fatal("the invocation", op.Status, op.ErrorCode, err)
	}
	if rt.restricted != 1 {
		t.Fatal("restricted boots", rt.restricted)
	}
}

// refusingGuests stands for the VMs of agents whose guests refuse every
// fence while they run (running: agent to generation). StopUnresponsiveGuest
// stops one and counts its failure; a stopped agent's store is fenced as
// the restricted boot would.
type refusingGuests struct {
	*peerRuntime
	s       *Store
	host    string
	running map[string]uint64
	refusal error
	stops   []string
}

func (r *refusingGuests) Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
}

func (r *refusingGuests) Fence(ctx context.Context, target, subject string) error {
	if g, ok := r.running[target]; ok {
		if r.refusal != nil {
			return r.refusal
		}
		return &UnresponsiveGuestError{Generation: g, Err: capsuleprotocol.ErrTransport}
	}
	return r.peerRuntime.Fence(ctx, target, subject)
}

func (r *refusingGuests) StopUnresponsiveGuest(ctx context.Context, target string, generation uint64) error {
	r.stops = append(r.stops, fmt.Sprintf("%s/%d", target, generation))
	if r.running[target] != generation {
		return nil
	}
	delete(r.running, target)
	if err := r.s.BeginPlacementStop(ctx, target, r.host, generation); err != nil {
		return err
	}
	_, err := r.s.ObserveGuestFailure(ctx, GuestFailure{AgentID: target, HostID: r.host, Kind: GuestUnresponsive, Generation: generation}, DefaultRestartBudget)
	return err
}

// A reply past its attempts, which its sender's guest never acknowledged,
// dies behind a fence that guest refuses: the worker stops the guest's VM,
// and the fence goes through a restricted boot.
func TestAReplyPastItsAttemptsStopsTheGuestThatRefusesItsFence(t *testing.T) {
	l := newDeadReplyLab(t)
	rt := &refusingGuests{peerRuntime: l.rt, s: l.s, host: "host", running: map[string]uint64{"a": l.a.Generation}}
	for range 3 {
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("a failed attempt", err)
		}
		expireLease(t, l.s, l.reply)
	}
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	l.deliveryState(t, "DEAD")
	if want := []string{fmt.Sprintf("a/%d", l.a.Generation)}; !slices.Equal(rt.stops, want) {
		t.Fatal("stops", rt.stops)
	}
	if got := guestFailureKinds(t, l.s, "a"); !slices.Equal(got, []string{fmt.Sprintf("%s/%d", GuestUnresponsive, l.a.Generation)}) {
		t.Fatal("guest failures", got)
	}
}

// A request past its attempts is closed, and its closure fences both
// parties. The sender's guest refuses first, but its own mailbox holds
// nothing past its attempts: its VM is not stopped, and the closure waits
// for its fence. Once it answers, the recipient's guest, which holds the
// request, refuses: its VM is stopped, and the closure commits.
func TestARequestPastItsAttemptsStopsOnlyTheGuestItHolds(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	tr := peerTransit(t, s)
	a, b := confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b")
	r, err := tr.SubmitFromVM(t.Context(), a, "request", peerSubmission("a question nobody answers"))
	if err != nil {
		t.Fatal(err)
	}
	request := mailboxFor(t, s, r.RequestID, "request")
	rt := &refusingGuests{peerRuntime: peerRuntimeLab(t), s: s, host: "host", running: map[string]uint64{"a": a.Generation, "b": b.Generation}}
	for range 3 {
		if err = tr.DispatchMailbox(t.Context(), request, time.Minute, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("a failed attempt", err)
		}
		expireLease(t, s, request)
	}
	if err = tr.DispatchMailbox(t.Context(), request, time.Minute, rt); !errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("the sender's refused fence", err)
	}
	if len(rt.stops) != 0 {
		t.Fatal("the sender's VM was stopped", rt.stops)
	}
	assertRequestState(t, s, r.RequestID, "DELIVERING")
	delete(rt.running, "a")
	if err = s.ReconcileRequestClosure(t.Context(), r.RequestID, rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r.RequestID, "FAILED")
	if want := []string{fmt.Sprintf("b/%d", b.Generation)}; !slices.Equal(rt.stops, want) {
		t.Fatal("stops", rt.stops)
	}
	if got := guestFailureKinds(t, s, "a"); len(got) != 0 {
		t.Fatal("the sender's guest failures", got)
	}
	if got := guestFailureKinds(t, s, "b"); !slices.Equal(got, []string{fmt.Sprintf("%s/%d", GuestUnresponsive, b.Generation)}) {
		t.Fatal("the recipient's guest failures", got)
	}
}

// Only a fence past the attempts of a delivery stops a guest: the agent's
// mailbox is held by its head, pending, which an attempt may have reached,
// with no attempt under way, and which can no longer be attempted (closing,
// past its deadline, or its attempts spent). A platform's failure, or a
// runtime that cannot stop a VM, stops nothing.
func TestOnlyAFencePastTheAttemptsStopsAGuest(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	ctx := t.Context()
	id, _ := queueInstruction(t, c, owner, e.AgentID, "probe")
	p, err := s.ClaimPlacement(ctx, e.AgentID, e.HostID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(ctx, e.AgentID, e.HostID, "worker", p.Generation, vmIdentifier(p.Generation)); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.ClaimInstruction(ctx, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	refused := &UnresponsiveGuestError{Generation: p.Generation, Err: capsuleprotocol.ErrTransport}
	for _, c := range []struct {
		name, set string
		err       error
		stops     bool
	}{
		{"an attempt under way", "closing=false,attempts=1,lease_until=clock_timestamp()+interval '1 minute',may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", refused, false},
		{"its attempts spent, the last under way", "closing=false,attempts=3,lease_until=clock_timestamp()+interval '1 minute',may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", refused, false},
		{"between two attempts", "closing=false,attempts=1,lease_until=NULL,may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", refused, false},
		{"no attempt reached it", "closing=false,attempts=3,lease_until=NULL,may_have_reached=false,expires_at=clock_timestamp()+interval '1 hour'", refused, false},
		{"its attempts spent", "closing=false,attempts=3,lease_until=clock_timestamp()-interval '1 second',may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", refused, true},
		{"past its deadline", "closing=false,attempts=1,lease_until=NULL,may_have_reached=true,expires_at=clock_timestamp()-interval '1 second'", refused, true},
		{"closing", "attempts=1,lease_until=NULL,may_have_reached=true,closing=true,expires_at=clock_timestamp()+interval '1 hour'", refused, true},
		{"a platform failure", "closing=false,attempts=3,lease_until=NULL,may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", errors.New("PostgreSQL unavailable"), false},
		{"a refusal wrapped by its caller", "closing=false,attempts=3,lease_until=NULL,may_have_reached=true,expires_at=clock_timestamp()+interval '1 hour'", fmt.Errorf("fence: %w", refused), true},
	} {
		if _, err = s.pool.Exec(ctx, "UPDATE agent_mailboxes SET "+c.set+" WHERE id=$1", id); err != nil {
			t.Fatal(c.name, err)
		}
		f := &fenceOnce{err: c.err}
		err = s.fencePastAttempts(ctx, f, e.AgentID, "event/"+id)
		if stopped := len(f.stops) == 1; stopped != c.stops {
			t.Error(c.name, "stopped", stopped, err)
		}
		if c.stops && (err != nil || f.fences != 2 || f.stops[0] != p.Generation) {
			t.Error(c.name, "fence after the stop", f.fences, f.stops, err)
		}
		if !c.stops && (err == nil || f.fences != 1) {
			t.Error(c.name, "the failure is returned", f.fences, err)
		}
	}
	if err = s.fencePastAttempts(ctx, cannotStop{}, e.AgentID, "event/"+id); !errors.As(err, new(*UnresponsiveGuestError)) {
		t.Fatal("a runtime that cannot stop a VM", err)
	}
	if _, err = s.pool.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='DEAD' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	f := &fenceOnce{err: refused}
	if err = s.fencePastAttempts(ctx, f, e.AgentID, "event/"+id); err == nil || len(f.stops) != 0 {
		t.Fatal("a mailbox with nothing pending", f.stops, err)
	}
}

// fenceOnce fails its first fence with err and succeeds after; it records
// the generations it was asked to stop.
type fenceOnce struct {
	err    error
	fences int
	stops  []uint64
}

func (f *fenceOnce) Fence(context.Context, string, string) error {
	f.fences++
	if f.fences == 1 {
		return f.err
	}
	return nil
}

func (f *fenceOnce) StopUnresponsiveGuest(_ context.Context, _ string, generation uint64) error {
	f.stops = append(f.stops, generation)
	return nil
}

// cannotStop refuses every fence and cannot stop a VM.
type cannotStop struct{}

func (cannotStop) Fence(context.Context, string, string) error {
	return &UnresponsiveGuestError{Generation: 1, Err: capsuleprotocol.ErrTransport}
}
