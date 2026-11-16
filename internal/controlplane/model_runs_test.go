package controlplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// Go projections of model runs that no ITF fixture replays. Each test drives
// the production code through the run's steps and checks its expectation.
// spec/projections.md lists every run and the test that projects it.

// p1Act builds a P1 action as its ITF manifest spells it (numbers as JSON).
func p1Act(t *testing.T, name, args string) protocolAction {
	t.Helper()
	var op protocolAction
	if err := json.Unmarshal([]byte(`{"name":"`+name+`","args":`+args+`}`), &op); err != nil {
		t.Fatal(err)
	}
	return op
}

func (a *p1Replay) run(t *testing.T, steps ...protocolAction) {
	t.Helper()
	for _, op := range steps {
		if err := a.step(t, op); err != nil {
			t.Fatalf("%s %v: %v", op.Name, op.Args, err)
		}
	}
}

// localEffects counts the application effects of one event in an agent's
// harness store; a store whose effect table was never created counts zero.
func localEffects(t *testing.T, root, agent, eventID string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(root, fmt.Sprintf("%x", sha256.Sum256([]byte(agent))), "harness.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var table, n int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='received'").Scan(&table); err != nil {
		t.Fatal(err)
	}
	if table == 0 {
		return 0
	}
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM received WHERE event_id=?", eventID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// abortedWriterThenFenceTest (concurrent_protocol_test.qnt), with a real crash
// of the guest's writer. B's harness store runs its SQLite writer in another
// process, which holds the effect's open transaction when it is killed
// (SIGKILL: no rollback, no close). The P1 fixture writer-crash-then-
// restricted-fencing replays the same steps but cancels the writer instead.
// The writer process stands for the guest's harness; it is not a VMM.
func TestAbortedWriterThenFence(t *testing.T) {
	a := newP1Replay(t, false)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},0]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	a.events["request/0/request"] = mailboxFor(t, a.s, a.requests[0], "request")
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,0]}]`), p1Act(t, "authorize", `[0]`))
	attempt := a.rpc[0].attempt
	if attempt.Destination != "b" {
		t.Fatal("route 0 must deliver to b:", attempt.Destination)
	}

	// beginEffect(0): B's writer, in its own process, applies the delivery
	// and stops inside its open transaction.
	a.stopLocal(t, 1)
	path := filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte("b"))), "harness.db")
	event, err := json.Marshal(attempt.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	// A second handle on B's store, opened before the writer starts, asks for
	// the fence below.
	direct, err := harnessstore.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestModelWriterCrashChild$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_MODEL_WRITER_DB="+path, "AGENTCAPSULE_MODEL_WRITER_EVENT="+string(event))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	ready := make(chan string, 1)
	go func() {
		r := bufio.NewReader(stdout)
		for {
			line, err := r.ReadString('\n')
			if err != nil || line == "WRITER-READY\n" {
				ready <- line
				return
			}
		}
	}()
	select {
	case line := <-ready:
		if line != "WRITER-READY\n" {
			t.Fatalf("writer did not open its transaction: %q %s", line, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("writer did not open its transaction:", stderr.String())
	}

	a.run(t, p1Act(t, "requestDelete", `[1]`))
	// writerBlocksFenceTest: while the writer holds its transaction, B's
	// store gives no fence.
	probe, cancelProbe := context.WithTimeout(t.Context(), 300*time.Millisecond)
	err = direct.Fence(probe, "agent/b")
	cancelProbe()
	if err == nil {
		t.Fatal("B's store gave a fence while its writer held an effect transaction")
	}

	// stopVM(1): the writer dies without rolling back or closing SQLite.
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("killed writer reported success")
	}
	a.rpc[0] = nil
	// restart(1, true): a restricted boot opens the store the writer left.
	a.run(t, p1Act(t, "retireBoot", `[1]`), p1Act(t, "observeStopped", `[1]`), p1Act(t, "bootVM", `[1,true]`),
		p1Act(t, "launchBoot", `[1]`), p1Act(t, "confirmBoot", `[1]`), p1Act(t, "publishBoot", `[1]`))
	if !a.restricted[1] {
		t.Fatal("the new boot of B is not restricted")
	}
	// barrierEverywhere(AgentSubject(1)), then commitDelete(1).
	for store := range 3 {
		subject := `[` + fmt.Sprint(store) + `,{"variant":"AgentSubject","value":1}]`
		a.run(t, p1Act(t, "fenceStore", subject), p1Act(t, "recordFence", subject))
	}
	a.run(t, p1Act(t, "commitDelete", `[1]`))

	// expect: s.effects.get((0,0)) == 0 and s.requests.get(0).phase == Canceled.
	if n := localEffects(t, a.root, "b", attempt.Envelope.ID); n != 0 {
		t.Fatalf("the killed writer's effect survived: %d", n)
	}
	assertRequestState(t, a.s, a.requests[0], "CANCELED")
	// noStaleEffect: once fenced, B's store refuses the delayed delivery.
	if _, err = a.boots[1].store.Apply(t.Context(), attempt.Envelope, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		return recordDelivery(ctx, "b", attempt.Envelope, tx)
	}); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the fenced store applied the delayed delivery:", err)
	}
	if n := localEffects(t, a.root, "b", attempt.Envelope.ID); n != 0 {
		t.Fatalf("delayed delivery applied after the fence: %d", n)
	}
}

// TestModelWriterCrashChild is the writer process of TestAbortedWriterThenFence.
func TestModelWriterCrashChild(t *testing.T) {
	path := os.Getenv("AGENTCAPSULE_MODEL_WRITER_DB")
	if path == "" {
		return
	}
	var event harnessstore.Event
	if err := json.Unmarshal([]byte(os.Getenv("AGENTCAPSULE_MODEL_WRITER_EVENT")), &event); err != nil {
		t.Fatal(err)
	}
	store, err := harnessstore.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Apply(context.Background(), event, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		if _, err := recordDelivery(ctx, "b", event, tx); err != nil {
			return nil, err
		}
		fmt.Println("WRITER-READY")
		select {} // killed here, inside the open transaction
	})
	t.Fatal("writer left its transaction:", err)
}

// confirmationCrashRetainsWakeTest (credential_renewal.qnt): the worker
// crashes after the replacement boot is confirmed in SQL but before the host
// published it. Recovery retires that boot; the renewal job survives, and a
// second replacement completes it.
func TestConfirmationCrashRetainsWake(t *testing.T) {
	s, _ := freshStore(t, "auto", 1)
	old := renewalBoot(t, s, "a")
	// request, retire, readJob.
	if err := s.BeginCredentialRenewal(t.Context(), "a", "host", old.Generation, old.VMID); err != nil {
		t.Fatal(err)
	}
	if err := s.ObservePlacementStopped(t.Context(), "a", "host", old.Generation, true); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.PendingCredentialRenewals(t.Context(), "host")
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	// start, confirmSQL.
	first, err := s.ClaimRenewalPlacement(t.Context(), jobs[0], "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(t.Context(), "a", "host", "worker", first.Generation, "unpublished"); err != nil {
		t.Fatal(err)
	}
	// crash, recover: the recovering worker retires the boot it never
	// published. Its SQL confirmation completes nothing.
	if err = s.ObservePlacementStopped(t.Context(), "a", "host", first.Generation, true); err != nil {
		t.Fatal(err)
	}
	// expect: s.job and s.owed and s.vm == "absent".
	jobs, err = s.PendingCredentialRenewals(t.Context(), "host")
	if err != nil || len(jobs) != 1 || jobs[0].Generation != old.Generation {
		t.Fatal("the renewal job did not survive the crash:", jobs, err)
	}
	placements, err := s.Placements(t.Context(), "host")
	if err != nil || len(placements) != 1 || placements[0].State != "STOPPED" {
		t.Fatal("the unpublished boot was not retired:", placements, err)
	}
	// readJob, start, confirmSQL, publishHost, complete.
	second, err := s.ClaimRenewalPlacement(t.Context(), jobs[0], "worker", time.Minute)
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatal(second, err)
	}
	if err = s.ConfirmPlacement(t.Context(), "a", "host", "worker", second.Generation, "published"); err != nil {
		t.Fatal(err)
	}
	if err = s.ObserveRenewalSatisfied(t.Context(), "a", "host", second.Generation, "published"); err != nil {
		t.Fatal(err)
	}
	// expect: s.completed.
	if n := count(t, s, "placement_renewals"); n != 0 {
		t.Fatal("the completed renewal is still owed:", n)
	}
}

// bind names a request's mailbox as the model names its event.
func (a *p1Replay) bind(t *testing.T, request int, kind string) {
	t.Helper()
	a.events[fmt.Sprintf("request/%d/%s", request, kind)] = mailboxFor(t, a.s, a.requests[request], kind)
}

func (a *p1Replay) submit(t *testing.T, request int) {
	t.Helper()
	sender := fmt.Sprint(p1Routes[request][0])
	a.run(t, p1Act(t, "receive", `[0,`+fmt.Sprint(request)+`,{"variant":"SubmitCall"},`+sender+`]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	a.bind(t, request, "request")
}

func (a *p1Replay) deliver(t *testing.T, rpc int, request int, kind int) {
	t.Helper()
	e := `[` + fmt.Sprint(rpc) + `,{"tuple":[` + fmt.Sprint(request) + `,` + fmt.Sprint(kind) + `]}]`
	w := `[` + fmt.Sprint(rpc) + `]`
	a.run(t, p1Act(t, "claim", e), p1Act(t, "authorize", w), p1Act(t, "beginEffect", w), p1Act(t, "commitEffect", w), p1Act(t, "acknowledge", w))
}

// refusedCall runs a received call to its end without holding it at the
// admission gate, and returns its error: the model's admit(slot).fail().
func (a *p1Replay) refusedCall(t *testing.T, slot int) error {
	t.Helper()
	a.startCall(t, slot)
	c := a.calls[slot]
	rollback(c.gate)
	c.gate = nil
	var result protocolAPIResult
	select {
	case result = <-c.done:
		c.done = nil
	case <-time.After(6 * time.Second):
		t.Fatal("refused call did not end")
	}
	a.cancelCall(t, slot, false)
	if result.err == nil {
		t.Fatal("the model refuses this call; Go accepted it")
	}
	return result.err
}

// terminalStateSurvivesLateReplyTest: the request is canceled while B's reply
// is received but not admitted; the late reply cannot change it.
func TestTerminalStateSurvivesLateReply(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.deliver(t, 0, 0, 0)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"ReplyCall"},1]`), p1Act(t, "closeRequest", `[0,{"variant":"CancelRequest"}]`))
	for store := range 3 {
		subject := `[` + fmt.Sprint(store) + `,{"variant":"RequestSubject","value":0}]`
		a.run(t, p1Act(t, "fenceStore", subject), p1Act(t, "recordFence", subject))
	}
	a.run(t, p1Act(t, "commitClose", `[0]`))
	assertRequestState(t, a.s, a.requests[0], "CANCELED")
	if err := a.refusedCall(t, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("late reply:", err)
	}
	assertRequestState(t, a.s, a.requests[0], "CANCELED")
	var replies int
	if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE ref_id=$1 AND kind='reply'", a.requests[0]).Scan(&replies); err != nil || replies != 0 {
		t.Fatal("the late reply was queued:", replies, err)
	}
}

// foreignMandateTest: A cannot spend C's mandate.
func TestForeignMandate(t *testing.T) {
	a := newP1Replay(t, false)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},2]`))
	if err := a.refusedCall(t, 0); !errors.Is(err, ErrMandate) {
		t.Fatal("foreign mandate:", err)
	}
	if n := count(t, a.s, "agent_requests"); n != 0 {
		t.Fatal("a request was made on a foreign mandate:", n)
	}
	var remaining int
	if err := a.s.pool.QueryRow(t.Context(), "SELECT remaining FROM mandates WHERE id='mandate-c'").Scan(&remaining); err != nil || remaining != 2 {
		t.Fatal("C's mandate was spent:", remaining, err)
	}
}

// fifoAcrossRequestsTest: B's queue is in commit order across requests.
func TestFifoAcrossRequests(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 1)
	a.submit(t, 0)
	// expect isHead(s, (1,0)), then claim(0, (0,0)).fail().
	if _, err := a.s.ClaimDelivery(t.Context(), a.events["request/0/request"], time.Hour); !errors.Is(err, ErrNotHead) {
		t.Fatal("the later request overtook B's queue:", err)
	}
	attempt, err := a.s.ClaimDelivery(t.Context(), a.events["request/1/request"], time.Hour)
	if err != nil || attempt.RequestID != a.requests[1] {
		t.Fatal("the head of B's queue is not request 1:", attempt, err)
	}
}

// authorityLockTest: an admitted call holds its agent's authority, so SQL
// cannot record A stopped until the call ends.
func TestAuthorityLock(t *testing.T) {
	a := newP1Replay(t, false)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},0]`), p1Act(t, "admit", `[0]`),
		p1Act(t, "stopVM", `[0]`), p1Act(t, "retireBoot", `[0]`))
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	err := a.s.ObservePlacementStopped(ctx, "a", a.callers[0].HostID, a.callers[0].Generation, true)
	cancel()
	if err == nil {
		t.Fatal("A was recorded stopped while its admitted call held its authority")
	}
	var state string
	if err = a.s.pool.QueryRow(t.Context(), "SELECT state FROM agent_placements WHERE agent_id='a'").Scan(&state); err != nil || state != "RUNNING" {
		t.Fatal("A's placement changed under the admitted call:", state, err)
	}
	// The call commits; then A can be recorded stopped (admittedPhysicalDeathTest).
	a.run(t, p1Act(t, "commitCall", `[0]`), p1Act(t, "observeStopped", `[0]`))
}

// receivedCallCanEnterSQLAfterPhysicalCrashTest (protocol_composition.qnt):
// A's call reached the platform before A's VM died; SQL has not retired A,
// so the call is admitted and commits.
func TestReceivedCallCanEnterSQLAfterPhysicalCrash(t *testing.T) {
	a := newP1Replay(t, false)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},0]`), p1Act(t, "stopVM", `[0]`),
		p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	assertRequestState(t, a.s, a.requests[0], "DELIVERING")
}

// sqlRetirementRejectsReceivedCallTest (protocol_composition.qnt), and the
// guard of concurrentWitnessStaleCallerGuard: once SQL begins to stop A, a
// call A sent before is refused, though A's VM still runs.
func TestSqlRetirementRejectsReceivedCall(t *testing.T) {
	a := newP1Replay(t, false)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"SubmitCall"},0]`), p1Act(t, "beginStop", `[0]`))
	if err := a.boots[0].client.Health(t.Context()); err != nil {
		t.Fatal("A's boot stopped with the SQL stop:", err)
	}
	a.refuseP1(t, p1Act(t, "admit", `[0]`), "ErrPlacement; no business mutation")
	if n := count(t, a.s, "agent_requests"); n != 0 {
		t.Fatal("the stale caller's request was made:", n)
	}
}

// concurrentWitnessRacyFenceGuard.guardTest: request 0 expires while B's
// writer applies it; A's store fences the request, B's store cannot until
// the writer ends.
func TestConcurrentWitnessRacyFenceGuard(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,0]}]`), p1Act(t, "authorize", `[0]`), p1Act(t, "beginEffect", `[0]`),
		p1Act(t, "closeRequest", `[0,{"variant":"ExpireRequest"}]`),
		p1Act(t, "fenceStore", `[0,{"variant":"RequestSubject","value":0}]`),
		p1Act(t, "recordFence", `[0,{"variant":"RequestSubject","value":0}]`))
	a.refuseP1(t, p1Act(t, "fenceStore", `[1,{"variant":"RequestSubject","value":0}]`), "")
}

// concurrentWitnessWrongRequestFenceGuard.guardTest: request 1 is closed and
// fenced everywhere while an RPC carrying it is authorized; that RPC applies
// nothing in B's store.
func TestConcurrentWitnessWrongRequestFenceGuard(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 1)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[1,0]}]`), p1Act(t, "authorize", `[0]`),
		p1Act(t, "closeRequest", `[1,{"variant":"ExpireRequest"}]`))
	for store := range 3 {
		subject := `[` + fmt.Sprint(store) + `,{"variant":"RequestSubject","value":1}]`
		a.run(t, p1Act(t, "fenceStore", subject), p1Act(t, "recordFence", subject))
	}
	a.run(t, p1Act(t, "commitClose", `[1]`))
	assertRequestState(t, a.s, a.requests[1], "EXPIRED")
	event := a.rpc[0].attempt.Envelope.ID
	if err := a.step(t, p1Act(t, "beginEffect", `[0]`)); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the authorized RPC of a fenced request was applied:", err)
	}
	if n := localEffects(t, a.root, "b", event); n != 0 {
		t.Fatal("effects of the fenced request in B's store:", n)
	}
}

// closingWithStoppedBystander: request 0 (A to B) is authorized for B while
// C, no party to it, is stopped; then the request expires.
func closingWithStoppedBystander(t *testing.T) *p1Replay {
	t.Helper()
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,0]}]`), p1Act(t, "authorize", `[0]`),
		p1Act(t, "stopVM", `[2]`), p1Act(t, "retireBoot", `[2]`), p1Act(t, "observeStopped", `[2]`),
		p1Act(t, "closeRequest", `[0,{"variant":"ExpireRequest"}]`))
	return a
}

// closureFencesOnlyItsPartiesTest (ADR 007 §7): C's store, stopped, gives no
// fence for the request.
func TestClosureFencesOnlyItsParties(t *testing.T) {
	a := closingWithStoppedBystander(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := a.boots[2].client.Fence(ctx, a.subject(p1Act(t, "fenceStore", `[2,{"variant":"RequestSubject","value":0}]`).Args[1])); err == nil {
		t.Fatal("a stopped bystander's store gave a fence")
	}
}

// closureCommitsWithoutOtherStoresTest (ADR 007 §7): the closure commits on
// its two parties' fences, without C's; the authorized send to B then
// applies nothing.
func TestClosureCommitsWithoutOtherStores(t *testing.T) {
	a := closingWithStoppedBystander(t)
	for store := range 2 {
		subject := `[` + fmt.Sprint(store) + `,{"variant":"RequestSubject","value":0}]`
		a.run(t, p1Act(t, "fenceStore", subject), p1Act(t, "recordFence", subject))
	}
	a.run(t, p1Act(t, "commitClose", `[0]`))
	assertRequestState(t, a.s, a.requests[0], "EXPIRED")
	var receipts int
	if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM request_closure_targets WHERE request_id=$1 AND store_agent_id='c'", a.requests[0]).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("the closure involved C's store:", receipts, err)
	}
	event := a.rpc[0].attempt.Envelope.ID
	if err := a.step(t, p1Act(t, "beginEffect", `[0]`)); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the authorized send applied the expired request:", err)
	}
	if n := localEffects(t, a.root, "b", event); n != 0 {
		t.Fatal("effects of the expired request in B's store:", n)
	}
}

// fencedDuplicateRefusedTest: B's reply reached A and its ACK was lost; B is
// deleted while a second claim of the reply is authorized. That claim's RPC
// cannot apply anything: A's store is fenced for B.
func TestFencedDuplicateRefused(t *testing.T) {
	a := newP1Replay(t, false)
	a.submit(t, 0)
	a.deliver(t, 0, 0, 0)
	a.run(t, p1Act(t, "receive", `[0,0,{"variant":"ReplyCall"},1]`), p1Act(t, "admit", `[0]`), p1Act(t, "commitCall", `[0]`))
	a.bind(t, 0, "reply")
	a.run(t, p1Act(t, "claim", `[0,{"tuple":[0,1]}]`), p1Act(t, "authorize", `[0]`), p1Act(t, "beginEffect", `[0]`),
		p1Act(t, "commitEffect", `[0]`), p1Act(t, "loseRPC", `[0]`), p1Act(t, "expireLease", `[{"tuple":[0,1]}]`),
		p1Act(t, "claim", `[1,{"tuple":[0,1]}]`), p1Act(t, "authorize", `[1]`), p1Act(t, "requestDelete", `[1]`))
	for store := range 3 {
		subject := `[` + fmt.Sprint(store) + `,{"variant":"AgentSubject","value":1}]`
		a.run(t, p1Act(t, "fenceStore", subject), p1Act(t, "recordFence", subject))
	}
	a.run(t, p1Act(t, "commitDelete", `[1]`))
	// expect: s.requests.get(0).phase == Replied and s.effects.get((0,1)) == 1.
	assertRequestState(t, a.s, a.requests[0], "REPLIED")
	reply := a.rpc[1].attempt.Envelope.ID
	if n := localEffects(t, a.root, "a", reply); n != 1 {
		t.Fatal("reply effects in A's store:", n)
	}
	// beginEffect(1).fail().
	err := a.step(t, p1Act(t, "beginEffect", `[1]`))
	if !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("the fenced store accepted the late RPC:", err)
	}
	if n := localEffects(t, a.root, "a", reply); n != 1 {
		t.Fatal("reply effects in A's store after the late RPC:", n)
	}
}
