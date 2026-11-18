//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// stuckBound bounds how long an invocation the harness never answers may
// take to end. Its three attempts and the leases between them take about
// 90 seconds with the labs' 30-second delivery lease (the first attempt
// ends at the host's 20-second timeout, the next two when the guest's busy
// store refuses them after 5 seconds); the fence, the stop, the restricted
// boot and its fence take less than a minute.
const stuckBound = 4 * time.Minute

// A harness that never returns from an invocation holds its store (ADR 012,
// question 7, option (b)). capsule-echo's never-returns behaviour holds any
// invocation whose text says "never return", and answers others. The agent
// answers an ordinary invocation; then it gets one it holds, and one more
// behind it. The held invocation's three attempts end at the host's
// timeout or its busy store, and the next waits behind it. The fence that
// would end the held one is refused by its store: the worker stops the VM,
// records a guest failure of kind unresponsive for that boot, and fences
// through a restricted boot. The held invocation fails with
// delivery_outcome_unknown within stuckBound, and the next is answered by
// a new boot of the same release. The agent is READY, within its budget.
func TestProductWorkerStopsAGuestThatNeverAnswersAnInvocation(t *testing.T) {
	l := newRegistryLab(t)
	l.publishBehaviour("1.0.0", "opt/stuck", "never-returns")
	agent := l.create("stuck", "1.0.0").AgentID
	run := l.runs(1)[agent]
	l.answers(agent, "ordinary", "an ordinary question")
	start := time.Now()
	held := l.invoke(agent, "held", "please never return")
	next := l.invoke(agent, "next", "answered after the stop")
	read := func(id string) controlplane.Invocation {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
		return v
	}
	var v controlplane.Invocation
	failed := l.awaitPasses("the invocation the harness never answers", stuckBound, onlyStuckHarness, func() bool {
		v = read(held)
		switch v.State {
		case "accepted", "working":
			if n := read(next); n.State != "accepted" {
				t.Fatal("the next invocation did not wait behind the held one", n.State, n.ErrorCode)
			}
			return false
		case "failed":
			return true
		}
		t.Fatal("the held invocation", v.State, v.ErrorCode)
		return false
	})
	took := time.Since(start)
	t.Log("the held invocation failed after", took, "; passes that failed on its attempts:", failed)
	if v.ErrorCode != "delivery_outcome_unknown" || v.ResultAvailable || v.CloseReason != "attempts_exhausted" {
		t.Fatal("the held invocation", v.ErrorCode, v.ResultAvailable, v.CloseReason)
	}
	if failed == 0 {
		t.Fatal("no attempt failed")
	}
	if got, want := l.guestFailures(agent), []string{fmt.Sprintf("%s/%d", controlplane.GuestUnresponsive, run.Generation)}; !slices.Equal(got, want) {
		t.Fatal("guest failures recorded", got, want)
	}
	if sameProcess(run.PID, run.StartTicks) {
		t.Fatal("the VM whose guest held its store still runs")
	}
	l.awaitPasses("the next invocation", 2*time.Minute, onlyStuckHarness, func() bool { return l.answered(next, "answered after the stop") })
	// One restricted boot fenced the store, then one boot for work answered
	// the next invocation.
	if g := l.placementGeneration(agent); g != run.Generation+2 {
		t.Fatal("boots after the stop", g, run.Generation)
	}
	if state := l.agentState(agent); state != "READY" {
		t.Fatal("the agent within its budget", state)
	}
	l.answers(agent, "again", "another ordinary question")
}
