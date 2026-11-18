package controlplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// The capacity adapter of the P3 replay. P3 has one execution VM, one
// admission queue for every request, and barriers (a request closing, a
// notification being retired) that go ahead of new work. On a Go host these
// are:
//
//   - the host's work queue (worker_jobs): DiscoverWork numbers the work of
//     every agent of the host in arrival order, deliveries and barriers alike
//     (a closure, the retirement of a notification), and ClaimWork gives the
//     worker the oldest. It is P3's global admission order: admit(i) is the
//     worker claiming request i's delivery job, which it gets only when no
//     older work waits;
//   - each agent's mailbox, FIFO over the requests it receives and the
//     notices it is sent;
//   - the store's writer: a fence waits for the effect transaction open in
//     the store, as on the host a barrier (WithBarrier) waits for the
//     callback's admission turn (TestBarrierAdmissionFIFOAndOrdinaryBackpressure).
//
// The replay is the only worker. A claimed delivery job ends with its
// request's completion. Notifications are dispatched outside the queue, as
// in the other cases; their jobs stay queued.

// p3Queued are the cases replayed through the host's work queue.
var p3Queued = map[string]bool{
	"retiring-notice-reserves-capacity": true,
	"barrier-reserves-capacity":         true,
	"fence-waits-for-current-execution": true,
	"fifo-admission-cannot-overtake":    true,
}

// p3Host is the host of agents a and b's placements (confirmedCaller).
const p3Host = "host"

type p3WorkQueue struct {
	jobs map[int]WorkerJob // the delivery job of each admitted request
}

// p3OtherWork is the worker's answer to admit(i) when the host's work queue
// gives it older work first.
type p3OtherWork struct{ Job WorkerJob }

func (e *p3OtherWork) Error() string {
	return fmt.Sprintf("the host's work queue gives %s %s first", e.Job.Kind, e.Job.ID)
}

// errNoticeOutstanding: P3 recycles a request's slot only once it is
// observed and its notice acknowledged.
var errNoticeOutstanding = errors.New("the request's notice is still outstanding")

func (a *p3Replay) discover(t *testing.T) {
	t.Helper()
	if a.work == nil {
		return
	}
	if err := a.s.DiscoverWork(t.Context(), p3Host, 64); err != nil {
		t.Fatal(err)
	}
}

// claimWork is the worker's claim before admit(i): it must be request i's
// delivery job.
func (a *p3Replay) claimWork(t *testing.T, i int) error {
	t.Helper()
	if a.work == nil {
		return nil
	}
	job, err := a.s.ClaimWork(t.Context(), p3Host, time.Hour)
	if err != nil {
		return err
	}
	if job.Kind != "delivery" || job.ID != a.bound[i].incoming {
		return &p3OtherWork{job}
	}
	a.work.jobs[i] = job
	return nil
}

// completeWork ends request i's delivery job with its completion.
func (a *p3Replay) completeWork(t *testing.T, i int) error {
	t.Helper()
	if a.work == nil {
		return nil
	}
	job, ok := a.work.jobs[i]
	if !ok {
		return nil
	}
	delete(a.work.jobs, i)
	return a.s.CompleteWork(t.Context(), job)
}

// workSlot names the model request a worker job belongs to, and whether it
// is the request's delivery, its notice's, or its closure.
func (a *p3Replay) workSlot(job WorkerJob) (int, string) {
	for i, b := range a.bound {
		switch {
		case b.id == "":
		case job.Kind == "delivery" && job.ID == b.incoming:
			return i, "request"
		case job.Kind == "delivery" && job.ID == b.notice:
			return i, "notice"
		case job.Kind == "closure" && job.ID == b.id:
			return i, "closure"
		}
	}
	return -1, ""
}

func p3Stage(w p3Observation, slot int) string {
	for _, r := range w.Requests {
		if r.Slot == slot {
			return r.Stage
		}
	}
	return ""
}

// openRequestAhead reports whether head is the delivery of a request still
// open in the model (accepted, executing or closing).
func (a *p3Replay) openRequestAhead(w p3Observation, head string) bool {
	for i, b := range a.bound {
		if b.id != "" && b.incoming == head {
			return slices.Contains([]string{"Accepted", "Executing", "Closing"}, p3Stage(w, i))
		}
	}
	return false
}

// refusedAdmission: P3 refuses admit(i) while a barrier is pending or while
// an older request heads the admission queue. The worker gets that older work
// from the host's work queue instead of request i's delivery.
func (a *p3Replay) refusedAdmission(t *testing.T, op protocolAction, err error) {
	t.Helper()
	var other *p3OtherWork
	if !errors.As(err, &other) {
		t.Fatal("admission was not refused by the host's work queue:", err)
	}
	i := p1Int(op.Args[0])
	j, kind := a.workSlot(other.Job)
	if j < 0 || j == i {
		t.Fatal("the host's work queue gave work that is not older:", other.Job)
	}
	w := a.model
	switch {
	case kind == "notice":
		// A notification to retire, a barrier: its dispatch is the retirement.
		if n := p3Notice(w, j); n != "RetiringDead" && n != "RetiringCancelled" {
			t.Fatal("older notice work is not a retirement:", n)
		}
		due, err := a.s.retirementDue(t.Context(), other.Job.ID)
		if err != nil || !due {
			t.Fatal("the notice's dispatch is not its retirement:", due, err)
		}
		// When the notice goes to request i's recipient, that agent's mailbox
		// keeps request i behind it too.
		if p3Sender(j) == 1-p3Sender(i) {
			if _, err := a.s.ClaimDelivery(t.Context(), a.bound[i].incoming, time.Hour); !errors.Is(err, ErrNotHead) {
				t.Fatal("request i overtook the retiring notice in its recipient's mailbox:", err)
			}
		}
	case p3Stage(w, j) == "Closing":
		// The closing request's work, a barrier: its delivery job retires
		// into its closure, which fences.
		var closing bool
		if err := a.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1 AND phase='FENCING')", a.bound[j].id).Scan(&closing); err != nil || !closing {
			t.Fatal("the older work is not a closure that fences:", closing, err)
		}
	default:
		// An older request ahead in the admission queue.
		q := w.Queues.Admission
		if kind != "request" || slices.Index(q, j) < 0 || slices.Index(q, j) > slices.Index(q, i) {
			t.Fatal("the host's work queue gave work out of the admission order:", other.Job, q)
		}
	}
	t.Logf("admit(%d) refused: the worker gets %s of request %d first", i, kind, j)
}

func p3Notice(w p3Observation, slot int) string {
	for _, r := range w.Requests {
		if r.Slot == slot {
			return r.Notification
		}
	}
	return ""
}

// refusedFence: P3's fence waits while a request executes. The store's
// writer holds the effect transaction of the request being executed; the
// fence waits for it to end, and leaves no fence meanwhile.
func (a *p3Replay) refusedFence(t *testing.T, op protocolAction) {
	t.Helper()
	i, store := p1Int(op.Args[0]), p1Int(op.Args[1])
	r := a.local.rpc[0]
	if r == nil || !r.executing || p1AgentNumber(r.attempt.Destination) != store {
		t.Fatal("no execution holds the store's writer")
	}
	subject := "request/" + a.bound[i].id
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := a.local.boots[store].client.Fence(ctx, subject); err == nil || ctx.Err() == nil {
		t.Fatal("the fence did not wait for the current execution:", err)
	}
	if n := a.sqliteCount(t, store, "capsule_fences", "subject", subject); n != 0 {
		t.Fatal("a fence went in under the open writer:", n)
	}
}

// refusedRecycle: Go has no recycle. A request keeps its identity; a new
// arrival takes a fresh UUID (two-repeatable-arrivals). What Go releases of
// a request is its content, by the purge (ADR 007 §7), and the purge keeps
// what an outstanding notice carries. Seven days pass here: the delivered
// request's content goes, the reply its pending notice carries stays.
func (a *p3Replay) refusedRecycle(t *testing.T, op protocolAction, err error) {
	t.Helper()
	if !errors.Is(err, errNoticeOutstanding) {
		t.Fatal("recycle was not refused for its outstanding notice:", err)
	}
	i := p1Int(op.Args[0])
	b := a.bound[i]
	if _, err := a.s.pool.Exec(t.Context(), "UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second' WHERE purge_after IS NOT NULL AND purged_at IS NULL"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.transit.PurgeExpired(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	var requestPurged, replyHeld bool
	if err := a.s.pool.QueryRow(t.Context(), `SELECT q.purged_at IS NOT NULL,p.purged_at IS NULL AND p.purge_after IS NULL AND p.ciphertext IS NOT NULL
        FROM agent_requests r JOIN transit_payloads q ON q.id=r.payload_ref JOIN transit_payloads p ON p.id=r.reply_ref WHERE r.id=$1`, b.id).Scan(&requestPurged, &replyHeld); err != nil {
		t.Fatal(err)
	}
	if !requestPurged || !replyHeld {
		t.Fatal("the purge released the pending notice's reply, or nothing:", requestPurged, replyHeld)
	}
	v, err := a.catalog.Request(t.Context(), a.principals[p3Sender(i)], b.id)
	if err != nil || v.Reply == nil || len(v.Reply.Content) != 1 || v.Reply.Content[0].Text != "progress result" {
		t.Fatal("the request's owner lost its result:", v, err)
	}
}
