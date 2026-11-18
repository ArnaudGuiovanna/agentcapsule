package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// Go projections of the P3 runs added with ADR 007 (service_progress_test.qnt,
// scenarios 20 to 22x1). The P3 fixture pins the model before ADR 007, so no
// ITF case replays them: each test drives the P3 replay through the run's
// steps and checks its expectation. The binding is the replay's: request 0
// goes from a to b, its notice back to a (P3's store 0).
//
// expireNotification(i) is the notice's deadline passing, then the
// production dispatcher (Transit.DispatchMailbox) on it, which retires a
// delivery past its deadline: at once when no attempt was allowed to reach
// its store, behind the store's fence otherwise.

// p3Dispatcher is the worker's runtime for the dispatcher: it sends to and
// fences in the replay's local stores, and prepares a delivery as the worker
// does, by checking its destination's health before any attempt is spent.
type p3Dispatcher struct{ a *p3Replay }

func (d p3Dispatcher) Fence(ctx context.Context, target, subject string) error {
	return p3Fences{d.a}.Fence(ctx, target, subject)
}

func (d p3Dispatcher) Send(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	return d.a.local.boots[p1AgentNumber(target)].client.Send(ctx, event)
}

func (p3Dispatcher) Invoke(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, errors.New("P3 has no owner instructions")
}

func (d p3Dispatcher) WithPreparedDelivery(ctx context.Context, target string, fn func(context.Context) error) error {
	if err := d.a.local.boots[p1AgentNumber(target)].client.Health(ctx); err != nil {
		return err
	}
	return fn(ctx)
}

func (a *p3Replay) run(t *testing.T, steps ...string) {
	t.Helper()
	for _, s := range steps {
		op := p3Act(t, s)
		if err := a.step(t, op); err != nil {
			t.Fatalf("%s %v: %v", op.Name, op.Args, err)
		}
	}
}

// p3Act parses a P3 step as the run spells it, such as "notify(0,false)".
func p3Act(t *testing.T, step string) protocolAction {
	t.Helper()
	name, args, _ := strings.Cut(step, "(")
	return p1Act(t, name, "["+strings.TrimSuffix(args, ")")+"]")
}

// dispatch runs the production dispatcher once on request i's notice.
func (a *p3Replay) dispatch(t *testing.T, i int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return a.transit.DispatchMailbox(ctx, a.bound[i].notice, time.Hour, p3Dispatcher{a})
}

// expireNotification ages request i's notice past its deadline and runs the
// dispatcher on it. Its error is the retirement's, if it could not end.
func (a *p3Replay) expireNotification(t *testing.T, i int) error {
	t.Helper()
	pastDeadline(t, a.s, a.bound[i].notice)
	return a.dispatch(t, i)
}

type p3NoticeState struct {
	State            string
	Attempts         int
	Closing, Reached bool
	Queued           bool // in the outbox
}

func (a *p3Replay) noticeState(t *testing.T, i int) p3NoticeState {
	t.Helper()
	var n p3NoticeState
	if err := a.s.pool.QueryRow(t.Context(), `SELECT delivery_state,attempts,closing,may_have_reached,
        EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id) FROM agent_mailboxes m WHERE id=$1`, a.bound[i].notice).
		Scan(&n.State, &n.Attempts, &n.Closing, &n.Reached, &n.Queued); err != nil {
		t.Fatal(err)
	}
	return n
}

// scenario20Test (expired-unattempted-notification-dies-without-store) and
// refusal20x0Test: request 0's reply waits for a, whose store is lost. No
// attempt is spent on it (notify fails), and past its deadline it dies at
// once, without the store. a's owner still reads the reply.
func TestProgressExpiredNotificationDiesWithoutItsStore(t *testing.T) {
	a := newP3Replay(t, "expired-notification")
	a.run(t, "arrive(0,true)", "admit(0)", "complete(0)", "loseStore(0)")
	// refusal20x0Test: notify(0,false).fail().
	if err := a.dispatch(t, 0); err == nil {
		t.Fatal("notify: a delivery to a lost store was attempted")
	}
	if n := a.noticeState(t, 0); n != (p3NoticeState{State: "PENDING", Queued: true}) {
		t.Fatal("the refused attempt changed the notice:", n)
	}
	// scenario20Test.
	if err := a.expireNotification(t, 0); err != nil {
		t.Fatal("expireNotification:", err)
	}
	a.run(t, "observe(0)")
	if n := a.noticeState(t, 0); n != (p3NoticeState{State: "DEAD"}) {
		t.Fatal("expect delivery == Dead, attempts == 0, notificationQueue == List():", n)
	}
	if !a.bound[0].observed {
		t.Fatal("a's owner did not observe request 0")
	}
}

// scenario21Test (expired-attempted-notification-waits-for-its-fence),
// refusal21x0Test and scenario21x1Test: an attempt of request 0's reply may
// have reached a; then a's store is lost and the reply's deadline passes.
// The reply is retiring and cannot die without a's fence; once the store is
// back, it is fenced and dies.
func TestProgressExpiredSentNotificationWaitsForItsFence(t *testing.T) {
	a := newP3Replay(t, "expired-notification")
	a.run(t, "arrive(0,true)", "admit(0)", "complete(0)", "notify(0,false)", "loseStore(0)")
	if err := a.expireNotification(t, 0); err == nil {
		t.Fatal("expireNotification: the reply died without a's fence")
	}
	// expect: delivery == RetiringDead and barriersPending.
	if n := a.noticeState(t, 0); n != (p3NoticeState{State: "PENDING", Attempts: 1, Closing: true, Reached: true, Queued: true}) {
		t.Fatal("the expired, attempted reply is not retiring:", n)
	}
	// refusal21x0Test: retireNotification(0).fail().
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	err := a.s.RetireDelivery(ctx, a.bound[0].notice, p3Fences{a})
	cancel()
	if err == nil || a.noticeState(t, 0).State != "PENDING" {
		t.Fatal("retireNotification: retired with its store lost:", err)
	}
	// scenario21x1Test: recoverStore(0), retireNotification(0); the delayed
	// copy is refused.
	a.run(t, "recoverStore(0)", "retireNotification(0)")
	if n := a.noticeState(t, 0); n.State != "DEAD" || n.Queued {
		t.Fatal("expect delivery == Dead and notificationQueue == List():", n)
	}
}

// refusal22x0Test and scenario22x1Test
// (expired-notification-to-a-deleted-store-is-cancelled): a's deletion is
// requested while request 0's reply waits for it. Past its deadline, the
// reply does not die: the deletion cancels it. Go cancels it at the
// deletion's tombstone: cancelNotification and retireNotification are the
// deletion's fences and its commit.
func TestProgressExpiredNotificationToADeletedStoreIsCanceled(t *testing.T) {
	a := newP3Replay(t, "expired-notification")
	a.run(t, "arrive(0,true)", "admit(0)", "complete(0)", "requestDelete()")
	// refusal22x0Test: expireNotification(0).fail().
	if err := a.expireNotification(t, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expireNotification: a reply to an agent being deleted:", err)
	}
	if n := a.noticeState(t, 0); n.State != "PENDING" || n.Attempts != 0 {
		t.Fatal("the reply to an agent being deleted died or was attempted:", n)
	}
	// scenario22x1Test.
	a.run(t, "finishDelete()")
	if n := a.noticeState(t, 0); n.State != "CANCELED" || n.Queued {
		t.Fatal("expect delivery == Cancelled:", n)
	}
	assertRequestState(t, a.s, a.bound[0].id, "REPLIED")
}
