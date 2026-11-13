package controlplane

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// The wake budget (INT-04, A2A-009): the agents of an organization wake
// sleeping agents through requests at most so many times per rolling hour.
// Only a request between agents of an organization counts; a status (or a
// reply) always wakes its recipient, and an agent of a person has no budget.
func TestRequestsBetweenAgentsWakeWithinTheOrganizationsBudget(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	sender := activateTenantAgent(t, l, c, owner, "sender")
	b := activateTenantAgent(t, l, c, owner, "wake-b")
	d := activateTenantAgent(t, l, c, owner, "wake-d")
	if _, err := l.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id IN ($1,$2)", b, d); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('mandate-wake',$1,'evt-wake',10,10,clock_timestamp()+interval '1 hour')`, sender); err != nil {
		t.Fatal(err)
	}
	submit := func(key, to string) string {
		t.Helper()
		r, err := l.s.Submit(ctx, sender, key, Submission{RecipientAgentID: to, MandateID: "mandate-wake",
			PayloadRef: "payload-" + key, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil || r.State != Delivering {
			t.Fatal("submit", r, err)
		}
		return r.RequestID
	}
	toB, toD := submit("to-b", b), submit("to-d", d)

	// The default is 60 wakes an hour; the organization sets its own.
	var status QueueStatus
	status, err := l.a.QueueStatus(ctx, owner)
	if err != nil || status.Limits.MaxPeerWakesPerHour != 60 || status.PeerWakesLastHour != 0 {
		t.Fatal("default budget", status, err)
	}
	for _, bad := range []int{-1, 100001} {
		if _, err = l.a.SetQueueLimits(ctx, owner, "bad-budget", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 10, MaxPeerWakesPerHour: bad}); !errors.Is(err, ErrInput) {
			t.Fatal("accepted wake budget", bad, err)
		}
	}
	r, err := l.a.SetQueueLimits(ctx, owner, "one-wake", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 10, MaxPeerWakesPerHour: 1})
	var set QueueLimits
	if err != nil || json.Unmarshal(r.Body, &set) != nil || set.MaxPeerWakesPerHour != 1 {
		t.Fatal("set budget", err, string(r.Body))
	}

	// One wake: b's request wakes b; d's request then waits.
	first, err := l.s.ReservePeerWake(ctx, b)
	if err != nil || first == "" {
		t.Fatal("the first wake", first, err)
	}
	var recorded string
	if err = l.s.pool.QueryRow(ctx, "SELECT request_id FROM peer_wakes WHERE id=$1 AND agent_id=$2 AND tenant_id=$3", first, b, owner.TenantID).Scan(&recorded); err != nil || recorded != toB {
		t.Fatal("the wake is not recorded with its request", recorded, err)
	}
	if _, err = l.s.ReservePeerWake(ctx, d); !errors.Is(err, ErrWakeBudget) {
		t.Fatal("a second wake within the hour", err)
	}
	if status, err = l.a.QueueStatus(ctx, owner); err != nil || status.PeerWakesLastHour != 1 {
		t.Fatal("usage", status, err)
	}
	// A boot that failed gives its wake back.
	if err = l.s.ReleasePeerWake(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := l.s.ReservePeerWake(ctx, d)
	if err != nil || second == "" {
		t.Fatal("a wake given back is usable again", err)
	}
	if err = l.s.pool.QueryRow(ctx, "SELECT request_id FROM peer_wakes WHERE id=$1", second).Scan(&recorded); err != nil || recorded != toD {
		t.Fatal("d's wake is not recorded with d's request", recorded, err)
	}
	// An hour later the wake no longer counts.
	if _, err = l.s.pool.Exec(ctx, "UPDATE peer_wakes SET woken_at=clock_timestamp()-interval '61 minutes' WHERE id=$1", second); err != nil {
		t.Fatal(err)
	}
	if third, err := l.s.ReservePeerWake(ctx, b); err != nil || third == "" {
		t.Fatal("a wake after the window", err)
	}
	if n := count(t, l.s, "peer_wakes"); n != 1 {
		t.Fatal("wakes out of the window are kept", n)
	}

	// Still exhausted, yet a status to the sender wakes it: it completes work
	// already admitted. An agent with nothing pending is not counted either.
	if _, err = l.s.pool.Exec(ctx, "UPDATE agents SET inbound_mode='manual' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	held := holdRequest(t, l, sender, b, "held")
	if _, err = c.DecideHeldRequest(ctx, owner, b, held, "decline", false); err != nil {
		t.Fatal(err)
	}
	if wake, err := l.s.ReservePeerWake(ctx, sender); err != nil || wake != "" {
		t.Fatal("a status to the sender was counted", wake, err)
	}
	idle := activateTenantAgent(t, l, c, owner, "idle")
	if wake, err := l.s.ReservePeerWake(ctx, idle); err != nil || wake != "" {
		t.Fatal("an agent with nothing pending was counted", wake, err)
	}
}

// holdRequest sends a request that the recipient's manual policy holds.
func holdRequest(t *testing.T, l *tenantLab, from, to, key string) string {
	t.Helper()
	r, err := l.s.Submit(t.Context(), from, key, Submission{RecipientAgentID: to, MandateID: "mandate-wake",
		PayloadRef: "payload-" + key, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || r.State != PendingApproval {
		t.Fatal("held submit", r, err)
	}
	return r.RequestID
}

// Concurrent workers cannot both take the last wake.
func TestTheLastWakeIsTakenOnce(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	sender := activateTenantAgent(t, l, c, owner, "sender")
	recipients := []string{}
	for _, name := range []string{"r1", "r2", "r3", "r4"} {
		id := activateTenantAgent(t, l, c, owner, name)
		recipients = append(recipients, id)
	}
	if _, err := l.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=ANY($1)", recipients); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('mandate-wake',$1,'evt-wake',10,10,clock_timestamp()+interval '1 hour')`, sender); err != nil {
		t.Fatal(err)
	}
	for _, to := range recipients {
		if _, err := l.s.Submit(ctx, sender, "to-"+to, Submission{RecipientAgentID: to, MandateID: "mandate-wake",
			PayloadRef: "payload-" + to, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.a.SetQueueLimits(ctx, owner, "two-wakes", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 10, MaxPeerWakesPerHour: 2}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	woken, refused := 0, 0
	for _, to := range recipients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wake, err := l.s.ReservePeerWake(ctx, to)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && wake != "":
				woken++
			case errors.Is(err, ErrWakeBudget):
				refused++
			default:
				t.Error("unexpected", wake, err)
			}
		}()
	}
	wg.Wait()
	if woken != 2 || refused != 2 {
		t.Fatal("concurrent wakes", woken, refused)
	}
}

// An agent of a person has no organization, hence no wake budget.
func TestAnAgentOfAPersonHasNoWakeBudget(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	if _, err := s.Submit(t.Context(), "a", "to-b", submission()); err != nil {
		t.Fatal(err)
	}
	if wake, err := s.ReservePeerWake(t.Context(), "b"); err != nil || wake != "" {
		t.Fatal("a person's agent was counted", wake, err)
	}
}
