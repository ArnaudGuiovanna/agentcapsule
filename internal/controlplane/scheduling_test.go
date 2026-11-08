package controlplane

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func (il *invocationLab) schedule(t *testing.T, p Principal, key, text string, at time.Time, ttl int) (Invocation, error) {
	t.Helper()
	r, err := il.c.CreateInvocation(t.Context(), p, il.agent, key, InvocationInput{OwnerInstruction: privateInstruction(text), RunAt: &at, TTLSeconds: ttl})
	if err != nil {
		return Invocation{}, err
	}
	return decodeInvocation(t, r), nil
}

func (il *invocationLab) mailboxes(t *testing.T, op string) int {
	t.Helper()
	var n int
	if err := il.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScheduledInvocationIsNeverReleasedBeforeItsTimeAndExactlyOnce(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")
	start := time.Now().UTC()
	at := start.Add(time.Hour)

	v, err := il.schedule(t, aliceP, "s1", "later", at, 120)
	if err != nil || v.State != "scheduled" || v.RunAt == nil {
		t.Fatal("not scheduled", v, err)
	}
	// An immediate invocation sent afterwards is not blocked by the scheduled one.
	now, _, err := il.create(t, aliceP, "now", "now")
	if err != nil {
		t.Fatal(err)
	}
	if il.mailboxes(t, v.ID) != 0 {
		t.Fatal("a future instruction already occupies the delivery queue")
	}
	before := start.Add(59 * time.Minute)
	if n, err := il.s.ReleaseDueInstructions(t.Context(), &before, 10); err != nil || n != 0 || il.mailboxes(t, v.ID) != 0 {
		t.Fatal("released before its time", n, err)
	}
	got := mustGet(t, il, aliceP, v.ID)
	if got.State != "scheduled" || !got.ExpiresAt.IsZero() {
		t.Fatal(got)
	}
	// Many workers at the due time: one release, one mailbox, same identity.
	due := at.Add(time.Second)
	var wg sync.WaitGroup
	total := make(chan int, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := il.s.ReleaseDueInstructions(t.Context(), &due, 10)
			if err != nil {
				t.Error(err)
			}
			total <- n
		}()
	}
	wg.Wait()
	close(total)
	sum := 0
	for n := range total {
		sum += n
	}
	if sum != 1 || il.mailboxes(t, v.ID) != 1 {
		t.Fatal("not released exactly once", sum, il.mailboxes(t, v.ID))
	}
	released := mustGet(t, il, aliceP, v.ID)
	if released.ID != v.ID || released.State != "accepted" {
		t.Fatal("identity or state changed at release", released)
	}
	// The TTL counts from the due time, not from admission.
	if d := released.ExpiresAt.Sub(due); d < 119*time.Second || d > 121*time.Second {
		t.Fatal("ttl does not start at the due time", d)
	}
	// Repeating after a crash neither loses nor duplicates it.
	if n, err := il.s.ReleaseDueInstructions(t.Context(), &due, 10); err != nil || n != 0 || il.mailboxes(t, v.ID) != 1 {
		t.Fatal("second release duplicated the event", n, err)
	}
	// And it is delivered and answered like any other instruction.
	il.complete(t, now.ID)
	il.complete(t, v.ID)
	if st := mustGet(t, il, aliceP, v.ID).State; st != "completed" {
		t.Fatal("scheduled instruction did not complete", st)
	}
}

func TestScheduleBoundsCancellationAndQueueAccounting(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	bob, bobP := il.person(t, "bob")
	for _, m := range []Member{alice, bob} {
		assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: m.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "as-"+m.PrincipalID)
	}
	start := time.Now().UTC()
	for name, at := range map[string]time.Time{"past": start.Add(-time.Minute), "too-soon": start, "too-far": start.Add(31 * 24 * time.Hour)} {
		if _, err := il.schedule(t, aliceP, name, "x", at, 0); !errors.Is(err, ErrInput) {
			t.Fatal("out-of-range schedule accepted", name, err)
		}
	}
	// Scheduled work counts against the queue from admission.
	if err := il.setLimits(t, il.owner, "lim", 1, 1); err != nil {
		t.Fatal(err)
	}
	v, err := il.schedule(t, aliceP, "s", "secret later", start.Add(time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.schedule(t, aliceP, "s2", "one too many", start.Add(2*time.Hour), 0); !errors.Is(err, ErrQueueFull) {
		t.Fatal("scheduling bypassed the queue limit", err)
	}
	if _, _, err = il.create(t, aliceP, "i", "immediate"); !errors.Is(err, ErrQueueFull) {
		t.Fatal("scheduled work not counted", err)
	}
	// Same key replays; a different run_at under the same key is another request.
	if again, err := il.schedule(t, aliceP, "s", "secret later", start.Add(time.Hour), 0); err != nil || again.ID != v.ID {
		t.Fatal("schedule replay", err)
	}
	// Only the requester cancels; a colleague cannot even see it.
	if _, err = il.c.CancelInvocation(t.Context(), bobP, v.ID, "c0"); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member cancelled it", err)
	}
	if _, err = il.c.CancelInvocation(t.Context(), il.owner, v.ID, "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an administrator cancelled someone's invocation", err)
	}
	r, err := il.c.CancelInvocation(t.Context(), aliceP, v.ID, "c2")
	if err != nil || r.Status != 200 {
		t.Fatal("cancel", err)
	}
	if again, err := il.c.CancelInvocation(t.Context(), aliceP, v.ID, "c2"); err != nil || !again.Replayed {
		t.Fatal("cancel is not idempotent", err)
	}
	got := mustGet(t, il, aliceP, v.ID)
	if got.State != "canceled" || got.ResultAvailable {
		t.Fatal(got)
	}
	// Content is destroyed and it is never released; the slot is free again.
	var live int
	if err = il.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM transit_payloads t JOIN owner_instructions i ON i.input_payload_id=t.id
        WHERE i.operation_id=$1 AND t.purged_at IS NULL`, v.ID).Scan(&live); err != nil || live != 0 {
		t.Fatal("cancelled content was kept", live, err)
	}
	later := start.Add(3 * time.Hour)
	if n, err := il.s.ReleaseDueInstructions(t.Context(), &later, 10); err != nil || n != 0 || il.mailboxes(t, v.ID) != 0 {
		t.Fatal("a cancelled instruction was released", n, err)
	}
	if _, _, err = il.create(t, aliceP, "i2", "immediate"); err != nil {
		t.Fatal("cancelled slot was not returned", err)
	}
	// Once released it is ordinary queued work: cancelling is refused.
	if err = il.setLimits(t, il.owner, "lim2", 10, 10); err != nil {
		t.Fatal(err)
	}
	w, err := il.schedule(t, aliceP, "w", "soon", start.Add(time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.ReleaseDueInstructions(t.Context(), &later, 10); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.CancelInvocation(t.Context(), aliceP, w.ID, "c3"); !errors.Is(err, ErrTransition) {
		t.Fatal("a released instruction was cancelled", err)
	}
}

func TestDeletingAnAgentClosesItsScheduledInstructions(t *testing.T) {
	il := newInvocationLab(t)
	alice, aliceP := il.person(t, "alice")
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: alice.PrincipalID, Permissions: []string{"read_metadata", "invoke"}}, "a")
	at := time.Now().UTC().Add(time.Hour)
	v, err := il.schedule(t, aliceP, "s", "doomed", at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.Delete(t.Context(), il.owner, il.agent, "del"); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, il, aliceP, v.ID)
	if got.State != "canceled" || got.ErrorCode != "agent_unavailable" {
		t.Fatal("scheduled instruction survived the deletion request", got)
	}
	later := at.Add(time.Hour)
	if n, err := il.s.ReleaseDueInstructions(t.Context(), &later, 10); err != nil || n != 0 || il.mailboxes(t, v.ID) != 0 {
		t.Fatal("released into a deleted agent", n, err)
	}
}
