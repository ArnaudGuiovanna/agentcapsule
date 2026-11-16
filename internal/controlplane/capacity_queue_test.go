package controlplane

import (
	"errors"
	"testing"
	"time"
)

// Work waiting for a VM slot (EVT-007, RUN-011, ADR 017). The worker decides
// under its host's exclusive admission turn; these tests play the worker with
// the host's census: the agents whose VMs run, and how many slots are free.

// wake opens a wake command for agent: work that needs a VM slot.
func (il *invocationLab) wake(t *testing.T, agent, key string) {
	t.Helper()
	if _, err := il.c.RequestLifecycle(t.Context(), il.owner, agent, key, "wake"); err != nil {
		t.Fatal(err)
	}
}

// foreignAgent creates an agent of a second organization on the same host,
// with an open wake: the other organization's work.
func (il *invocationLab) foreignAgent(t *testing.T, id string) {
	t.Helper()
	org := createTestOrganization(t, il.a, il.platform, "org-"+id)
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO agents(id,tenant_id,discoverable,inbound_mode) VALUES($1,$2,false,'manual')`, id, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
        VALUES($1,'someone',$2,'local',1,'wake')`, newID("op"), id); err != nil {
		t.Fatal(err)
	}
}

func (il *invocationLab) admit(t *testing.T, agent string, running []string, free int) SlotDecision {
	t.Helper()
	d, err := il.s.AdmitToSlot(t.Context(), "local", agent, running, free)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (il *invocationLab) taken(t *testing.T, agent string) {
	t.Helper()
	if err := il.s.SlotTaken(t.Context(), "local", agent); err != nil {
		t.Fatal(err)
	}
}

func (il *invocationLab) waiters(t *testing.T) []string {
	t.Helper()
	rows, err := il.s.pool.Query(t.Context(), "SELECT agent_id FROM capacity_waits WHERE host_id='local' ORDER BY ticket")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func (il *invocationLab) agentState(t *testing.T, agent string) string {
	t.Helper()
	v, err := il.c.GetTenantAgent(t.Context(), il.owner, agent)
	if err != nil {
		t.Fatal(err)
	}
	return v.State
}

// busy gives the lab agent an invocation it acknowledged "working": work in
// progress, which no other work may evict.
func (il *invocationLab) busy(t *testing.T) string {
	t.Helper()
	alice := il.invoker(t, "busy-requester")
	v, _, err := il.create(t, alice, "busy", "long work")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, v.ID)
	return v.ID
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A full host queues work in arrival order, whatever its organization: a
// flood from one organization never overtakes another's older waiter. When a
// slot frees, the oldest waiter takes it and the next one's jobs are tried at
// once. The agent shows QUEUED meanwhile (RUN-011).
func TestAFullHostAdmitsWaitingWorkInArrivalOrder(t *testing.T) {
	il := newInvocationLab(t)
	il.busy(t)
	x1 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "x1")
	x2 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "x2")
	il.foreignAgent(t, "y1")
	il.wake(t, x1, "wake-x1")
	il.wake(t, x2, "wake-x2")
	full := []string{il.agent}

	// The host is full and its only VM is busy: nothing is evicted, the
	// other organization's agent waits first, then this organization's two.
	for _, a := range []string{"y1", x1, x2} {
		if d := il.admit(t, a, full, 0); d.Admit || d.Evict != "" {
			t.Fatal("a full host admitted work or evicted a busy VM", a, d)
		}
	}
	if got := il.waiters(t); !sameOrder(got, []string{"y1", x1, x2}) {
		t.Fatal("waiters not in arrival order", got)
	}
	// Asking again keeps the first place.
	il.admit(t, x1, full, 0)
	if got := il.waiters(t); !sameOrder(got, []string{"y1", x1, x2}) {
		t.Fatal("a retry changed the order", got)
	}
	if st := il.agentState(t, x1); st != "QUEUED" {
		t.Fatal("a waiting agent is not QUEUED", st)
	}

	// One slot frees. The newer waiters may not take it before the oldest.
	if err := il.s.DiscoverWork(t.Context(), "local", 64); err != nil {
		t.Fatal(err)
	}
	if _, err := il.s.pool.Exec(t.Context(), "UPDATE worker_jobs SET available_at=clock_timestamp()+interval '1 hour' WHERE kind='lifecycle'"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{x2, x1} {
		if d := il.admit(t, a, nil, 1); d.Admit {
			t.Fatal("work overtook an older waiter", a)
		}
	}
	if d := il.admit(t, "y1", nil, 1); !d.Admit || d.Evict != "" {
		t.Fatal("the oldest waiter did not get the free slot", d)
	}
	il.taken(t, "y1")
	if got := il.waiters(t); !sameOrder(got, []string{x1, x2}) {
		t.Fatal("the admitted agent still waits", got)
	}
	// The next waiter's job is tried at once; the one after it keeps its delay.
	var x1Now, x2Now bool
	if err := il.s.pool.QueryRow(t.Context(), `SELECT
        bool_or(available_at<=clock_timestamp()) FILTER (WHERE agent_id=$1),
        bool_or(available_at<=clock_timestamp()) FILTER (WHERE agent_id=$2) FROM worker_jobs WHERE kind='lifecycle'`, x1, x2).Scan(&x1Now, &x2Now); err != nil {
		t.Fatal(err)
	}
	if !x1Now || x2Now {
		t.Fatal("the next waiter was not promoted, or the wrong one", x1Now, x2Now)
	}
	// Two slots free: both remaining waiters fit, in order.
	if d := il.admit(t, x2, nil, 2); !d.Admit {
		t.Fatal("a waiter was held although capacity suffices for every older one", d)
	}
	if d := il.admit(t, x1, nil, 2); !d.Admit {
		t.Fatal("the oldest waiter was refused", d)
	}
	il.taken(t, x1)
	il.taken(t, x2)
	if got := il.waiters(t); len(got) != 0 {
		t.Fatal("waiters left", got)
	}
	if st := il.agentState(t, x1); st == "QUEUED" {
		t.Fatal("an admitted agent stays QUEUED")
	}
}

// computing gives agent a model call in flight: its VM is computing.
func (il *invocationLab) computing(t *testing.T, agent string) {
	t.Helper()
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO llm_usage(id,tenant_id,agent_id,alias,request_key,reserved_tokens)
        SELECT $1,tenant_id,id,'model',$1,10 FROM agents WHERE id=$2`, newID("llm"), agent); err != nil {
		t.Fatal(err)
	}
}

// Work stops a VM that is not computing: an idle one first, then one that only
// waits, the least recently active first. It never stops a computing VM; with
// only those running, it waits.
func TestWorkStopsOnlyVMsThatAreNotComputing(t *testing.T) {
	il := newInvocationLab(t)
	il.busy(t)
	i1 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "i1")
	i2 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "i2")
	w := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "w")
	c := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "c")
	il.computing(t, c)
	il.wake(t, w, "wake-w")

	if d := il.admit(t, w, []string{il.agent, c, i2, i1}, 0); !d.Admit || d.Evict != i1 {
		t.Fatal("not the least recently active idle VM", d)
	}
	// i1 was just active: i2 is now the least recently active.
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind,status,completed_at)
        VALUES($1,'someone',$2,'local',99,'wake','SUCCEEDED',clock_timestamp())`, newID("op"), i1); err != nil {
		t.Fatal(err)
	}
	if d := il.admit(t, w, []string{il.agent, c, i1, i2}, 0); !d.Admit || d.Evict != i2 {
		t.Fatal("eviction ignored recent activity", d)
	}
	// An agent that owes work but only waits (here, an open wake) goes after
	// every idle one.
	il.wake(t, i2, "wake-i2")
	if d := il.admit(t, w, []string{il.agent, c, i2, i1}, 0); !d.Admit || d.Evict != i1 {
		t.Fatal("a waiting VM stopped before an idle one", d)
	}
	if d := il.admit(t, w, []string{il.agent, c, i2}, 0); !d.Admit || d.Evict != i2 {
		t.Fatal("a VM that only waits was not stopped", d)
	}
	// Only computing VMs run: the work waits.
	if d := il.admit(t, w, []string{il.agent, c}, 0); d.Admit {
		t.Fatal("work stopped a computing VM", d)
	}
	if got := il.waiters(t); !sameOrder(got, []string{w}) {
		t.Fatal("the refused agent does not wait", got)
	}
	// A barrier may stop any VM, computing ones last.
	order, err := il.s.EvictionOrder(t.Context(), "local", []string{il.agent, c, i1, i2})
	if err != nil || len(order) != 4 || order[0] != i1 || order[1] != i2 {
		t.Fatal("barrier eviction order", order, err)
	}
}

// An agent that waits for another agent's answer holds no slot against it,
// even with an invocation in progress: otherwise, on a full host, the answer
// could never be computed until a deadline.
func TestAnAgentWaitingForAnotherDoesNotHoldItsSlotAgainstIt(t *testing.T) {
	il := newInvocationLab(t)
	op := il.busy(t)
	b := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "b")
	il.wake(t, b, "wake-b")
	if d := il.admit(t, b, []string{il.agent}, 0); d.Admit {
		t.Fatal("a computing VM was stopped", d)
	}
	var mandate string
	if err := il.s.pool.QueryRow(t.Context(), "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", op).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO agent_requests(id,sender_agent_id,recipient_agent_id,mandate_id,state,via_auto,payload_ref,expires_at)
        VALUES($1,$2,$3,$4,'DELIVERING',true,'opaque',clock_timestamp()+interval '1 hour')`, newID("req"), il.agent, b, mandate); err != nil {
		t.Fatal(err)
	}
	if d := il.admit(t, b, []string{il.agent}, 0); !d.Admit || d.Evict != il.agent {
		t.Fatal("an agent waiting for another kept its slot against it", d)
	}
}

// Nothing runs after its TTL: an instruction that waited for capacity until
// its deadline dies without its agent, with an error that says so, and its
// agent leaves the queue when nothing else of it is due.
func TestWorkWaitingPastItsTTLNeverRunsAndLeavesTheQueue(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	first, _, err := il.create(t, alice, "first", "one")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := il.create(t, alice, "second", "two")
	if err != nil {
		t.Fatal(err)
	}
	other := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "other")
	il.wake(t, other, "wake-other")
	busy := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "busy")
	il.computing(t, busy)
	for _, a := range []string{il.agent, other} {
		if d := il.admit(t, a, []string{busy}, 0); d.Admit {
			t.Fatal("full host admitted", a)
		}
	}
	// Both instructions expire while the agent waits. The worker's pass first
	// offers freed slots, then retires them: the agent still waits meanwhile.
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE instruction_id IN ($1,$2)", first.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if err = il.s.PromoteCapacityHead(t.Context(), "local"); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{first.ID, second.ID} {
		var mbx string
		if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mbx); err != nil {
			t.Fatal(err)
		}
		if _, err = il.tr.ClaimInstruction(t.Context(), mbx, time.Minute); !errors.Is(err, ErrExpired) && !errors.Is(err, ErrNotHead) {
			t.Fatal("an expired instruction was claimed", err)
		}
		if err = il.tr.DispatchMailbox(t.Context(), mbx, time.Minute, instructionRuntimeLab(t, il.agent)); err != nil {
			t.Fatal(err)
		}
		v := mustGet(t, il, alice, op)
		if v.State != "expired" || v.CloseReason != "expired" || v.ErrorCode != "capacity_unavailable" {
			t.Fatal("expiry while waiting for capacity is not clear", v)
		}
	}
	// Nothing of the agent is due any more: the next decision drops it, and
	// the other waiter heads the queue.
	if d := il.admit(t, other, nil, 1); !d.Admit {
		t.Fatal("an expired waiter still holds the queue", d)
	}
	if got := il.waiters(t); !sameOrder(got, []string{other}) {
		t.Fatal("the expired waiter was not removed", got)
	}
	if st := il.agentState(t, il.agent); st == "QUEUED" {
		t.Fatal("an agent with nothing due shows QUEUED")
	}
	// An instruction that expires without waiting for capacity keeps the
	// general error.
	late, _, err := il.create(t, alice, "late", "three")
	if err != nil {
		t.Fatal(err)
	}
	var mbx string
	if err = il.s.pool.QueryRow(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE instruction_id=$1 RETURNING id", late.ID).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	if err = il.tr.DispatchMailbox(t.Context(), mbx, time.Minute, instructionRuntimeLab(t, il.agent)); err != nil {
		t.Fatal(err)
	}
	if v := mustGet(t, il, alice, late.ID); v.ErrorCode != "delivery_failed" {
		t.Fatal("an ordinary expiry blames capacity", v)
	}
}

// An agent whose VM stopped while it held work in progress is booted again
// (the resume job), unless that work ended, someone put it to sleep since,
// or it is FAILED.
func TestInterruptedWorkIsResumed(t *testing.T) {
	il := newInvocationLab(t)
	_ = il.s.RegisterPlacement(t.Context(), il.agent, "local")
	resumes := func() int {
		t.Helper()
		if _, err := il.s.pool.Exec(t.Context(), "DELETE FROM worker_jobs WHERE kind='resume'"); err != nil {
			t.Fatal(err)
		}
		if err := il.s.DiscoverWork(t.Context(), "local", 64); err != nil {
			t.Fatal(err)
		}
		return il.count(t, "SELECT count(*) FROM worker_jobs WHERE kind='resume' AND object_id=$1", il.agent)
	}
	due := func() bool {
		t.Helper()
		ok, err := il.s.ResumeDue(t.Context(), il.agent)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if resumes() != 0 || due() {
		t.Fatal("an agent without work in progress is resumed")
	}
	op := il.busy(t)
	if resumes() != 1 || !due() {
		t.Fatal("an agent stopped with work in progress is not resumed")
	}
	// A resume waits for capacity like any other work.
	other := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "other")
	if d := il.admit(t, il.agent, []string{other}, 0); !d.Admit || d.Evict != other {
		t.Fatal("a resume did not take an idle VM's slot", d)
	}
	// Running: nothing to resume.
	il.run(t)
	if resumes() != 0 || due() {
		t.Fatal("a running agent is resumed")
	}
	if _, err := il.s.pool.Exec(t.Context(), `UPDATE agent_placements SET state='STOPPED',vm_id='',worker_id='',lease_until=NULL WHERE agent_id=$1`, il.agent); err != nil {
		t.Fatal(err)
	}
	// FAILED: it waits for a wake.
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO failed_agents(agent_id,reason,failures) VALUES($1,'crashed',5)`, il.agent); err != nil {
		t.Fatal(err)
	}
	if resumes() != 0 || due() {
		t.Fatal("a FAILED agent is resumed")
	}
	if _, err := il.s.pool.Exec(t.Context(), "DELETE FROM failed_agents WHERE agent_id=$1", il.agent); err != nil {
		t.Fatal(err)
	}
	if resumes() != 1 {
		t.Fatal("a cleared agent is not resumed")
	}
	// Someone put it to sleep after the work began: the sleep wins.
	if _, err := il.c.RequestLifecycle(t.Context(), il.owner, il.agent, "sleep", "sleep"); err != nil {
		t.Fatal(err)
	}
	if resumes() != 0 || due() {
		t.Fatal("a sleep requested during the work was overridden")
	}
	if _, err := il.s.pool.Exec(t.Context(), "DELETE FROM platform_operations WHERE kind='sleep' AND agent_id=$1", il.agent); err != nil {
		t.Fatal(err)
	}
	// Past its due time, the work is no longer in progress.
	if _, err := il.s.pool.Exec(t.Context(), "UPDATE owner_instructions SET working_since=working_since-interval '2 hours',result_due_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1", op); err != nil {
		t.Fatal(err)
	}
	if resumes() != 0 || due() {
		t.Fatal("work past its due time is resumed")
	}
}

// The capacity queue projects fair_admission.qnt's fifo policy with exclusive
// clients (one VM slot each). deadOwnerTest: client 2 heads the queue and is
// admitted, then leaves (its VM is gone); when it asks again it queues behind
// client 1, which is admitted first, and 2 is not admitted while 1 holds the
// slot.
func TestCapacityQueueProjectsFairAdmissionDeadOwner(t *testing.T) {
	il := newInvocationLab(t)
	holder := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "holder")
	il.computing(t, holder)
	c1 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "c1")
	c2 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "c2")
	il.wake(t, c1, "wake-c1")
	il.wake(t, c2, "wake-c2")
	// init: queue [2,1], both alive.
	il.admit(t, c2, []string{holder}, 0)
	il.admit(t, c1, []string{holder}, 0)
	if got := il.waiters(t); !sameOrder(got, []string{c2, c1}) {
		t.Fatal("init", got)
	}
	// admit(2): the slot frees and 2 takes it.
	if d := il.admit(t, c2, nil, 1); !d.Admit {
		t.Fatal("admit(2)", d)
	}
	il.taken(t, c2)
	// crash(2), prune, enqueue(2): 2's VM is gone and it needs a slot again.
	if d := il.admit(t, c2, []string{holder}, 0); d.Admit {
		t.Fatal("enqueue(2) admitted", d)
	}
	if got := il.waiters(t); !sameOrder(got, []string{c1, c2}) {
		t.Fatal("enqueue(2) did not queue behind 1", got)
	}
	// admit(1), then admit(2) fails.
	if d := il.admit(t, c2, nil, 1); d.Admit {
		t.Fatal("2 overtook 1")
	}
	if d := il.admit(t, c1, nil, 1); !d.Admit {
		t.Fatal("admit(1)", d)
	}
	il.taken(t, c1)
	il.computing(t, c1) // active: it holds its slot
	if d := il.admit(t, c2, []string{holder, c1}, 0); d.Admit {
		t.Fatal("admit(2) while 1 holds the slot", d)
	}
}

// A FAILED agent never waits for capacity: its wake goes on to fail with
// restart_budget_exhausted, as on a host with room (ADR 012).
func TestAFailedAgentDoesNotWaitForCapacity(t *testing.T) {
	il := newInvocationLab(t)
	holder := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "holder")
	il.computing(t, holder)
	il.wake(t, il.agent, "wake")
	if _, err := il.s.pool.Exec(t.Context(), `INSERT INTO failed_agents(agent_id,reason,failures) VALUES($1,'boot_failed',5)`, il.agent); err != nil {
		t.Fatal(err)
	}
	if d := il.admit(t, il.agent, []string{holder}, 0); !d.Admit || d.Evict != "" {
		t.Fatal("a FAILED agent waits for capacity, or stopped a VM", d)
	}
	if got := il.waiters(t); len(got) != 0 {
		t.Fatal("a FAILED agent queued", got)
	}
}
