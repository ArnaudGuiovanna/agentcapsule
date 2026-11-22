package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// bootRefused is a worker runtime that must not be used: a delivery of a
// disabled organization boots no VM and sends nothing.
type bootRefused struct{ calls atomic.Int32 }

func (b *bootRefused) Fence(context.Context, string, string) error { b.calls.Add(1); return nil }
func (b *bootRefused) Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	b.calls.Add(1)
	return harnessstore.Receipt{}, errors.New("sent")
}
func (b *bootRefused) Invoke(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	b.calls.Add(1)
	return harnessstore.Receipt{}, errors.New("invoked")
}
func (b *bootRefused) WithPreparedDelivery(ctx context.Context, _ string, fn func(context.Context) error) error {
	b.calls.Add(1)
	return fn(ctx)
}

// Disabling an organization stops its work, not only its members' requests:
// a scheduled invocation that comes due is closed, a wake is canceled, its
// agents cannot send to one another, a delivery to one of them is not
// claimed and boots no VM, and its running VMs get the ordinary sleep
// command, once. Found by the v0.1.0 audit (S-22): before, the disable only
// changed the organization's status.
func TestDisabledOrganizationsWorkStops(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	a := il.agent
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "peer-b")
	if _, err := il.s.pool.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vmA := il.vm(t)
	il.runAgent(t, b)
	// The organization's work before the disable: an invocation the agent
	// works on, with its mandate; one queued behind it; one scheduled; a wake.
	working, _, err := il.create(t, alice, "working", "ask b")
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, working.ID)
	var mandate string
	if err = il.s.pool.QueryRow(ctx, "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", working.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	queued, _, err := il.create(t, alice, "queued", "later in the queue")
	if err != nil {
		t.Fatal(err)
	}
	scheduled, err := il.schedule(t, alice, "scheduled", "at its time", time.Now().UTC().Add(time.Hour), 120)
	if err != nil {
		t.Fatal(err)
	}
	r, err := il.c.RequestLifecycle(ctx, il.owner, b, "wake-b", "wake")
	if err != nil {
		t.Fatal(err)
	}
	var wake AgentCreation
	if err = json.Unmarshal(r.Body, &wake); err != nil || wake.OperationID == "" {
		t.Fatal("the wake", string(r.Body), err)
	}

	if _, err = il.a.DisableOrganization(ctx, il.platform, il.org.ID, "disable"); err != nil {
		t.Fatal(err)
	}

	// Its agents send nothing to one another.
	in := capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond),
		Payload: text("still there?")}
	if _, err = il.tr.SubmitFromVM(ctx, vmA, "peer-after-disable", in); !errors.Is(err, ErrUnavailable) {
		t.Fatal("an agent of a disabled organization sent a request", err)
	}
	if remaining(t, il.s, mandate) != il.count(t, "SELECT max_requests FROM mandates WHERE id='"+mandate+"'") {
		t.Fatal("the refused request spent its mandate")
	}
	// Its scheduled invocation is closed when it comes due, and queues nothing.
	due := time.Now().UTC().Add(2 * time.Hour)
	if n, err := il.s.ReleaseDueInstructions(ctx, &due, 10); err != nil || n != 0 || il.mailboxes(t, scheduled.ID) != 0 {
		t.Fatal("a disabled organization's scheduled invocation was released", n, err)
	}
	if il.count(t, "SELECT count(*) FROM platform_operations WHERE id='"+scheduled.ID+"' AND status='CANCELED' AND error_code='organization_disabled'") != 1 {
		t.Fatal("the scheduled invocation is not closed")
	}
	// Its wake is canceled.
	op, err := il.s.BeginLifecycleOperation(ctx, wake.OperationID, b, "local")
	if err != nil || op.Status != "CANCELED" ||
		il.count(t, "SELECT count(*) FROM platform_operations WHERE id='"+wake.OperationID+"' AND error_code='organization_disabled'") != 1 {
		t.Fatal("a disabled organization's agent woke", op, err)
	}
	// Its queued invocation is not claimed, and boots no VM.
	var mbx string
	if err = il.s.pool.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", queued.ID).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ClaimInstruction(ctx, mbx, time.Minute); !errors.Is(err, ErrOrganizationDisabled) {
		t.Fatal("a disabled organization's invocation was claimed", err)
	}
	rt := &bootRefused{}
	if err = il.tr.DispatchMailbox(ctx, mbx, time.Minute, rt); !errors.Is(err, ErrNoDelivery) || !errors.Is(err, ErrOrganizationDisabled) || rt.calls.Load() != 0 {
		t.Fatal("a disabled organization's delivery reached the runtime", err, rt.calls.Load())
	}
	if il.count(t, "SELECT attempts FROM agent_mailboxes WHERE id='"+mbx+"' AND delivery_state='PENDING'") != 0 {
		t.Fatal("the held delivery spent an attempt")
	}
	// Its running VMs go to sleep, through the ordinary command, once.
	n, err := il.s.ScheduleSuspensionSleeps(ctx, "local", 10)
	if err != nil || n != 2 {
		t.Fatal("the running agents were not put to sleep", n, err)
	}
	if il.count(t, "SELECT count(*) FROM platform_operations WHERE kind='sleep' AND cause='organization_disabled' AND status='PENDING' AND agent_id IN ('"+a+"','"+b+"')") != 2 {
		t.Fatal("no sleep command for each running agent")
	}
	if n, err = il.s.ScheduleSuspensionSleeps(ctx, "local", 10); err != nil || n != 0 {
		t.Fatal("asked again while the sleep is pending", n, err)
	}
	// The sleep itself runs: a disabled organization's agent still stops.
	var sleep string
	if err = il.s.pool.QueryRow(ctx, "SELECT id FROM platform_operations WHERE kind='sleep' AND agent_id=$1", b).Scan(&sleep); err != nil {
		t.Fatal(err)
	}
	if op, err = il.s.BeginLifecycleOperation(ctx, sleep, b, "local"); err != nil || op.Status != "RUNNING" {
		t.Fatal("the sleep of a disabled organization's agent did not start", op, err)
	}
}
