package controlplane

import (
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// A job leads back to the API request that started it (OPS-02): the
// invocation's operation records the request's X-Request-ID, and so do, through
// the mandate it granted, the requests its agent then sends to other agents.
func TestJobsLeadBackToTheAPIRequestThatStartedThem(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	requestID := strings.Repeat("ab", 16)
	ctx := telemetry.WithRequestID(t.Context(), requestID)
	r, err := il.c.CreateInvocation(ctx, alice, il.agent, "traced", InvocationInput{OwnerInstruction: privateInstruction("ask b")})
	if err != nil {
		t.Fatal(err)
	}
	inv := decodeInvocation(t, r)
	var recorded *string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT request_id FROM platform_operations WHERE id=$1", inv.ID).Scan(&recorded); err != nil || recorded == nil || *recorded != requestID {
		t.Fatal("the operation did not record its request", recorded, err)
	}
	origin := func(kind, id string) string {
		t.Helper()
		got, err := il.s.JobOrigin(t.Context(), WorkerJob{Kind: kind, ID: id})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	var instructionMailbox string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", inv.ID).Scan(&instructionMailbox); err != nil {
		t.Fatal(err)
	}
	if got := origin("delivery", instructionMailbox); got != requestID {
		t.Fatal("the invocation's delivery", got)
	}

	// The agent asks another agent under the invocation's mandate.
	b := activateTenantAgent(t, il.tenantLab, mustCatalog(t, il.tenantLab), il.owner, "traced-b")
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	vm := il.vm(t)
	il.ackWorking(t, inv.ID)
	var mandate string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT mandate_id FROM owner_instructions WHERE operation_id=$1", inv.ID).Scan(&mandate); err != nil {
		t.Fatal(err)
	}
	sent, err := il.tr.SubmitFromVM(t.Context(), vm, "peer-1", capsuleprotocol.Submission{RecipientAgentID: b, MandateID: mandate,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), Payload: text("hello b")})
	if err != nil {
		t.Fatal(err)
	}
	if got := origin("delivery", mailboxFor(t, il.s, sent.RequestID, "request")); got != requestID {
		t.Fatal("the request between agents", got)
	}
	for _, kind := range []string{"expiration", "closure"} {
		if got := origin(kind, sent.RequestID); got != requestID {
			t.Fatal(kind, got)
		}
	}

	// Work no API request started leads nowhere; neither does a bad ID.
	untraced, _, err := il.create(t, alice, "untraced", "no request ID")
	if err != nil {
		t.Fatal(err)
	}
	var none string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", untraced.ID).Scan(&none); err != nil {
		t.Fatal(err)
	}
	if got := origin("delivery", none); got != "" {
		t.Fatal("an untraced invocation", got)
	}
	if telemetry.RequestIDFrom(telemetry.WithRequestID(t.Context(), "'; DROP TABLE agents; --")) != "" {
		t.Fatal("a bad request ID was carried")
	}
	if got := origin("delivery", "mbx_missing"); got != "" {
		t.Fatal("a missing mailbox", got)
	}

	// An agent's provisioning, created through a traced request.
	created, err := mustCatalog(t, il.tenantLab).Reserve(telemetry.WithRequestID(t.Context(), strings.Repeat("cd", 16)), il.owner, "traced-agent", tenantAgentInput("traced-c"))
	if err != nil {
		t.Fatal(err)
	}
	var provision string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM platform_operations WHERE kind='provision' AND request_id IS NOT NULL").Scan(&provision); err != nil {
		t.Fatal(err)
	}
	if got := origin("provision", provision); got != strings.Repeat("cd", 16) || created.Status != 202 {
		t.Fatal("provisioning", got, created.Status)
	}
}
