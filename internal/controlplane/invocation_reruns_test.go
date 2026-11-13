package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func declared(ids ...string) []DeclaredLoss {
	out := make([]DeclaredLoss, len(ids))
	for i, id := range ids {
		out[i] = DeclaredLoss{OutcomeID: id}
	}
	return out
}

func mailboxOf(t *testing.T, s *Store, op string) string {
	t.Helper()
	var id string
	if err := s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// lossOf is the restore authority's outcome ID of invocation op.
func lossOf(t *testing.T, s *Store, agentID, op string) string {
	t.Helper()
	id, err := outcomeID(agentID, mailboxOf(t, s, op))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// activateRestore takes restore n of the agent through its steps up to the
// activation, as the worker does, and retires its restricted boot. No VM
// runs here. CompleteVolumeRestore is the next step.
func activateRestore(t *testing.T, s *Store, agentID string, n int) {
	t.Helper()
	e, err := s.VolumeEnrollment(t.Context(), agentID, "local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.BeginVolumeRestore(t.Context(), restoreID(n), agentID, "local", archiveID(n)); err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err = s.AdvanceVolumeRestore(t.Context(), restoreID(n), "local", step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	boot := restrictedRestoreBoot(t, s, e)
	if err = s.ActivateVolumeRestore(t.Context(), restoreID(n), "local", boot.Generation, boot.VMID); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, boot)
}

// restoreLosing runs restore n of the agent and declares these invocations
// lost. It returns the restore's decision for each, by invocation.
func restoreLosing(t *testing.T, s *Store, agentID string, n int, ops ...string) map[string]RestoreLoss {
	t.Helper()
	activateRestore(t, s, agentID, n)
	ids := make([]string, len(ops))
	for i, op := range ops {
		ids[i] = lossOf(t, s, agentID, op)
	}
	losses, err := s.CompleteVolumeRestore(t.Context(), restoreID(n), "local", declared(ids...))
	if err != nil || len(losses) != len(ops) {
		t.Fatal("complete the restore", losses, err)
	}
	byInvocation := map[string]RestoreLoss{}
	for _, l := range losses {
		byInvocation[l.InvocationID] = l
	}
	return byInvocation
}

func (il *invocationLab) get(t *testing.T, p Principal, op string) Invocation {
	t.Helper()
	v, err := il.c.GetInvocation(t.Context(), p, op)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (il *invocationLab) listed(t *testing.T, p Principal, state string) []string {
	t.Helper()
	items, err := il.c.ListInvocations(t.Context(), p, il.agent, "", state, 50)
	if err != nil {
		t.Fatal(state, err)
	}
	ids := []string{}
	for _, v := range items {
		ids = append(ids, v.ID)
	}
	slices.Sort(ids)
	return ids
}

func (il *invocationLab) cancel(t *testing.T, p Principal, op, key string) (Invocation, APIReceipt, error) {
	t.Helper()
	r, err := il.c.CancelInvocation(t.Context(), p, op, key)
	var v Invocation
	if err == nil && (r.Status != 200 || json.Unmarshal(r.Body, &v) != nil) {
		t.Fatal("cancel receipt", r.Status)
	}
	return v, r, err
}

// The restore's last step queues the rerun of each lost invocation, in the
// same transaction as the copy of its losses: same mailbox ID and place in
// the queue, fresh attempts, the first delivery window again, and the same
// mandate with its remaining budget, its expiry moved with the deadline. The
// invocation is lost until the rerun completes; the result the database
// still holds stays readable; the rerun's replaces it. Repeating the step
// decides nothing again.
func TestRestoreQueuesTheRerunOfLostInvocations(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	var lost []string
	for _, key := range []string{"first", "second"} {
		v, _, err := il.create(t, alice, key, key+" question")
		if err != nil {
			t.Fatal(err)
		}
		il.complete(t, v.ID)
		lost = append(lost, v.ID)
	}
	first := lost[0]
	pending, _, err := il.create(t, alice, "pending", "third question")
	if err != nil {
		t.Fatal(err)
	}
	old, err := il.c.InstructionResult(t.Context(), alice, first)
	if err != nil {
		t.Fatal(err)
	}
	// The first run used one request of its budget.
	var mandate, payload string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT mandate_id,result_payload_id FROM owner_instructions WHERE operation_id=$1", first).Scan(&mandate, &payload); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE mandates SET remaining=remaining-1 WHERE id=$1", mandate); err != nil {
		t.Fatal(err)
	}
	var cipher []byte
	if err = il.s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE id=$1", payload).Scan(&cipher); err != nil {
		t.Fatal(err)
	}

	activateRestore(t, il.s, il.agent, 1)
	unmatched, err := outcomeID(il.agent, "event-this-database-lost")
	if err != nil {
		t.Fatal(err)
	}
	ids := declared(lossOf(t, il.s, il.agent, first), lossOf(t, il.s, il.agent, lost[1]), unmatched)
	losses, err := il.s.CompleteVolumeRestore(t.Context(), restoreID(1), "local", ids)
	if err != nil || len(losses) != 3 {
		t.Fatal("complete the restore", losses, err)
	}
	for _, l := range losses {
		want := RerunQueued
		if l.InvocationID == "" {
			want = ""
		}
		if l.Rerun != want || l.SkipReason != "" {
			t.Fatal("rerun decision", l)
		}
	}

	// The API: lost, with the time of the loss, and the old result readable.
	v := il.get(t, alice, first)
	if v.State != "lost" || v.LostAt == nil || v.CompletedAt != nil || !v.ResultAvailable || v.ErrorCode != "" || !v.ExpiresAt.After(time.Now().Add(59*time.Minute)) {
		t.Fatal("a lost invocation", v)
	}
	if body, err := il.c.InstructionResult(t.Context(), alice, first); err != nil || !bytes.Equal(body, old) {
		t.Fatal("the result the database holds is not readable while lost", err)
	}
	if got := il.listed(t, alice, "lost"); !slices.Equal(got, slices.Sorted(slices.Values(lost))) {
		t.Fatal("state filter lost", got)
	}
	for state, want := range map[string][]string{"completed": {}, "accepted": {pending.ID}, "working": {}, "": slices.Sorted(slices.Values(append([]string{pending.ID}, lost...)))} {
		if got := il.listed(t, alice, state); !slices.Equal(got, want) {
			t.Fatal("state filter", state, got, want)
		}
	}
	if p := il.get(t, alice, pending.ID); p.State != "accepted" || p.LostAt != nil {
		t.Fatal("an invocation the restore did not lose", p)
	}

	// The queue: same mailbox, first in line, a fresh delivery.
	mailbox := mailboxOf(t, il.s, first)
	if head, err := il.s.HeadDelivery(t.Context(), il.agent); err != nil || head != mailbox {
		t.Fatal("the rerun is not at the head of the queue", head, err)
	}
	var deadline, expiry time.Time
	var attempts, remaining int
	var reached, valid, held bool
	var status string
	if err = il.s.pool.QueryRow(t.Context(), `SELECT m.expires_at,m.attempts,m.may_have_reached,d.expires_at,d.remaining,d.valid,o.status,
            p.delivered_at IS NULL AND p.purge_after IS NULL
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id JOIN mandates d ON d.id=i.mandate_id
        JOIN platform_operations o ON o.id=i.operation_id JOIN transit_payloads p ON p.id=i.input_payload_id
        WHERE m.id=$1 AND m.delivery_state='PENDING' AND EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id)`, mailbox).
		Scan(&deadline, &attempts, &reached, &expiry, &remaining, &valid, &status, &held); err != nil {
		t.Fatal("the rerun is not queued", err)
	}
	if attempts != 0 || reached || !expiry.Equal(deadline) || remaining != 2 || !valid || status != "PENDING" || !held {
		t.Fatal("queued rerun", attempts, reached, deadline, expiry, remaining, valid, status, held)
	}
	if deadline.After(time.Now().Add(time.Hour + time.Minute)) {
		t.Fatal("the rerun's window is longer than the first one", deadline)
	}

	// Repeating the step returns the same decisions and changes nothing.
	again, err := il.s.CompleteVolumeRestore(t.Context(), restoreID(1), "local", declared(unmatched))
	if err != nil || !slices.Equal(again, losses) {
		t.Fatal("a repeated completion", again, err)
	}
	var unchanged bool
	if err = il.s.pool.QueryRow(t.Context(), "SELECT expires_at=$2 FROM agent_mailboxes WHERE id=$1", mailbox, deadline).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("a repeated completion queued the rerun again", err)
	}
	if n := il.count(t, "SELECT count(*) FROM invocation_reruns"); n != 2 {
		t.Fatal("rerun decisions", n)
	}

	// The rerun: the same event, mandate and budget, then the new result.
	attempt, envelope := claimInstruction(t, il.tr, mailbox)
	in, err := capsuleprotocol.DecodeInvocation(envelope, il.agent)
	if err != nil || envelope.ID != mailbox || in.OperationID != first || in.Mandate.ID != mandate || !in.Mandate.ExpiresAt.Equal(deadline) || in.Mandate.MaxAgentRequests != 3 {
		t.Fatal("the rerun's envelope", envelope.ID, in.Mandate, err)
	}
	r, err := instructionRuntimeLab(t, il.agent).Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailbox, attempt.Token, r.Result); err != nil {
		t.Fatal("the rerun's result", err)
	}
	v = il.get(t, alice, first)
	if v.State != "completed" || v.LostAt == nil || v.CompletedAt == nil || !v.CompletedAt.After(*v.LostAt) || !v.ResultAvailable || v.ErrorCode != "" {
		t.Fatal("a completed rerun", v)
	}
	var replaced []byte
	var fresh bool
	if err = il.s.pool.QueryRow(t.Context(), `SELECT p.ciphertext,p.delivered_at IS NULL FROM owner_instructions i
        JOIN transit_payloads p ON p.id=i.result_payload_id WHERE i.operation_id=$1 AND p.id=$2`, first, payload).Scan(&replaced, &fresh); err != nil {
		t.Fatal("the rerun's result is not in the old result's place", err)
	}
	if bytes.Equal(replaced, cipher) || !fresh || il.count(t, "SELECT count(*) FROM transit_payloads WHERE kind='instruction_result' AND ref_id=$1", first) != 1 {
		t.Fatal("the rerun's result did not replace the old one")
	}
	if body, err := il.c.InstructionResult(t.Context(), alice, first); err != nil || !bytes.Contains(body, []byte("first question")) {
		t.Fatal("the rerun's result", err)
	}
	if il.count(t, "SELECT count(*) FROM transit_payloads p JOIN owner_instructions i ON i.input_payload_id=p.id WHERE i.operation_id=$1 AND p.delivered_at IS NOT NULL", first) != 1 {
		t.Fatal("the input's retention did not start again")
	}
	if got := il.listed(t, alice, "completed"); !slices.Equal(got, []string{first}) {
		t.Fatal("completed after the rerun", got)
	}
	if got := il.listed(t, alice, "lost"); !slices.Equal(got, []string{lost[1]}) {
		t.Fatal("lost after one rerun", got)
	}
	// A second ACK of the same rerun is refused.
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailbox, attempt.Token, r.Result); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("a second ACK", err)
	}
}

// The decisions commit with the losses and the return to READY, or not at
// all. A crash during the rerun's delivery retries it like any delivery.
func TestRerunsCommitWithTheRestoreAndSurviveCrashes(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	v, _, err := il.create(t, alice, "lost", "lost question")
	if err != nil {
		t.Fatal(err)
	}
	il.complete(t, v.ID)
	mailbox := mailboxOf(t, il.s, v.ID)
	loss := lossOf(t, il.s, il.agent, v.ID)
	activateRestore(t, il.s, il.agent, 1)
	if _, err = il.s.pool.Exec(t.Context(), `CREATE FUNCTION fail_rerun() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	untouched := func(point string) {
		t.Helper()
		if stage, _ := enrollmentState(t, il.s, il.agent); stage != "RESTORING" {
			t.Fatal(point, "the volume served", stage)
		}
		if n := il.count(t, `SELECT count(*) FROM agent_mailboxes m JOIN platform_operations o ON o.id=m.instruction_id
            JOIN owner_instructions i ON i.operation_id=o.id JOIN transit_payloads p ON p.id=i.input_payload_id
            WHERE m.id=$1 AND m.delivery_state='DELIVERED' AND o.status='SUCCEEDED' AND p.delivered_at IS NOT NULL
            AND NOT EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id)`, mailbox); n != 1 {
			t.Fatal(point, "the invocation changed without its losses")
		}
		if n := il.count(t, "SELECT (SELECT count(*) FROM invocation_reruns)+(SELECT count(*) FROM volume_restore_losses)"); n != 0 {
			t.Fatal(point, "a decision or a loss was kept", n)
		}
	}
	for point, trigger := range map[string]string{
		"decision": "CREATE TRIGGER fail_point BEFORE INSERT ON invocation_reruns FOR EACH ROW EXECUTE FUNCTION fail_rerun()",
		"ready":    "CREATE TRIGGER fail_point BEFORE UPDATE ON store_enrollments FOR EACH ROW EXECUTE FUNCTION fail_rerun()",
	} {
		if _, err = il.s.pool.Exec(t.Context(), trigger); err != nil {
			t.Fatal(err)
		}
		if _, err = il.s.CompleteVolumeRestore(t.Context(), restoreID(1), "local", declared(loss)); err == nil {
			t.Fatal(point, "injected failure ignored")
		}
		untouched(point)
		if _, err = il.s.pool.Exec(t.Context(), "DROP TRIGGER fail_point ON "+map[string]string{"decision": "invocation_reruns", "ready": "store_enrollments"}[point]); err != nil {
			t.Fatal(err)
		}
	}
	losses, err := il.s.CompleteVolumeRestore(t.Context(), restoreID(1), "local", declared(loss))
	if err != nil || len(losses) != 1 || losses[0].Rerun != RerunQueued {
		t.Fatal("completion after the failures", losses, err)
	}

	// The worker dies after the rerun reached the agent, before its ACK: the
	// lease lapses and the next attempt delivers the same event again.
	stale, envelope := claimInstruction(t, il.tr, mailbox)
	if _, _, err = il.cancel(t, alice, v.ID, "while-delivered"); !errors.Is(err, ErrTransition) {
		t.Fatal("a rerun being delivered was canceled", err)
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", mailbox); err != nil {
		t.Fatal(err)
	}
	attempt, again := claimInstruction(t, il.tr, mailbox)
	if again.ID != envelope.ID || !bytes.Equal(again.Body, envelope.Body) {
		t.Fatal("the retry is not the same event")
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailbox, stale.Token, []byte(`{"content":[]}`)); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("a stale attempt acknowledged the rerun", err)
	}
	r, err := instructionRuntimeLab(t, il.agent).Invoke(t.Context(), il.agent, again)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailbox, attempt.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	if got := il.get(t, alice, v.ID); got.State != "completed" || got.LostAt == nil {
		t.Fatal("rerun after a crash", got)
	}
}

// A lost invocation whose requester can no longer invoke the agent is never
// run again: at the restore, or later, before the rerun reaches the agent.
// It stays lost, with the reason as its error_code. A decision only moves
// from queued to skipped.
func TestRevokedRequesterLostInvocationIsNeverRerun(t *testing.T) {
	il := newInvocationLab(t)
	aliceMember, alice := il.person(t, "alice")
	bobMember, bob := il.person(t, "bob")
	rights := []string{"read_metadata", "invoke", "read_content"}
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: aliceMember.PrincipalID, Permissions: rights}, "assign-alice")
	bobRight := assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: bobMember.PrincipalID, Permissions: rights}, "assign-bob")
	var ops []string
	for _, c := range []struct {
		p   Principal
		key string
	}{{alice, "a"}, {bob, "b1"}, {bob, "b2"}} {
		v, _, err := il.create(t, c.p, c.key, "question "+c.key)
		if err != nil {
			t.Fatal(err)
		}
		il.complete(t, v.ID)
		ops = append(ops, v.ID)
	}
	if _, err := il.a.RevokeMember(t.Context(), il.owner, aliceMember.PrincipalID, "revoke-alice"); err != nil {
		t.Fatal(err)
	}
	decisions := restoreLosing(t, il.s, il.agent, 1, ops...)
	if d := decisions[ops[0]]; d.Rerun != RerunSkipped || d.SkipReason != SkipRequesterRevoked {
		t.Fatal("a revoked member's invocation", d)
	}
	for _, op := range ops[1:] {
		if d := decisions[op]; d.Rerun != RerunQueued {
			t.Fatal("an active member's invocation", d)
		}
	}
	if v := il.get(t, il.owner, ops[0]); v.State != "lost" || v.ErrorCode != SkipRequesterRevoked || v.LostAt == nil {
		t.Fatal("a skipped rerun", v)
	}
	if n := il.count(t, `SELECT count(*) FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN transit_payloads p ON p.id=i.input_payload_id WHERE m.id=$1 AND m.delivery_state='DELIVERED' AND p.delivered_at IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id)`, mailboxOf(t, il.s, ops[0])); n != 1 {
		t.Fatal("a skipped rerun was queued, or its input held")
	}

	// Bob loses the right to invoke after the rerun was queued.
	if _, err := il.a.RevokeAgentAssignment(t.Context(), il.owner, il.agent, bobRight.ID, "revoke-bob"); err != nil {
		t.Fatal(err)
	}
	first := mailboxOf(t, il.s, ops[1])
	if _, err := il.tr.ClaimInstruction(t.Context(), first, time.Minute); !errors.Is(err, ErrRerunSkipped) {
		t.Fatal("a revoked requester's rerun was claimed", err)
	}
	if n := il.count(t, `SELECT count(*) FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN mandates d ON d.id=i.mandate_id JOIN transit_payloads p ON p.id=i.input_payload_id
        WHERE m.id=$1 AND m.delivery_state='CANCELED' AND m.attempts=0 AND NOT d.valid AND p.delivered_at IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id)`, first); n != 1 {
		t.Fatal("the skipped rerun is not closed")
	}
	// The dispatcher skips the next one too, and the queue moves on.
	second := mailboxOf(t, il.s, ops[2])
	if err := il.tr.DispatchMailbox(t.Context(), second, time.Minute, instructionRuntimeLab(t, il.agent)); err != nil {
		t.Fatal("dispatch of a skipped rerun", err)
	}
	if _, err := il.s.HeadDelivery(t.Context(), il.agent); !errors.Is(err, ErrNoDelivery) {
		t.Fatal("a skipped rerun stayed in the queue", err)
	}
	for _, op := range ops {
		if v := il.get(t, il.owner, op); v.State != "lost" || v.ErrorCode != SkipRequesterRevoked || v.CompletedAt != nil {
			t.Fatal("a revoked requester's invocation", v)
		}
	}
	if got := il.listed(t, il.owner, "lost"); len(got) != 3 {
		t.Fatal("lost invocations", got)
	}
	if got := il.listed(t, il.owner, "failed"); len(got) != 0 {
		t.Fatal("a skipped rerun is listed as failed", got)
	}

	// The decisions are permanent, except queued to skipped.
	for name, query := range map[string]string{
		"skipped to queued":  "UPDATE invocation_reruns SET state='queued',skip_reason='' WHERE state='skipped'",
		"another reason":     "UPDATE invocation_reruns SET skip_reason='input_purged'",
		"another invocation": "UPDATE invocation_reruns SET invocation_id=(SELECT operation_id FROM owner_instructions LIMIT 1)",
		"deleted":            "DELETE FROM invocation_reruns",
	} {
		if _, err := il.s.pool.Exec(t.Context(), query); err == nil {
			t.Fatal("a rerun decision was", name)
		}
	}
}

// A lost invocation whose files are purged is not run again until a product
// decision: it stays lost, and its input waits. Its input purged: the same.
// A queued rerun keeps its files: the purge waits for the rerun to end.
func TestLostInvocationWithPurgedContentIsNotRerun(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	invokeWithFile := func(key string) Invocation {
		t.Helper()
		att, _, err := il.upload(t, alice, "upload-"+key, key+".txt", []byte("file "+key), 0)
		if err != nil {
			t.Fatal(err)
		}
		v, err := il.invokeWith(t, alice, key, att.ID)
		if err != nil {
			t.Fatal(err)
		}
		il.complete(t, v.ID)
		return v
	}
	purgedFile := invokeWithFile("purged-file")
	if n, err := il.s.PurgeAttachments(t.Context(), nil, 10); err != nil || n != 1 {
		t.Fatal("purge", n, err)
	}
	keptFile := invokeWithFile("kept-file")
	purgedInput, _, err := il.create(t, alice, "purged-input", "short-lived question")
	if err != nil {
		t.Fatal(err)
	}
	il.complete(t, purgedInput.ID)
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second'
        WHERE id=(SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1)`, purgedInput.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := il.tr.PurgeExpired(t.Context(), 10); err != nil || n != 1 {
		t.Fatal("input purge", n, err)
	}
	decisions := restoreLosing(t, il.s, il.agent, 1, purgedFile.ID, keptFile.ID, purgedInput.ID)
	for op, want := range map[string][2]string{purgedFile.ID: {RerunSkipped, SkipAttachmentsPurged}, keptFile.ID: {RerunQueued, ""},
		purgedInput.ID: {RerunSkipped, SkipInputPurged}} {
		if d := decisions[op]; d.Rerun != want[0] || d.SkipReason != want[1] {
			t.Fatal("decision", op, d, want)
		}
		v := il.get(t, alice, op)
		if v.State != "lost" || v.ErrorCode != want[1] {
			t.Fatal("lost invocation", v)
		}
	}
	held := `SELECT count(*) FROM transit_payloads p JOIN owner_instructions i ON i.input_payload_id=p.id
        WHERE i.operation_id=$1 AND p.purged_at IS NULL AND p.delivered_at IS NULL AND p.purge_after IS NULL`
	for _, op := range []string{purgedFile.ID, keptFile.ID} {
		if il.count(t, held, op) != 1 {
			t.Fatal("the input of a lost invocation is not held", op)
		}
	}
	if n, err := il.s.PurgeAttachments(t.Context(), nil, 10); err != nil || n != 0 {
		t.Fatal("the files of a queued rerun were purged", n, err)
	}
	attempt, envelope := claimInstruction(t, il.tr, mailboxOf(t, il.s, keptFile.ID))
	in, err := capsuleprotocol.DecodeInvocation(envelope, il.agent)
	if err != nil || len(in.Attachments) != 1 || in.Attachments[0].ID != keptFile.Attachments[0] {
		t.Fatal("the rerun does not carry its file", in.Attachments, err)
	}
	r, err := instructionRuntimeLab(t, il.agent).Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailboxOf(t, il.s, keptFile.ID), attempt.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	if n, err := il.s.PurgeAttachments(t.Context(), nil, 10); err != nil || n != 1 {
		t.Fatal("the files of a finished rerun", n, err)
	}
}

// A lost invocation can be canceled until its rerun reaches the agent: a
// queued rerun then never runs, a skipped one is closed. A rerun being
// delivered is not interrupted; one acknowledged "working" is canceled like
// any working invocation.
func TestLostInvocationCanBeCanceledUntilItsRerunReachesTheAgent(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	att, _, err := il.upload(t, alice, "upload", "file.txt", []byte("file"), 0)
	if err != nil {
		t.Fatal(err)
	}
	skipped, err := il.invokeWith(t, alice, "skipped", att.ID)
	if err != nil {
		t.Fatal(err)
	}
	il.complete(t, skipped.ID)
	if _, err = il.s.PurgeAttachments(t.Context(), nil, 10); err != nil {
		t.Fatal(err)
	}
	var ops []string
	for _, key := range []string{"queued", "delivered", "working"} {
		v, _, err := il.create(t, alice, key, key+" question")
		if err != nil {
			t.Fatal(err)
		}
		il.complete(t, v.ID)
		ops = append(ops, v.ID)
	}
	queued, delivered, working := ops[0], ops[1], ops[2]
	restoreLosing(t, il.s, il.agent, 1, append([]string{skipped.ID}, ops...)...)

	v, r, err := il.cancel(t, alice, queued, "cancel-queued")
	if err != nil || v.State != "canceled" || v.LostAt == nil || v.ErrorCode != "canceled" {
		t.Fatal("cancel a queued rerun", v, err)
	}
	if again, replay, err := il.cancel(t, alice, queued, "cancel-queued"); err != nil || !replay.Replayed || !bytes.Equal(replay.Body, r.Body) || again.State != "canceled" {
		t.Fatal("cancel replay", err)
	}
	if _, _, err = il.cancel(t, alice, queued, "cancel-again"); !errors.Is(err, ErrTransition) {
		t.Fatal("a canceled invocation canceled again", err)
	}
	if n := il.count(t, `SELECT count(*) FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN mandates d ON d.id=i.mandate_id JOIN transit_payloads p ON p.id=i.input_payload_id
        WHERE m.id=$1 AND m.delivery_state='CANCELED' AND NOT d.valid AND p.purged_at IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id)`, mailboxOf(t, il.s, queued)); n != 1 {
		t.Fatal("a canceled rerun is still queued, or its input kept")
	}
	if v, _, err = il.cancel(t, alice, skipped.ID, "cancel-skipped"); err != nil || v.State != "canceled" || v.LostAt == nil {
		t.Fatal("cancel a skipped rerun", v, err)
	}
	if got := il.listed(t, alice, "canceled"); !slices.Equal(got, slices.Sorted(slices.Values([]string{queued, skipped.ID}))) {
		t.Fatal("canceled", got)
	}

	// The next rerun reaches the agent: it is not interrupted.
	attempt, envelope := claimInstruction(t, il.tr, mailboxOf(t, il.s, delivered))
	if _, _, err = il.cancel(t, alice, delivered, "cancel-delivered"); !errors.Is(err, ErrTransition) {
		t.Fatal("a rerun being delivered was canceled", err)
	}
	result, err := instructionRuntimeLab(t, il.agent).Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mailboxOf(t, il.s, delivered), attempt.Token, result.Result); err != nil {
		t.Fatal(err)
	}
	// The last one is acknowledged "working": lost until its outcome.
	il.ackWorking(t, working)
	if v = il.get(t, alice, working); v.State != "lost" || v.ResultDueAt == nil {
		t.Fatal("a working rerun", v)
	}
	if v, _, err = il.cancel(t, alice, working, "cancel-working"); err != nil || v.State != "canceled" || v.LostAt == nil {
		t.Fatal("cancel a working rerun", v, err)
	}
}

// A completion posted later over the platform channel replaces the old
// result too, and the owner of a historical agent reads the old result while
// the invocation is lost.
func TestLaterCompletionOfARerunReplacesTheResult(t *testing.T) {
	s, c, tr, _, owner, e := instructionLab(t)
	mailbox, op := queueInstruction(t, c, owner, e.AgentID, "historical")
	attempt, envelope := claimInstruction(t, tr, mailbox)
	r, err := instructionRuntimeLab(t, e.AgentID).Invoke(t.Context(), e.AgentID, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.AcknowledgeInstruction(t.Context(), mailbox, attempt.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	old, err := c.InstructionResult(t.Context(), owner, op)
	if err != nil {
		t.Fatal(err)
	}
	decisions := restoreLosing(t, s, e.AgentID, 1, op)
	if decisions[op].Rerun != RerunQueued {
		t.Fatal("decision", decisions[op])
	}
	if body, err := c.InstructionResult(t.Context(), owner, op); err != nil || !bytes.Equal(body, old) {
		t.Fatal("the owner cannot read the result while lost", err)
	}
	attempt, _ = claimInstruction(t, tr, mailbox)
	if err = tr.AcknowledgeInstruction(t.Context(), mailbox, attempt.Token, capsuleprotocol.WorkingResult()); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := VMCaller{AgentID: e.AgentID, HostID: "local", Generation: p.Generation, VMID: fmt.Sprintf("%016x", p.Generation)}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, "local", "worker", p.Generation, vm.VMID); err != nil {
		t.Fatal(err)
	}
	done := capsuleprotocol.InvocationCompletion{OperationID: op, Outcome: "completed", Content: []capsuleprotocol.TextContent{{Type: "text", Text: "the rerun's answer"}}}
	if _, err = tr.CompleteInvocationFromVM(t.Context(), vm, "rerun-key", done); err != nil {
		t.Fatal("a later completion of a rerun", err)
	}
	if body, err := c.InstructionResult(t.Context(), owner, op); err != nil || !bytes.Contains(body, []byte("the rerun's answer")) {
		t.Fatal("the later completion did not replace the result", err)
	}
	var count int
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM transit_payloads WHERE kind='instruction_result' AND ref_id=$1", op).Scan(&count); err != nil || count != 1 {
		t.Fatal("results", count, err)
	}
}
