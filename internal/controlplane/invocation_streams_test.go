package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

// deltas are delta frames from seq first, one per text.
func deltas(first int64, texts ...string) []capsuleprotocol.OutputFrame {
	out := make([]capsuleprotocol.OutputFrame, len(texts))
	for i, text := range texts {
		out[i] = capsuleprotocol.OutputFrame{Type: "delta", Seq: first + int64(i), Text: text}
	}
	return out
}

// workingStream creates alice's invocation, has the agent answer working
// and opens its output stream from the current boot.
func (il *invocationLab) workingStream(t *testing.T, alice Principal, vm VMCaller, key string) string {
	t.Helper()
	inv, _, err := il.create(t, alice, key, "stream "+key)
	if err != nil {
		t.Fatal(err)
	}
	il.ackWorking(t, inv.ID)
	opened, err := il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 0)
	if err != nil || opened.Attempt != 1 || opened.LastSeq != 0 || opened.Closing != "" {
		t.Fatal("open", opened, err)
	}
	return inv.ID
}

func (il *invocationLab) appendTo(t *testing.T, vm VMCaller, op string, attempt int, frames []capsuleprotocol.OutputFrame) StreamAppend {
	t.Helper()
	r, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, attempt, frames, DefaultStreamLimits)
	if err != nil {
		t.Fatal("append", err)
	}
	return r
}

func (il *invocationLab) chunks(t *testing.T, op string) int {
	t.Helper()
	return il.count(t, "SELECT count(*) FROM invocation_stream_chunks WHERE operation_id=$1", op)
}

func (il *invocationLab) signal(t *testing.T, vm VMCaller, op string, attempt int) string {
	t.Helper()
	reason, err := il.s.OutputStreamSignal(t.Context(), vm, op, attempt)
	if err != nil {
		t.Fatal("signal", err)
	}
	return reason
}

// A stream opens only for a working invocation, from its agent's current
// boot, before its deadline (invocationCompletion.openStreamOnlyWhileWorkingTest).
func TestOpenStreamOnlyWhileWorking(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	inv, _, err := il.create(t, alice, "s1", "not delivered yet")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("opened before working", err)
	}
	il.ackWorking(t, inv.ID)
	stale := vm
	stale.Generation++
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), stale, inv.ID, 0); !errors.Is(err, ErrPlacement) {
		t.Fatal("opened from another boot", err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, "op_unknown", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("opened an unknown invocation", err)
	}
	for _, bad := range []struct {
		op      string
		attempt int
	}{{"", 0}, {strings.Repeat("o", 101), 0}, {inv.ID, -1}} {
		if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, bad.op, bad.attempt); !errors.Is(err, ErrInput) {
			t.Fatal("invalid opening", bad, err)
		}
	}
	opened, err := il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 0)
	if err != nil || opened != (StreamOpening{Attempt: 1}) {
		t.Fatal("open", opened, err)
	}
	// An attempt the platform never gave: the stream opens and closes at once.
	if opened, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 2); err != nil || opened.Closing != capsuleprotocol.StreamReset {
		t.Fatal("a stale attempt", opened, err)
	}
	il.appendTo(t, vm, inv.ID, 1, deltas(1, "one", "two"))
	// Opening again, naming its attempt, continues after the stored frames.
	if opened, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 1); err != nil || opened != (StreamOpening{Attempt: 1, LastSeq: 2}) {
		t.Fatal("open again", opened, err)
	}
	// Past its due time, before the worker expires it, then after.
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE owner_instructions SET working_since=clock_timestamp()-interval '2 seconds',
        result_due_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1`, inv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 0); !errors.Is(err, ErrExpired) {
		t.Fatal("opened past its due time", err)
	}
	if n, err := il.s.ExpireWorkingInvocations(t.Context(), nil, 10); err != nil || n != 1 {
		t.Fatal("expire", n, err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, inv.ID, 0); !errors.Is(err, ErrExpired) {
		t.Fatal("opened after it expired", err)
	}
	// After an outcome, and after a cancellation.
	done := il.workingStream(t, alice, vm, "s2")
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(done, "the answer")); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, done, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("opened after the outcome", err)
	}
	canceled := il.workingStream(t, alice, vm, "s3")
	if _, _, err = il.cancel(t, alice, canceled, "cancel"); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.OpenOutputStreamFromVM(t.Context(), vm, canceled, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("opened after a cancellation", err)
	}
}

// An outcome stops the chunks, although the stream is still open
// (invocationCompletion.noChunkAfterTheOutcomeTest). The deltas never become
// the result.
func TestNoChunkAfterTheOutcome(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "o1")
	if r := il.appendTo(t, vm, op, 1, deltas(1, "streamed text")); r.Stored != 1 || r.LastSeq != 1 || r.Reason != "" {
		t.Fatal("first chunk", r)
	}
	if reason := il.signal(t, vm, op, 1); reason != "" {
		t.Fatal("a working invocation's stream must stay open", reason)
	}
	if _, err := il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(op, "the filed answer")); err != nil {
		t.Fatal(err)
	}
	if reason := il.signal(t, vm, op, 1); reason != capsuleprotocol.StreamTerminal {
		t.Fatal("the outcome's signal", reason)
	}
	if r := il.appendTo(t, vm, op, 1, deltas(2, "after the outcome")); r.Stored != 0 || r.Reason != capsuleprotocol.StreamTerminal || r.LastSeq != 0 {
		t.Fatal("a chunk after the outcome", r)
	}
	if n := il.chunks(t, op); n != 1 {
		t.Fatal("chunks", n)
	}
	result, err := il.c.InstructionResult(t.Context(), alice, op)
	if err != nil || !bytes.Contains(result, []byte("the filed answer")) || bytes.Contains(result, []byte("streamed text")) {
		t.Fatal("the result is the filed answer only", err)
	}
}

// A cancellation stops the chunks too, and the stream learns it
// (invocationCompletion.cancelStopsTheChunksTest).
func TestCancelStopsTheChunks(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "c1")
	il.appendTo(t, vm, op, 1, deltas(1, "partial"))
	if _, _, err := il.cancel(t, alice, op, "cancel"); err != nil {
		t.Fatal(err)
	}
	if reason := il.signal(t, vm, op, 1); reason != capsuleprotocol.StreamCanceled {
		t.Fatal("the cancellation's signal", reason)
	}
	if r := il.appendTo(t, vm, op, 1, deltas(2, "more")); r.Stored != 0 || r.Reason != capsuleprotocol.StreamCanceled {
		t.Fatal("a chunk after the cancellation", r)
	}
	if v := mustGet(t, il, alice, op); v.State != "canceled" || v.ResultAvailable {
		t.Fatal("canceled view", v)
	}
	if il.chunks(t, op) != 1 {
		t.Fatal("chunks after the cancellation")
	}
	// The agent's deletion cancels too.
	other := il.workingStream(t, alice, vm, "c2")
	if _, err := il.c.Delete(t.Context(), il.owner, il.agent, "delete"); err != nil {
		t.Fatal(err)
	}
	if r := il.appendTo(t, vm, other, 1, deltas(1, "while deleted")); r.Stored != 0 || r.Reason == "" {
		t.Fatal("a chunk of an agent being deleted", r)
	}
}

// A rerun starts a new attempt: the old attempt's chunks go in its
// transaction, a stream of the old attempt stores nothing more, and an
// opening that names it closes at once
// (invocationCompletion.rerunDropsTheOldAttemptTest).
func TestRerunDropsTheOldAttempt(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "r1")
	il.appendTo(t, vm, op, 1, append(deltas(1, "old attempt"), capsuleprotocol.OutputFrame{Type: "step", Seq: 2, Step: "retrieval", State: "started"}))
	if il.chunks(t, op) != 1 || il.count(t, "SELECT count(*) FROM transit_payloads WHERE kind='stream_chunk'") != 1 {
		t.Fatal("the first attempt's chunk")
	}
	// A restore stops the VM first.
	if err := il.s.BeginPlacementStop(t.Context(), il.agent, "local", vm.Generation); err != nil {
		t.Fatal(err)
	}
	if err := il.s.ObservePlacementStopped(t.Context(), il.agent, "local", vm.Generation, false); err != nil {
		t.Fatal(err)
	}
	decisions := restoreLosing(t, il.s, il.agent, 1, op)
	if decisions[op].Rerun != RerunQueued {
		t.Fatal("rerun", decisions[op])
	}
	if n := il.count(t, "SELECT attempt FROM owner_instructions WHERE operation_id=$1", op); n != 2 {
		t.Fatal("attempt after the rerun", n)
	}
	if il.chunks(t, op) != 0 || il.count(t, "SELECT count(*) FROM transit_payloads WHERE kind='stream_chunk'") != 0 ||
		il.count(t, "SELECT count(*) FROM transit_parties p WHERE NOT EXISTS(SELECT 1 FROM transit_payloads WHERE id=p.payload_id)") != 0 {
		t.Fatal("the old attempt's chunks survived the rerun")
	}
	if il.count(t, "SELECT count(*) FROM invocation_streams WHERE operation_id=$1 AND attempt=2 AND last_seq=0 AND frames=0 AND bytes=0 AND NOT truncated", op) != 1 {
		t.Fatal("the stream's state did not start again")
	}
	// The rerun is delivered, and works again, on a new boot.
	current := il.vm(t)
	il.ackWorking(t, op)
	if reason := il.signal(t, current, op, 1); reason != capsuleprotocol.StreamReset {
		t.Fatal("the old attempt's signal", reason)
	}
	if r := il.appendTo(t, current, op, 1, deltas(3, "late")); r.Stored != 0 || r.Reason != capsuleprotocol.StreamReset {
		t.Fatal("a chunk of the old attempt", r)
	}
	if opened, err := il.tr.OpenOutputStreamFromVM(t.Context(), current, op, 1); err != nil || opened.Attempt != 2 || opened.Closing != capsuleprotocol.StreamReset {
		t.Fatal("an opening that names the old attempt", opened, err)
	}
	opened, err := il.tr.OpenOutputStreamFromVM(t.Context(), current, op, 0)
	if err != nil || opened != (StreamOpening{Attempt: 2}) {
		t.Fatal("the new attempt's stream", opened, err)
	}
	if r := il.appendTo(t, current, op, 2, deltas(1, "new attempt")); r.Stored != 1 || r.Reason != "" {
		t.Fatal("the new attempt's chunk", r)
	}
	if il.count(t, "SELECT count(*) FROM invocation_stream_chunks WHERE operation_id=$1 AND attempt=2", op) != 1 {
		t.Fatal("chunks of the new attempt")
	}
}

// A dead letter's replay starts an attempt too.
func TestReplayStartsANewAttempt(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	dead, _, err := il.create(t, alice, "d1", "dies")
	if err != nil {
		t.Fatal(err)
	}
	il.kill(t, dead.ID, false)
	addMember(t, il.tenantLab, il.owner, "admin", authorization.OrgAdmin)
	if _, _, err = il.replay(t, agentPrincipal(t, il.tenantLab, "admin", agentScopes), dead.ID, "k", 0); err != nil {
		t.Fatal(err)
	}
	if n := il.count(t, "SELECT attempt FROM owner_instructions WHERE operation_id=$1", dead.ID); n != 2 {
		t.Fatal("attempt after the replay", n)
	}
}

// Closing the stream is not an outcome: the invocation keeps working, and
// its deadline still ends it without a result
// (invocationCompletion.closingTheStreamIsNotAnOutcomeTest).
func TestClosingTheStreamIsNotAnOutcome(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "n1")
	il.appendTo(t, vm, op, 1, deltas(1, "all I had to say"))
	// The harness's close stores nothing: the stream simply ends.
	if v := mustGet(t, il, alice, op); v.State != "working" || v.ResultAvailable {
		t.Fatal("a closed stream changed the invocation", v)
	}
	if _, err := il.c.InstructionResult(t.Context(), alice, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("a closed stream made a result", err)
	}
	later := time.Now().Add(2 * time.Hour)
	if n, err := il.s.ExpireWorkingInvocations(t.Context(), &later, 10); err != nil || n != 1 {
		t.Fatal("expire", n, err)
	}
	if v := mustGet(t, il, alice, op); v.State != "failed" || v.ErrorCode != "work_timeout" || v.ResultAvailable {
		t.Fatal("expired view", v)
	}
	if reason := il.signal(t, vm, op, 1); reason != capsuleprotocol.StreamExpired {
		t.Fatal("the expiry's signal", reason)
	}
	if r := il.appendTo(t, vm, op, 1, deltas(2, "late")); r.Reason != capsuleprotocol.StreamExpired || il.chunks(t, op) != 1 {
		t.Fatal("a chunk after the expiry", r)
	}
}

// Chunks are sealed as results are: only the requester, while holding
// read_content on the agent, opens them; nobody else, not even another
// member with the same rights, and changing their bound party breaks them.
func TestStreamChunksAreReadableOnlyByTheirRequester(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	bob := il.invoker(t, "bob")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "p1")
	il.appendTo(t, vm, op, 1, deltas(1, "first <secret> & ", "words"))
	il.appendTo(t, vm, op, 1, []capsuleprotocol.OutputFrame{{Type: "step", Seq: 3, Step: "check", State: "done", Label: "Checking"}})
	// Nothing of the content is stored in clear.
	var cipher []byte
	if err := il.s.pool.QueryRow(t.Context(), `SELECT p.ciphertext FROM invocation_stream_chunks c JOIN transit_payloads p ON p.id=c.payload_id
        WHERE c.operation_id=$1 AND c.first_seq=1`, op).Scan(&cipher); err != nil || bytes.Contains(cipher, []byte("secret")) {
		t.Fatal("ciphertext", err)
	}
	view, err := il.c.ReadOutputStream(t.Context(), alice, op, 0, 64)
	if err != nil || view.Status != "RUNNING" || !view.Working || view.Attempt != 1 || view.LastSeq != 3 || view.Truncated || len(view.Chunks) != 2 {
		t.Fatal("the requester's read", view, err)
	}
	var frames []capsuleprotocol.OutputFrame
	if err = json.Unmarshal(view.Chunks[0].Frames, &frames); err != nil || !slices.Equal(frames, deltas(1, "first <secret> & ", "words")) ||
		!bytes.Contains(view.Chunks[0].Frames, []byte(`"first <secret> & "`)) {
		t.Fatal("the frames", string(view.Chunks[0].Frames), err)
	}
	if view, err = il.c.ReadOutputStream(t.Context(), alice, op, 2, 64); err != nil || len(view.Chunks) != 1 || view.Chunks[0].FirstSeq != 3 {
		t.Fatal("a read after a position", view, err)
	}
	if _, err = il.c.ReadOutputStream(t.Context(), bob, op, 0, 64); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member read the stream", err)
	}
	if _, err = il.c.ReadOutputStream(t.Context(), il.owner, op, 0, 64); !errors.Is(err, ErrNotFound) {
		t.Fatal("the organization's owner read the stream", err)
	}
	if _, err = il.c.ReadOutputStream(t.Context(), agentPrincipal(t, il.tenantLab, "alice", "org:read agent:read agent:invoke"), op, 0, 64); !errors.Is(err, ErrForbidden) {
		t.Fatal("a read without agent:content:read", err)
	}
	// Moving the chunk to bob does not open it to him: the seal binds alice.
	var payload string
	if err = il.s.pool.QueryRow(t.Context(), `SELECT payload_id FROM invocation_stream_chunks WHERE operation_id=$1 AND first_seq=1`, op).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE transit_parties SET owner_user_id=$2 WHERE payload_id=$1`, payload, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE platform_operations SET requested_by_principal_id=$2 WHERE id=$1`, op, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.ReadOutputStream(t.Context(), bob, op, 0, 64); !errors.Is(err, ErrTransitPayload) {
		t.Fatal("a chunk whose party changed opened", err)
	}
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE platform_operations SET requested_by_principal_id=$2 WHERE id=$1`, op, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.ReadOutputStream(t.Context(), alice, op, 0, 64); !errors.Is(err, ErrNotFound) {
		t.Fatal("a chunk no longer bound to alice opened for her", err)
	}
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE transit_parties SET owner_user_id=$2 WHERE payload_id=$1`, payload, alice.ID); err != nil {
		t.Fatal(err)
	}
	// Revoking alice's assignment closes it to her.
	assignments, err := il.a.ListAgentAssignments(t.Context(), il.owner, il.agent, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range assignments {
		if a.PrincipalID != nil && *a.PrincipalID == alice.ID {
			if _, err = il.a.RevokeAgentAssignment(t.Context(), il.owner, il.agent, a.ID, "revoke-alice"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = il.c.ReadOutputStream(t.Context(), alice, op, 0, 64); !errors.Is(err, ErrNotFound) {
		t.Fatal("a revoked requester read the stream", err)
	}
}

// Past the attempt's limits, the chunk stores what fits and the attempt is
// truncated: nothing more is stored, an opening closes at once, and the
// outcome is untouched. A gap in seq is refused.
func TestStreamLimitsTruncateTheAttempt(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "l1")
	limits := StreamLimits{MaxBytes: 1 << 20, MaxFrames: 64, Retention: time.Minute}
	if r, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, deltas(2, "gap"), limits); err != nil || r.Reason != capsuleprotocol.StreamInvalid || r.Stored != 0 {
		t.Fatal("a gap in seq", r, err)
	}
	if _, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, append(deltas(1, "a"), deltas(3, "c")...), limits); !errors.Is(err, ErrInput) {
		t.Fatal("frames that do not follow each other", err)
	}
	if _, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, deltas(1, "a"), StreamLimits{}); !errors.Is(err, ErrInput) {
		t.Fatal("limits out of bounds", err)
	}
	texts := make([]string, 70)
	for i := range texts {
		texts[i] = "x"
	}
	r, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, deltas(1, texts...), limits)
	if err != nil || r.Stored != 64 || r.LastSeq != 64 || r.Reason != capsuleprotocol.StreamTruncated {
		t.Fatal("frames past the limit", r, err)
	}
	if r, err = il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, deltas(65, "more"), limits); err != nil || r.Stored != 0 || r.Reason != capsuleprotocol.StreamTruncated {
		t.Fatal("a chunk after the truncation", r, err)
	}
	if opened, err := il.tr.OpenOutputStreamFromVM(t.Context(), vm, op, 1); err != nil || opened.Closing != capsuleprotocol.StreamTruncated || opened.LastSeq != 64 {
		t.Fatal("an opening after the truncation", opened, err)
	}
	if v := mustGet(t, il, alice, op); v.State != "working" {
		t.Fatal("the truncation touched the invocation", v)
	}
	if view, err := il.c.ReadOutputStream(t.Context(), alice, op, 0, 64); err != nil || !view.Truncated || view.LastSeq != 64 {
		t.Fatal("the truncation is not visible", view, err)
	}
	// The bytes' bound: a second large frame does not fit.
	big := il.workingStream(t, alice, vm, "l2")
	large := strings.Repeat("y", 40<<10)
	r, err = il.tr.AppendOutputStreamFromVM(t.Context(), vm, big, 1, deltas(1, large, large), StreamLimits{MaxBytes: 64 << 10, MaxFrames: 64, Retention: time.Minute})
	if err != nil || r.Stored != 1 || r.Reason != capsuleprotocol.StreamTruncated {
		t.Fatal("frames past the bytes' bound", r, err)
	}
	if il.count(t, "SELECT count(*) FROM invocation_streams WHERE operation_id=$1 AND truncated AND frames=1 AND bytes>40960", big) != 1 {
		t.Fatal("the state row of a truncated attempt")
	}
}

// The worker deletes the chunks 10 minutes after the outcome, at once for an
// agent being deleted, and never those of an invocation still working.
func TestStreamChunksArePurgedAfterTheirRetention(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	done := il.workingStream(t, alice, vm, "g1")
	il.appendTo(t, vm, done, 1, deltas(1, "one"))
	il.appendTo(t, vm, done, 1, deltas(2, "two"))
	working := il.workingStream(t, alice, vm, "g2")
	il.appendTo(t, vm, working, 1, deltas(1, "still working"))
	if _, err := il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(done, "answer")); err != nil {
		t.Fatal(err)
	}
	if n, err := il.s.PurgeStreamChunks(t.Context(), nil, DefaultStreamLimits.Retention, 100); err != nil || n != 0 {
		t.Fatal("purged before the retention", n, err)
	}
	later := time.Now().Add(DefaultStreamLimits.Retention + time.Minute)
	if n, err := il.s.PurgeStreamChunks(t.Context(), &later, DefaultStreamLimits.Retention, 1); err != nil || n != 1 {
		t.Fatal("bounded purge", n, err)
	}
	if n, err := il.s.PurgeStreamChunks(t.Context(), &later, DefaultStreamLimits.Retention, 100); err != nil || n != 1 {
		t.Fatal("purge", n, err)
	}
	if il.chunks(t, done) != 0 || il.chunks(t, working) != 1 {
		t.Fatal("chunks after the purge")
	}
	if il.count(t, "SELECT count(*) FROM transit_payloads WHERE kind='stream_chunk'") != 1 ||
		il.count(t, "SELECT count(*) FROM transit_parties p WHERE NOT EXISTS(SELECT 1 FROM transit_payloads WHERE id=p.payload_id)") != 0 {
		t.Fatal("payloads after the purge")
	}
	if _, err := il.c.InstructionResult(t.Context(), alice, done); err != nil {
		t.Fatal("the purge took the result", err)
	}
	if _, err := il.c.Delete(t.Context(), il.owner, il.agent, "delete"); err != nil {
		t.Fatal(err)
	}
	if n, err := il.s.PurgeStreamChunks(t.Context(), nil, DefaultStreamLimits.Retention, 100); err != nil || n != 1 || il.chunks(t, working) != 0 {
		t.Fatal("chunks of an agent being deleted", n, err)
	}
	if _, err := il.s.PurgeStreamChunks(t.Context(), nil, time.Minute, 0); !errors.Is(err, ErrInput) {
		t.Fatal("an unbounded purge", err)
	}
}

// Every change of a stream or of an outcome notifies its operation ID, and
// nothing else; a policy change notifies its organization's ID.
func TestStreamChangesNotifyTheirOperation(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	conn, err := pgx.ConnectConfig(t.Context(), il.s.pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err = conn.Exec(t.Context(), "LISTEN agentcapsule_invocation_stream"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), "LISTEN agentcapsule_organization_policy"); err != nil {
		t.Fatal(err)
	}
	// Other tests notify too, for their own operations: wait for ours.
	await := func(what, channel, payload string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				t.Fatal("no notification:", what, err)
			}
			if n.Channel == channel && n.Payload == payload {
				return
			}
		}
	}
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "w1")
	await("working", "agentcapsule_invocation_stream", op)
	il.appendTo(t, vm, op, 1, deltas(1, "a delta"))
	await("chunk", "agentcapsule_invocation_stream", op)
	r, err := il.tr.AppendOutputStreamFromVM(t.Context(), vm, op, 1, deltas(2, "x", "y"), StreamLimits{MaxBytes: 1 << 20, MaxFrames: 64, Retention: time.Minute})
	if err != nil || r.Reason != "" {
		t.Fatal(r, err)
	}
	await("second chunk", "agentcapsule_invocation_stream", op)
	if _, err = il.tr.CompleteInvocationFromVM(t.Context(), vm, "done", answer(op, "answer")); err != nil {
		t.Fatal(err)
	}
	await("outcome", "agentcapsule_invocation_stream", op)
	truncated := il.workingStream(t, alice, vm, "w2")
	await("working", "agentcapsule_invocation_stream", truncated)
	texts := make([]string, 65)
	for i := range texts {
		texts[i] = "t"
	}
	if r, err = il.tr.AppendOutputStreamFromVM(t.Context(), vm, truncated, 1, deltas(1, texts...), StreamLimits{MaxBytes: 1 << 20, MaxFrames: 64, Retention: time.Minute}); err != nil || r.Reason != capsuleprotocol.StreamTruncated {
		t.Fatal(r, err)
	}
	await("truncation", "agentcapsule_invocation_stream", truncated)
	if _, err = il.a.SetOrganizationCapabilities(t.Context(), il.owner, "policy", CapabilityPolicy{Allowed: capability.Known()}); err != nil {
		t.Fatal(err)
	}
	await("policy", "agentcapsule_organization_policy", il.owner.TenantID)
}

// stream.output is a capability like the others: requested by a manifest
// without the field, shown in the catalog, refused when a policy written
// before it does not list it, and accepted by the database's policies.
func TestStreamOutputIsACapability(t *testing.T) {
	il := newInvocationLab(t)
	vm := il.vm(t)
	c, err := il.c.AgentCapabilities(t.Context(), il.owner, il.agent)
	if err != nil || !slices.Contains(c.Requested, capability.StreamOutput) || !slices.Contains(c.Effective, capability.StreamOutput) {
		t.Fatal("catalog", c, err)
	}
	if err = il.s.RequireCapabilityFromVM(t.Context(), vm, capability.StreamOutput); err != nil {
		t.Fatal("stream.output refused by default", err)
	}
	// A policy written before stream.output does not list it.
	if _, err = il.a.SetOrganizationCapabilities(t.Context(), il.owner, "older", CapabilityPolicy{Allowed: []string{capability.LLMInvoke, capability.AgentsDelegate, capability.AgentsDiscover}}); err != nil {
		t.Fatal(err)
	}
	if err = il.s.RequireCapabilityFromVM(t.Context(), vm, capability.StreamOutput); !errors.Is(err, ErrCapability) {
		t.Fatal("stream.output granted by a policy that does not list it", err)
	}
	if _, err = il.a.SetOrganizationCapabilities(t.Context(), il.owner, "newer", CapabilityPolicy{Allowed: capability.Known()}); err != nil {
		t.Fatal("the policy's constraint refuses stream.output", err)
	}
	if _, err = il.c.SetAgentCapabilities(t.Context(), il.owner, il.agent, "agent", CapabilityPolicy{Allowed: []string{capability.StreamOutput}}); err != nil {
		t.Fatal("the agent policy's constraint refuses stream.output", err)
	}
	if err = il.s.RequireCapabilityFromVM(t.Context(), vm, capability.StreamOutput); err != nil {
		t.Fatal("stream.output refused once allowed", err)
	}
	if _, err = il.s.pool.Exec(t.Context(), `UPDATE harness_releases SET capabilities=ARRAY['stream.output'] WHERE id=(SELECT release_id FROM agent_specs WHERE agent_id=$1)`, il.agent); err != nil {
		t.Fatal("the release's constraint refuses stream.output", err)
	}
}
