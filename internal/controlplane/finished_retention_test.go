package controlplane

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// pastRetention is a database clock past the shortest retention.
func pastRetention() *time.Time {
	t := time.Now().Add(MinFinishedRetention + 24*time.Hour)
	return &t
}

func (il *invocationLab) rows(t *testing.T, query string, args ...any) int {
	t.Helper()
	return il.count(t, query, args...)
}

// Finished invocations and lifecycle commands whose content is gone are
// deleted past their retention, with their instruction, mailbox entry,
// content tombstones and mandate (P-04). Nothing goes before the retention;
// an unread result is never purged, so its invocation stays (ADR 007, 022);
// nor does one an audit event names (ADR 014).
func TestFinishedInvocationsGoAfterTheirRetention(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	alice := il.invoker(t, "alice")
	invocation := func(key string) string {
		t.Helper()
		v, _, err := il.create(t, alice, key, "finished "+key)
		if err != nil {
			t.Fatal(err)
		}
		il.complete(t, v.ID)
		return v.ID
	}
	read, unread, replayed := invocation("read"), invocation("unread"), invocation("replayed")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := il.s.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(sql, err)
		}
	}
	// The contents' own retention has passed: the inputs and the result read.
	for _, op := range []string{read, unread, replayed} {
		exec(`UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
            WHERE id=(SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1)`, op)
	}
	for _, op := range []string{read, replayed} {
		exec(`UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
            WHERE id=(SELECT result_payload_id FROM owner_instructions WHERE operation_id=$1)`, op)
	}
	exec(`INSERT INTO instruction_replays(id,operation_id,agent_id,tenant_id,actor_kind,request_key,previous_reason,expires_at)
        SELECT $1,o.id,o.agent_id,a.tenant_id,'operator','replay','expired',clock_timestamp() FROM platform_operations o JOIN agents a ON a.id=o.agent_id WHERE o.id=$2`, newID("replay"), replayed)
	il.wake(t, il.agent, "finished-wake")
	exec(`UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE agent_id=$1 AND kind='wake'`, il.agent)
	var mandate, inputPayload string
	if err := il.s.pool.QueryRow(ctx, "SELECT coalesce(mandate_id,''),input_payload_id FROM owner_instructions WHERE operation_id=$1", read).Scan(&mandate, &inputPayload); err != nil {
		t.Fatal(err)
	}
	if n, err := il.s.PurgeFinished(ctx, "local", nil, MinFinishedRetention, 100); err != nil || n.Total() != 0 {
		t.Fatal("a purge before the retention", n, err)
	}
	if n, err := il.s.PurgeFinished(ctx, "other-host", pastRetention(), MinFinishedRetention, 100); err != nil || n.Total() != 0 {
		t.Fatal("another host's purge", n, err)
	}
	n, err := il.s.PurgeFinished(ctx, "local", pastRetention(), MinFinishedRetention, 100)
	if err != nil || n.Invocations != 1 || n.Lifecycle != 1 {
		t.Fatal("the purge past the retention", n, err)
	}
	for what, count := range map[string]int{
		"operation":   il.rows(t, "SELECT count(*) FROM platform_operations WHERE id=$1", read),
		"instruction": il.rows(t, "SELECT count(*) FROM owner_instructions WHERE operation_id=$1", read),
		"mailbox":     il.rows(t, "SELECT count(*) FROM agent_mailboxes WHERE instruction_id=$1", read),
		"payloads":    il.rows(t, "SELECT count(*) FROM transit_payloads WHERE ref_id=$1", read),
		"parties":     il.rows(t, "SELECT count(*) FROM transit_parties WHERE payload_id=$1", inputPayload),
		"mandate":     il.rows(t, "SELECT count(*) FROM mandates WHERE id=$1", mandate),
		"wake":        il.rows(t, "SELECT count(*) FROM platform_operations WHERE agent_id=$1 AND kind='wake'", il.agent),
	} {
		if count != 0 {
			t.Errorf("%s left after the purge: %d", what, count)
		}
	}
	for what, op := range map[string]string{"an unread result's invocation": unread, "an audited replay's invocation": replayed} {
		if il.rows(t, "SELECT count(*) FROM platform_operations WHERE id=$1", op) != 1 {
			t.Errorf("%s was purged", what)
		}
	}
	if _, err = il.c.InstructionResult(ctx, alice, unread); err != nil {
		t.Fatal("the unread result is gone", err)
	}
	if _, err = il.c.GetInvocation(ctx, alice, read); !errors.Is(err, ErrNotFound) {
		t.Fatal("a purged invocation", err)
	}
	if _, err = il.s.PurgeFinished(ctx, "local", nil, MinFinishedRetention-time.Hour, 100); !errors.Is(err, ErrInput) {
		t.Fatal("a retention under the minimum", err)
	}
}

// Finished requests between agents go after their retention with their
// idempotency key, mailbox entries and closure (P-04), once nothing is left
// to deliver; the revocation of their subject stays, as it is permanent. One
// an owner's message is bound to stays: the message's receipt is permanent.
func TestFinishedRequestsGoAfterTheirRetention(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(sql, err)
		}
	}
	exec(`INSERT INTO agent_placements(agent_id,host_id) VALUES('a','local'),('b','local')`)
	m := mockStores(t, t.TempDir(), "a", "b")
	m.SetHandler(recordDelivery)
	closed := func(key string) string {
		t.Helper()
		r, err := s.Submit(ctx, "a", key, submission())
		if err != nil {
			t.Fatal(err)
		}
		if err = s.RequestCancellation(ctx, "user-a", r.RequestID); err != nil {
			t.Fatal(err)
		}
		if err = s.ReconcileRequestClosure(ctx, r.RequestID, m); err != nil {
			t.Fatal(err)
		}
		return r.RequestID
	}
	gone, bound := closed("gone"), closed("bound")
	exec(`INSERT INTO transit_keys(id,key_hash) VALUES('k',$1)`, make([]byte, 32))
	hash := sha256.Sum256([]byte("summary"))
	exec(`INSERT INTO transit_payloads(id,kind,ref_id,key_id,content_hash,ciphertext,purged_at) VALUES('pay-summary','owner_message','msg-1','k',$1,NULL,clock_timestamp())`, hash[:])
	exec(`INSERT INTO owner_messages(id,agent_id,owner_user_id,request_id,payload_id,idempotency_key,body_hash) VALUES('msg-1','a','user-a',$1,'pay-summary','summary',$2)`, bound, hash[:])
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := s.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("SELECT count(*) FROM idempotency_keys WHERE response_ref=$1", gone) != 1 || count("SELECT count(*) FROM request_closures WHERE request_id=$1", gone) != 1 {
		t.Fatal("no key or closure to purge")
	}
	// The cancellation's status to the sender is still queued: a delivery
	// still to make keeps its request.
	if n, err := s.PurgeFinished(ctx, "local", pastRetention(), MinFinishedRetention, 100); err != nil || n.Requests != 0 {
		t.Fatal("a request with a queued delivery was purged", n, err)
	}
	exec(`UPDATE agent_mailboxes SET delivery_state='DELIVERED' WHERE kind='status' AND ref_id IN ($1,$2)`, gone, bound)
	n, err := s.PurgeFinished(ctx, "local", pastRetention(), MinFinishedRetention, 100)
	if err != nil || n.Requests != 1 {
		t.Fatal("the purge past the retention", n, err)
	}
	for what, left := range map[string]int{
		"request":         count("SELECT count(*) FROM agent_requests WHERE id=$1", gone),
		"idempotency key": count("SELECT count(*) FROM idempotency_keys WHERE response_ref=$1", gone),
		"mailbox":         count("SELECT count(*) FROM agent_mailboxes WHERE ref_id=$1", gone),
		"closure":         count("SELECT count(*) FROM request_closures WHERE request_id=$1", gone),
		"closure targets": count("SELECT count(*) FROM request_closure_targets WHERE request_id=$1", gone),
	} {
		if left != 0 {
			t.Errorf("%s left after the purge: %d", what, left)
		}
	}
	if count("SELECT count(*) FROM revocation_catalogue WHERE subject=$1", "request/"+gone) != 1 {
		t.Fatal("the purge took a revocation")
	}
	if count("SELECT count(*) FROM agent_requests WHERE id=$1", bound) != 1 {
		t.Fatal("a request an owner's message is bound to was purged")
	}
}
