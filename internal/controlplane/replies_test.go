package controlplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func completedReply() Reply {
	return Reply{Outcome: "completed", PayloadRef: "encrypted-reply-reference", PayloadHash: sha256.Sum256([]byte("private reply"))}
}

func processingRequest(t *testing.T, mode string) (*Store, string, string, *vmruntime.MockRuntime, Receipt) {
	t.Helper()
	s, dsn := freshStore(t, mode, 5)
	root := t.TempDir()
	m := mockStores(t, root, "a", "b", "c")
	m.SetHandler(recordDelivery)
	r, err := s.Submit(t.Context(), "a", "request", submission())
	if err != nil {
		t.Fatal(err)
	}
	if mode == "manual" {
		if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DispatchOne(t.Context(), "b", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r.RequestID, "PROCESSING")
	return s, dsn, root, m, r
}

func TestReplyAtomicConcurrentIdempotencyAndNotification(t *testing.T) {
	s, _, root, m, r := processingRequest(t, "manual")
	input := completedReply()
	if _, err := s.ReplyToRequest(t.Context(), "a", r.RequestID, "unauthorized", input); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "not-auto", Reply{Outcome: "declined"}); !errors.Is(err, ErrTransition) {
		t.Fatalf("manual harness declined after acceptance: %v", err)
	}
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_reply_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected reply outbox failure'; END $$;
        CREATE TRIGGER reject_reply_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_reply_outbox()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", input); err == nil {
		t.Fatal("partial reply acknowledged")
	}
	assertRequestState(t, s, r.RequestID, "PROCESSING")
	var refs, keys int
	if err := s.pool.QueryRow(t.Context(), `SELECT
        (SELECT count(*) FROM agent_requests WHERE reply_ref<>''),
        (SELECT count(*) FROM idempotency_keys WHERE operation LIKE 'reply/%')`).Scan(&refs, &keys); err != nil || refs != 0 || keys != 0 {
		t.Fatalf("reply escaped rollback: refs=%d keys=%d err=%v", refs, keys, err)
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_reply_outbox ON outbox"); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 12)
	for range 12 {
		go func() { _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", input); errs <- err }()
	}
	for range 12 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	assertRequestState(t, s, r.RequestID, "REPLIED")
	changed := input
	changed.PayloadHash = sha256.Sum256([]byte("different reply"))
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("different body reused key: %v", err)
	}
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "second-final", changed); !errors.Is(err, ErrTransition) {
		t.Fatalf("second reply replaced first: %v", err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_requests SET reply_ref='changed' WHERE id=$1", r.RequestID); err == nil {
		t.Fatal("database allowed terminal payload mutation")
	}
	id := mailboxFor(t, s, r.RequestID, "reply")
	lost := errors.New("reply ACK lost")
	m.SetSendHook(func(stage, target string, event harnessstore.Event) error {
		if target == "a" {
			var body struct{ PayloadRef, PayloadHash, Status string }
			if err := json.Unmarshal(event.Body, &body); err != nil || body.PayloadRef != input.PayloadRef || body.PayloadHash != hex.EncodeToString(input.PayloadHash[:]) || body.Status != "REPLIED" {
				return fmt.Errorf("invalid reply envelope: %+v %v", body, err)
			}
			if stage == "after_commit" {
				return lost
			}
		}
		return nil
	})
	if err := s.DispatchOne(t.Context(), "a", time.Minute, m); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	expireLease(t, s, id)
	m.SetSendHook(nil)
	if err := s.DispatchOne(t.Context(), "a", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	if got := received(t, root, "a"); fmt.Sprint(got) != fmt.Sprint([]string{id}) {
		t.Fatalf("duplicate reply effect: %v", got)
	}
	var notified bool
	if err := s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", r.RequestID).Scan(&notified); err != nil || !notified {
		t.Fatalf("sender was not notified: %v", err)
	}
}

func TestDeclineOwnerAndAutoRules(t *testing.T) {
	t.Run("owner-before-acceptance", func(t *testing.T) {
		s, _ := freshStore(t, "manual", 3)
		r, err := s.Submit(t.Context(), "a", "request", submission())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeclineRequest(t.Context(), "user-a", r.RequestID, "wrong-owner"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := s.DeclineRequest(t.Context(), "user-b", r.RequestID, "decline"); err != nil {
			t.Fatal(err)
		}
		if receipt, err := s.DeclineRequest(t.Context(), "user-b", r.RequestID, "decline"); err != nil || !receipt.Replayed {
			t.Fatalf("decline replay=%+v %v", receipt, err)
		}
		if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "late"); !errors.Is(err, ErrTransition) {
			t.Fatal(err)
		}
		assertRequestState(t, s, r.RequestID, "DECLINED")
		if count(t, s, "agent_mailboxes") != 1 {
			t.Fatal("decline queued recipient work or duplicated sender status")
		}
	})
	t.Run("auto-decline-after-reception", func(t *testing.T) {
		s, _, _, m, r := processingRequest(t, "auto")
		if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "leak", Reply{Outcome: "declined", PayloadRef: "private-reason"}); err == nil {
			t.Fatal("private content attached to decline")
		}
		if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "decline", Reply{Outcome: "declined"}); err != nil {
			t.Fatal(err)
		}
		assertRequestState(t, s, r.RequestID, "DECLINED")
		if err := s.DispatchOne(t.Context(), "a", time.Minute, m); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReplyRacesCancellation(t *testing.T) {
	s, _, _, m, r := processingRequest(t, "auto")
	start := make(chan struct{})
	replied, canceled := make(chan error, 1), make(chan error, 1)
	go func() {
		<-start
		_, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", completedReply())
		replied <- err
	}()
	go func() { <-start; canceled <- s.RequestCancellation(t.Context(), "user-a", r.RequestID) }()
	close(start)
	replyErr, cancelErr := <-replied, <-canceled
	if replyErr == nil {
		if !errors.Is(cancelErr, ErrTransition) {
			t.Fatalf("cancellation changed completed reply: %v", cancelErr)
		}
		assertRequestState(t, s, r.RequestID, "REPLIED")
	} else {
		if !errors.Is(replyErr, ErrTransition) || cancelErr != nil {
			t.Fatalf("reply=%v cancel=%v", replyErr, cancelErr)
		}
		if err := s.ReconcileRequestClosure(t.Context(), r.RequestID, m); err != nil {
			t.Fatal(err)
		}
		assertRequestState(t, s, r.RequestID, "CANCELED")
	}
	if count(t, s, "agent_mailboxes") != 2 {
		t.Fatal("expected one request and exactly one final notification")
	}
}

func TestDeletingReplyAuthorPreservesContentFreeFinalStatus(t *testing.T) {
	s, _, _, m, r := processingRequest(t, "auto")
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", completedReply()); err != nil {
		t.Fatal(err)
	}
	id := mailboxFor(t, s, r.RequestID, "reply")
	a, err := s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeDispatch(t.Context(), id, a.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "b", m); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r.RequestID, "REPLIED")
	if _, err := m.Send(t.Context(), "a", a.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("revoked reply content delivered: %v", err)
	}
	m.SetSendHook(func(stage, _ string, event harnessstore.Event) error {
		var body struct{ PayloadRef, PayloadHash, Status, Reason string }
		if err := json.Unmarshal(event.Body, &body); err != nil || body.PayloadRef != "" || body.PayloadHash != "" || body.Status != "REPLIED" || body.Reason != "content_revoked" {
			return fmt.Errorf("unsafe fallback status: %+v %v", body, err)
		}
		return nil
	})
	if err := s.DispatchOne(t.Context(), "a", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	var notified bool
	if err := s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", r.RequestID).Scan(&notified); err != nil || !notified {
		t.Fatalf("live sender lost final status: %v", err)
	}
}

// SQLite may have committed the private reply while PostgreSQL still considers
// its mailbox pending. Revocation must fence that envelope and allocate a fresh
// identity for the content-free status, including after a rolled-back tombstone.
func TestDeletingReplyAuthorAfterLocalCommitBeforeACK(t *testing.T) {
	s, _, root, m, r := processingRequest(t, "auto")
	if _, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", completedReply()); err != nil {
		t.Fatal(err)
	}
	replyID := mailboxFor(t, s, r.RequestID, "reply")
	a, err := s.ClaimDelivery(t.Context(), replyID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeDispatch(t.Context(), replyID, a.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(t.Context(), "a", a.Envelope); err != nil {
		t.Fatal(err)
	}
	// Deliberately omit the SQL ACK after the committed local effect.
	if got := received(t, root, "a"); fmt.Sprint(got) != fmt.Sprint([]string{replyID}) {
		t.Fatalf("reply was not applied: %v", got)
	}
	if err := s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_fallback_status() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.kind='status' THEN RAISE EXCEPTION 'injected fallback failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_fallback_status BEFORE INSERT ON agent_mailboxes FOR EACH ROW EXECUTE FUNCTION reject_fallback_status()`); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "b", m); err == nil {
		t.Fatal("tombstone committed without its replacement status")
	}
	var phase, oldState string
	if err := s.pool.QueryRow(t.Context(), `SELECT a.phase,m.delivery_state FROM agents a,agent_mailboxes m WHERE a.id='b' AND m.id=$1`, replyID).Scan(&phase, &oldState); err != nil || phase != "QUIESCING" || oldState != "PENDING" {
		t.Fatalf("partial tombstone: phase=%s reply=%s err=%v", phase, oldState, err)
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_fallback_status ON agent_mailboxes"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.ReconcileRevocation(t.Context(), "b", m); err != nil {
			t.Fatal(err)
		}
	}
	assertRequestState(t, s, r.RequestID, "REPLIED")
	if _, err := m.Send(t.Context(), "a", a.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("revoked duplicate replayed its cached private result: %v", err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), replyID, a.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("late reply ACK changed the revoked mailbox: %v", err)
	}
	statusID := mailboxFor(t, s, r.RequestID, "status")
	if statusID == replyID {
		t.Fatal("fallback reused the already committed envelope identity")
	}
	m.SetSendHook(func(_ string, target string, event harnessstore.Event) error {
		var body struct{ PayloadRef, PayloadHash, Status, Reason string }
		if err := json.Unmarshal(event.Body, &body); err != nil || target != "a" || event.ID != statusID || body.PayloadRef != "" || body.PayloadHash != "" || body.Status != "REPLIED" || body.Reason != "content_revoked" {
			return fmt.Errorf("unsafe replacement status: %+v %v", body, err)
		}
		return nil
	})
	if err := s.DispatchOne(t.Context(), "a", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	if got := received(t, root, "a"); fmt.Sprint(got) != fmt.Sprint([]string{replyID, statusID}) {
		t.Fatalf("expected one effect per distinct envelope: %v", got)
	}
	var notified bool
	var statuses, pending int
	if err := s.pool.QueryRow(t.Context(), `SELECT sender_notified,
        (SELECT count(*) FROM agent_mailboxes WHERE ref_id=$1 AND kind='status'),
        (SELECT count(*) FROM outbox o JOIN agent_mailboxes m ON m.id=o.mailbox_id WHERE m.ref_id=$1)
        FROM agent_requests WHERE id=$1`, r.RequestID).Scan(&notified, &statuses, &pending); err != nil || !notified || statuses != 1 || pending != 0 {
		t.Fatalf("fallback completion: notified=%v statuses=%d pending=%d err=%v", notified, statuses, pending, err)
	}
}

func TestReplyAPIProcessCrash(t *testing.T) {
	s, dsn, _, m, r := processingRequest(t, "auto")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplyAPIChild$")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_REPLY_CHILD=1", "AGENTCAPSULE_REPLY_DSN="+dsn, "AGENTCAPSULE_REPLY_ID="+r.RequestID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "REPLY_COMMITTED\n" {
		t.Fatalf("reply child=%q %v", line, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
	receipt, err := s.ReplyToRequest(t.Context(), "b", r.RequestID, "reply", completedReply())
	if err != nil || !receipt.Replayed {
		t.Fatalf("reply not recoverable: %+v %v", receipt, err)
	}
	if count(t, s, "agent_mailboxes") != 2 {
		t.Fatal("duplicate response after API crash")
	}
	if err := s.DispatchOne(t.Context(), "a", time.Minute, m); err != nil {
		t.Fatal(err)
	}
}

func TestReplyAPIChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_REPLY_CHILD") == "" {
		return
	}
	s, err := Open(t.Context(), os.Getenv("AGENTCAPSULE_REPLY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ReplyToRequest(t.Context(), "b", os.Getenv("AGENTCAPSULE_REPLY_ID"), "reply", completedReply()); err != nil {
		t.Fatal(err)
	}
	fmt.Println("REPLY_COMMITTED")
	for {
		time.Sleep(time.Hour)
	}
}
