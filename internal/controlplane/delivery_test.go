package controlplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func recordDelivery(ctx context.Context, _ string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
	var body struct{ Sequence int64 }
	if err := json.Unmarshal(event.Body, &body); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS received (position INTEGER PRIMARY KEY, event_id TEXT NOT NULL, seq INTEGER NOT NULL)"); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO received(event_id,seq) VALUES (?,?)", event.ID, body.Sequence); err != nil {
		return nil, err
	}
	return []byte("durable"), nil
}

func received(t *testing.T, root, target string) []string {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(root, fmt.Sprintf("%x", sha256.Sum256([]byte(target))), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(t.Context(), "SELECT event_id FROM received ORDER BY position")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func mailboxFor(t *testing.T, s *Store, requestID, kind string) string {
	t.Helper()
	var id string
	if err := s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2", requestID, kind).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func expireLease(t *testing.T, s *Store, id string) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
}

func assertRequestState(t *testing.T, s *Store, id, want string) {
	t.Helper()
	var got string
	if err := s.pool.QueryRow(t.Context(), "SELECT state FROM agent_requests WHERE id=$1", id).Scan(&got); err != nil || got != want {
		t.Fatalf("request state=%s want=%s error=%v", got, want, err)
	}
}

func TestDeliveryConcurrentClaimsFIFOAndLostAck(t *testing.T) {
	s, _ := freshStore(t, "auto", 4)
	root := t.TempDir()
	m := mockStores(t, root, "a", "b", "c")
	m.SetHandler(recordDelivery)
	r1, err := s.Submit(t.Context(), "a", "first", submission())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Submit(t.Context(), "a", "second", submission())
	if err != nil {
		t.Fatal(err)
	}
	first, second := mailboxFor(t, s, r1.RequestID, "request"), mailboxFor(t, s, r2.RequestID, "request")
	if _, err := s.ClaimDelivery(t.Context(), second, time.Minute); !errors.Is(err, ErrNotHead) {
		t.Fatalf("FIFO bypass: %v", err)
	}
	type result struct {
		a DeliveryAttempt
		e error
	}
	results := make(chan result, 12)
	for range 12 {
		go func() { a, e := s.ClaimDelivery(t.Context(), first, time.Minute); results <- result{a, e} }()
	}
	var original DeliveryAttempt
	winners := 0
	for range 12 {
		r := <-results
		if r.e == nil {
			original, winners = r.a, winners+1
		} else if !errors.Is(r.e, ErrDeliveryBusy) {
			t.Fatal(r.e)
		}
	}
	if winners != 1 {
		t.Fatalf("%d concurrent lease owners", winners)
	}
	if err := s.AuthorizeDispatch(t.Context(), first, original.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(t.Context(), "b", original.Envelope); err != nil {
		t.Fatal(err)
	}
	// Lose the ACK. A second claim cannot overtake the still-live lease.
	if err := s.DispatchOne(t.Context(), "b", time.Minute, m); !errors.Is(err, ErrDeliveryBusy) {
		t.Fatal(err)
	}
	expireLease(t, s, first)
	retry, err := s.ClaimDelivery(t.Context(), first, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), first, original.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale ACK accepted: %v", err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), first, retry.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("previous dispatch permission reused by a new lease: %v", err)
	}
	if err := s.AuthorizeDispatch(t.Context(), first, retry.Token); err != nil {
		t.Fatal(err)
	}
	if receipt, err := m.Send(t.Context(), "b", retry.Envelope); err != nil || !receipt.Replayed {
		t.Fatalf("replay=%v err=%v", receipt.Replayed, err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), first, retry.Token); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r1.RequestID, "PROCESSING")
	if err := s.DispatchOne(t.Context(), "b", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	if got := received(t, root, "b"); fmt.Sprint(got) != fmt.Sprint([]string{first, second}) {
		t.Fatalf("effect log=%v", got)
	}
}

func TestExhaustedDeliveryFencesLateWorkerAndNotifiesSender(t *testing.T) {
	s, _ := freshStore(t, "auto", 4)
	root := t.TempDir()
	m := mockStores(t, root, "a", "b", "c")
	m.SetHandler(recordDelivery)
	r1, err := s.Submit(t.Context(), "a", "first", submission())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Submit(t.Context(), "a", "second", submission())
	if err != nil {
		t.Fatal(err)
	}
	first, second := mailboxFor(t, s, r1.RequestID, "request"), mailboxFor(t, s, r2.RequestID, "request")
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET attempt_limit=2 WHERE id=$1", first); err != nil {
		t.Fatal(err)
	}
	stale, err := s.ClaimDelivery(t.Context(), first, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeDispatch(t.Context(), first, stale.Token); err != nil {
		t.Fatal(err)
	}
	// Both attempts are delayed before reaching SQLite; their workers might still run.
	expireLease(t, s, first)
	if _, err := s.ClaimDelivery(t.Context(), first, time.Minute); err != nil {
		t.Fatal(err)
	}
	expireLease(t, s, first)
	if err := s.DispatchOne(t.Context(), "b", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r1.RequestID, "FAILED")
	var reason string
	if err := s.pool.QueryRow(t.Context(), "SELECT reason FROM request_closures WHERE request_id=$1", r1.RequestID).Scan(&reason); err != nil || reason != "delivery_outcome_unknown" {
		t.Fatalf("uncertain outcome misreported: %s %v", reason, err)
	}
	if err := s.DispatchOne(t.Context(), "b", time.Minute, m); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(t.Context(), "b", stale.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("old RPC applied after the next event: %v", err)
	}
	if got := received(t, root, "b"); fmt.Sprint(got) != fmt.Sprint([]string{second}) {
		t.Fatalf("effects=%v", got)
	}
	notice := mailboxFor(t, s, r1.RequestID, "status")
	statusAttempt, err := s.ClaimDelivery(t.Context(), notice, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var body struct{ PayloadRef, Status string }
	if err := json.Unmarshal(statusAttempt.Envelope.Body, &body); err != nil || body.PayloadRef != "" || body.Status != "FAILED" {
		t.Fatalf("unsafe notification: %+v %v", body, err)
	}
	if err := s.AuthorizeDispatch(t.Context(), notice, statusAttempt.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(t.Context(), "a", statusAttempt.Envelope); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), notice, statusAttempt.Token); err != nil {
		t.Fatal(err)
	}
}

func TestExpirationWaitsForEffectAndAtomicNotification(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	r, err := s.Submit(t.Context(), "a", "expiring", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestExpiration(t.Context(), r.RequestID); !errors.Is(err, ErrTransition) {
		t.Fatalf("early expiration: %v", err)
	}
	id := mailboxFor(t, s, r.RequestID, "request")
	attempt, err := s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeDispatch(t.Context(), id, attempt.Token); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		value, err := recordDelivery(ctx, target, event, tx)
		close(entered)
		<-release
		return value, err
	})
	sent := make(chan error, 1)
	go func() { _, err := m.Send(t.Context(), "b", attempt.Envelope); sent <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("effect did not start")
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestExpiration(t.Context(), r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), id, attempt.Token); !errors.Is(err, ErrClosurePending) {
		t.Fatalf("reception escaped closure intent: %v", err)
	}
	fencing := make(chan struct{})
	m.SetFenceHook(func(stage, target, subject string) error {
		if stage == "before" && target == "b" && subject == "request/"+r.RequestID {
			close(fencing)
		}
		return nil
	})
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_final_notice() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected final notice failure'; END $$;
        CREATE TRIGGER reject_final_notice BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_final_notice()`); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.ReconcileRequestClosure(t.Context(), r.RequestID, m) }()
	select {
	case <-fencing:
	case <-time.After(5 * time.Second):
		t.Fatal("request fence did not start")
	}
	select {
	case err := <-closed:
		t.Fatalf("closure overtook active effect: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	assertRequestState(t, s, r.RequestID, "DELIVERING")
	unblock()
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err == nil {
		t.Fatal("notification failure was acknowledged")
	}
	assertRequestState(t, s, r.RequestID, "DELIVERING")
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_final_notice ON outbox"); err != nil {
		t.Fatal(err)
	}
	m.SetFenceHook(nil)
	if err := s.ReconcileRequestClosure(t.Context(), r.RequestID, m); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r.RequestID, "EXPIRED")
	if _, err := m.Send(t.Context(), "b", attempt.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal(err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), id, attempt.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
}

func TestCancellationIntentBlocksConsentAndSurvivesDeletion(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	r, err := s.Submit(t.Context(), "a", "pending", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestCancellation(t.Context(), "user-b", r.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.RequestCancellation(t.Context(), "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "late-accept"); !errors.Is(err, ErrTransition) {
		t.Fatalf("accept escaped intent: %v", err)
	}
	if err := s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "b", m); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRequestClosure(t.Context(), r.RequestID, m); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, s, r.RequestID, "CANCELED")
	if count(t, s, "agent_mailboxes") != 1 {
		t.Fatal("duplicate terminal notifications")
	}
}

func TestDeliveryWorkerProcessCrash(t *testing.T) {
	for _, point := range []string{"before-commit", "after-commit"} {
		t.Run(point, func(t *testing.T) {
			s, dsn := freshStore(t, "auto", 3)
			root := t.TempDir()
			r, err := s.Submit(t.Context(), "a", "crash", submission())
			if err != nil {
				t.Fatal(err)
			}
			id := mailboxFor(t, s, r.RequestID, "request")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeliveryWorkerChild$")
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_DELIVERY_CHILD="+point, "AGENTCAPSULE_DELIVERY_DSN="+dsn,
				"AGENTCAPSULE_DELIVERY_ROOT="+root, "AGENTCAPSULE_DELIVERY_ID="+id)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || line != "CRASH_POINT\n" {
				t.Fatalf("child point=%q err=%v", line, err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("worker was not killed")
			}
			expireLease(t, s, id)
			m := mockStores(t, root, "a", "b", "c")
			m.SetHandler(recordDelivery)
			if err := s.DispatchOne(t.Context(), "b", time.Minute, m); err != nil {
				t.Fatal(err)
			}
			assertRequestState(t, s, r.RequestID, "PROCESSING")
			if got := received(t, root, "b"); fmt.Sprint(got) != fmt.Sprint([]string{id}) {
				t.Fatalf("crash duplicated/lost effect: %v", got)
			}
		})
	}
}

func TestDeliveryWorkerChild(t *testing.T) {
	point := os.Getenv("AGENTCAPSULE_DELIVERY_CHILD")
	if point == "" {
		return
	}
	s, err := Open(t.Context(), os.Getenv("AGENTCAPSULE_DELIVERY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := vmruntime.NewMock(t.Context(), os.Getenv("AGENTCAPSULE_DELIVERY_ROOT"), "a", "b", "c")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	pause := func() {
		fmt.Println("CRASH_POINT")
		for {
			time.Sleep(time.Hour)
		}
	}
	m.SetHandler(func(ctx context.Context, target string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		result, err := recordDelivery(ctx, target, e, tx)
		if err == nil && point == "before-commit" {
			pause()
		}
		return result, err
	})
	a, err := s.ClaimDelivery(t.Context(), os.Getenv("AGENTCAPSULE_DELIVERY_ID"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeDispatch(t.Context(), a.ID, a.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(t.Context(), "b", a.Envelope); err != nil {
		t.Fatal(err)
	}
	pause() // Durable local effect, but no PostgreSQL ACK yet.
}

func TestNeverDispatchedDeliveryIsKnownFailure(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	r, err := s.Submit(t.Context(), "a", "never-sent", submission())
	if err != nil {
		t.Fatal(err)
	}
	id := mailboxFor(t, s, r.RequestID, "request")
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET attempt_limit=1 WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	a, err := s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeDelivery(t.Context(), id, a.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("ACK without dispatch permission: %v", err)
	}
	expireLease(t, s, id)
	if err := s.RetireDelivery(t.Context(), id, m); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := s.pool.QueryRow(t.Context(), "SELECT reason FROM request_closures WHERE request_id=$1", r.RequestID).Scan(&reason); err != nil || reason != "delivery_failed" {
		t.Fatalf("known failure misreported: %s %v", reason, err)
	}
	if err := s.AuthorizeDispatch(t.Context(), id, a.Token); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("late dispatch permission: %v", err)
	}
}
