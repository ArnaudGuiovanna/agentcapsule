package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func mockStores(t *testing.T, root string, ids ...string) *vmruntime.MockRuntime {
	t.Helper()
	m, err := vmruntime.NewMock(t.Context(), root, ids...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func incoming(t *testing.T, s *Store) Receipt {
	t.Helper()
	in := submission()
	in.RecipientAgentID, in.MandateID = "a", "mandate-c"
	r, err := s.Submit(t.Context(), "c", "incoming", in)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertPhase(t *testing.T, s *Store, id, want string) {
	t.Helper()
	var got string
	if err := s.pool.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id=$1", id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("agent %s: phase %s, want %s", id, got, want)
	}
}

func assertCanceled(t *testing.T, s *Store, requests, statusEvents int) {
	t.Helper()
	var canceled, pendingWork, statuses, outboxes int
	err := s.pool.QueryRow(t.Context(), `SELECT
        (SELECT count(*) FROM agent_requests WHERE state='CANCELED'),
        (SELECT count(*) FROM agent_mailboxes WHERE kind IN ('request','reply') AND delivery_state='PENDING'),
        (SELECT count(*) FROM agent_mailboxes WHERE kind='status' AND delivery_state='PENDING'),
        (SELECT count(*) FROM outbox)`).Scan(&canceled, &pendingWork, &statuses, &outboxes)
	if err != nil {
		t.Fatal(err)
	}
	if canceled != requests || pendingWork != 0 || statuses != statusEvents || outboxes != statusEvents {
		t.Fatalf("canceled=%d pending work=%d status=%d outbox=%d", canceled, pendingWork, statuses, outboxes)
	}
}

func localEffect(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY)"); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO effects DEFAULT VALUES"); err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects").Scan(&n); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprint(n)), nil
}

func TestRevocationWaitsForEveryStoreAndCancelsAtomically(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	outgoing, err := s.Submit(t.Context(), "a", "outgoing", submission())
	if err != nil {
		t.Fatal(err)
	}
	in := incoming(t, s)
	event := harnessstore.Event{ID: "outgoing-work", Subjects: []string{"agent/a", "agent/b", "request/" + outgoing.RequestID}, Body: []byte("old authorized work")}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	delivered := make(chan error, 1)
	go func() {
		_, err := m.Deliver(t.Context(), "b", event, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
			result, err := localEffect(ctx, tx)
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return result, err
		})
		delivered <- err
	}()
	select {
	case <-entered:
	case err := <-delivered:
		t.Fatalf("effect did not start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("effect did not start")
	}
	if err := s.RequestDeletion(t.Context(), "user-b", "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong owner: %v", err)
	}
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, s, "a", "QUIESCING")
	if _, err := s.Submit(t.Context(), "a", "late", submission()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("new work passed intent: %v", err)
	}
	if err := s.commitRevocation(t.Context(), "a"); !errors.Is(err, ErrPendingFences) {
		t.Fatalf("missing barriers accepted: %v", err)
	}
	fencingB := make(chan struct{})
	m.SetFenceHook(func(stage, target, _ string) error {
		if stage == "before" && target == "b" {
			close(fencingB)
		}
		return nil
	})
	reconciled := make(chan error, 1)
	go func() { reconciled <- s.ReconcileRevocation(t.Context(), "a", m) }()
	select {
	case <-fencingB:
	case err := <-reconciled:
		t.Fatalf("reconciliation stopped before busy store: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("fence not attempted")
	}
	select {
	case err := <-reconciled:
		t.Fatalf("fence did not wait for active SQL: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	assertPhase(t, s, "a", "QUIESCING")
	unblock()
	if err := <-delivered; err != nil {
		t.Fatal(err)
	}
	if err := <-reconciled; err != nil {
		t.Fatal(err)
	}
	assertPhase(t, s, "a", "DELETING")
	assertCanceled(t, s, 2, 1)
	// Both a replay and fresh old work are refused after the logical tombstone.
	for _, id := range []string{event.ID, "late-old-work"} {
		event.ID = id
		if _, err := m.Deliver(t.Context(), "b", event, localEffect); !errors.Is(err, harnessstore.ErrFenced) {
			t.Fatalf("late effect: %v", err)
		}
	}
	var notification, destination string
	if err := s.pool.QueryRow(t.Context(), "SELECT id,dest_agent_id FROM agent_mailboxes WHERE kind='status' AND ref_id=$1", in.RequestID).Scan(&notification, &destination); err != nil {
		t.Fatal(err)
	}
	if destination != "c" {
		t.Fatalf("status addressed to %s", destination)
	}
	// Status is new control-plane metadata, not a replay of the revoked payload.
	status := harnessstore.Event{ID: notification, Subjects: []string{"agent/c", "notification/" + notification}, Body: []byte("CANCELED")}
	if _, err := m.Deliver(t.Context(), "c", status, localEffect); err != nil {
		t.Fatal(err)
	}
	unrelated := submission()
	unrelated.MandateID, unrelated.RecipientAgentID = "mandate-b", "c"
	if _, err := s.Submit(t.Context(), "b", "unrelated", unrelated); err != nil {
		t.Fatalf("unrelated admission blocked: %v", err)
	}
	if _, err := m.Deliver(t.Context(), "c", harnessstore.Event{ID: "unrelated", Subjects: []string{"agent/b", "agent/c"}}, localEffect); err != nil {
		t.Fatalf("unrelated effect blocked: %v", err)
	}
}

func TestRevocationLostAckSurvivesReopenAndConcurrentRetry(t *testing.T) {
	s, dsn := freshStore(t, "auto", 3)
	incoming(t, s)
	root := t.TempDir()
	m := mockStores(t, root, "a", "b", "c")
	lost := errors.New("injected lost fence ACK")
	m.SetFenceHook(func(stage, target, _ string) error {
		if stage == "after_commit" && target == "b" {
			return lost
		}
		return nil
	})
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "a", m); !errors.Is(err, lost) {
		t.Fatalf("lost ACK: %v", err)
	}
	assertPhase(t, s, "a", "QUIESCING")
	var ack bool
	if err := s.pool.QueryRow(t.Context(), "SELECT acknowledged FROM deletion_targets WHERE agent_id='a' AND store_agent_id='b'").Scan(&ack); err != nil || ack {
		t.Fatalf("unreceived fence recorded: %v %v", ack, err)
	}
	m.Close()
	s.Close()
	peer, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	m = mockStores(t, root, "a", "b", "c")
	if _, err := m.Deliver(t.Context(), "b", harnessstore.Event{ID: "after-reopen", Subjects: []string{"agent/a", "agent/b"}}, localEffect); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("local fence lost after reopen: %v", err)
	}
	if err := peer.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 4)
	for range 4 {
		go func() { errs <- peer.ReconcileRevocation(t.Context(), "a", m) }()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	assertPhase(t, peer, "a", "DELETING")
	assertCanceled(t, peer, 1, 1)
	// A later deletion of the live sender also cancels its queued status notice.
	if err := peer.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	if err := peer.ReconcileRevocation(t.Context(), "c", m); err != nil {
		t.Fatal(err)
	}
	assertCanceled(t, peer, 1, 0)
}

func TestRevocationUnavailableStoreAndNotificationRollback(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	incoming(t, s)
	root := t.TempDir()
	m := mockStores(t, root, "a", "b") // Store c cannot acknowledge anything.
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "a", m); err == nil {
		t.Fatal("unreachable store counted as fenced")
	}
	if err := s.commitRevocation(t.Context(), "a"); !errors.Is(err, ErrPendingFences) {
		t.Fatalf("missing barrier: %v", err)
	}
	assertPhase(t, s, "a", "QUIESCING")
	m.Close()
	m = mockStores(t, root, "a", "b", "c")
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_status_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected status outbox failure'; END $$;
        CREATE TRIGGER reject_status_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_status_outbox();
        ALTER TABLE agent_mailboxes DROP CONSTRAINT agent_mailboxes_kind_check;
        ALTER TABLE agent_mailboxes ADD CONSTRAINT agent_mailboxes_kind_check CHECK (kind IN ('request','reply'))`)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the migration from the original mailbox schema as well as retry.
	simulatePreLedgerSchema(t, s)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "a", m); err == nil {
		t.Fatal("notification loss was acknowledged")
	}
	assertPhase(t, s, "a", "QUIESCING")
	var state string
	if err := s.pool.QueryRow(t.Context(), "SELECT state FROM agent_requests").Scan(&state); err != nil || state != "DELIVERING" {
		t.Fatalf("cancellation escaped rollback: %s %v", state, err)
	}
	assertRows(t, s, 1, 1, 1)
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_status_outbox ON outbox"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}
	assertPhase(t, s, "a", "DELETING")
	assertCanceled(t, s, 1, 1)
}

func TestConcurrentDeletionAndAdmission(t *testing.T) {
	s, _ := freshStore(t, "auto", 20)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	errs := make(chan error, 14)
	for i := range 12 {
		go func() {
			<-start
			_, err := s.Submit(ctx, "a", fmt.Sprintf("racing-%d", i), submission())
			if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) {
				err = nil
			}
			errs <- err
		}()
	}
	for _, id := range []string{"a", "b"} {
		go func() {
			<-start
			err := s.RequestDeletion(ctx, "user-"+id, id)
			if err == nil {
				err = s.ReconcileRevocation(ctx, id, m)
			}
			errs <- err
		}()
	}
	close(start)
	for range 14 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	assertPhase(t, s, "a", "DELETING")
	assertPhase(t, s, "b", "DELETING")
	assertCanceled(t, s, count(t, s, "agent_requests"), 0)
}

func TestDeletionManifestsAllowForeignKeyLocks(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	gate, err := s.pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err := gate.Exec(t.Context(), "SELECT pg_advisory_lock(756610044)"); err != nil {
		t.Fatal(err)
	}
	defer gate.Exec(context.Background(), "SELECT pg_advisory_unlock(756610044)")
	// Stop both deletions AFTER each holds its subject row, BEFORE their target
	// census inserts reference the other subject. FOR UPDATE deadlocks here;
	// FOR NO KEY UPDATE correctly coexists with foreign keys' KEY SHARE locks.
	_, err = s.pool.Exec(t.Context(), `CREATE FUNCTION pause_deletion_intent() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.phase='QUIESCING' AND OLD.phase='LIVE' THEN
            PERFORM pg_advisory_xact_lock_shared(756610044);
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER pause_deletion_intent AFTER UPDATE ON agents
        FOR EACH ROW EXECUTE FUNCTION pause_deletion_intent()`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		go func() { errs <- s.RequestDeletion(ctx, "user-"+id, id) }()
	}
	waitUntil(t, func() bool {
		var waiting int
		if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=756610044 AND NOT granted").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting == 2
	})
	if _, err := gate.Exec(ctx, "SELECT pg_advisory_unlock(756610044)"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, s, "deletion_targets"); n != 6 {
		t.Fatalf("incomplete manifests: %d targets", n)
	}
}
