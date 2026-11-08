package controlplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func confirmedCaller(t *testing.T, s *Store, id string) VMCaller {
	t.Helper()
	if err := s.RegisterPlacement(t.Context(), id, "host"); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimPlacement(t.Context(), id, "host", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = s.ConfirmPlacement(t.Context(), id, "host", "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return VMCaller{AgentID: id, HostID: "host", VMID: vm, Generation: p.Generation}
}

func TestVMGenerationGuardsIncludingIdempotentReplay(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	old := confirmedCaller(t, s, "a")
	first, err := s.SubmitFromVM(t.Context(), old, "one", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(t.Context(), "a", "host", old.Generation); err != nil {
		t.Fatal(err)
	}
	// Unit SQL authority test: physical retirement is tested in the KVM campaign.
	if err = s.ObservePlacementStopped(t.Context(), "a", "host", old.Generation, false); err != nil {
		t.Fatal(err)
	}
	current := confirmedCaller(t, s, "a")
	for _, key := range []string{"one", "new"} {
		if _, err = s.SubmitFromVM(t.Context(), old, key, submission()); !errors.Is(err, ErrPlacement) {
			t.Fatalf("stale admission/replay accepted: %v", err)
		}
	}
	input := submission()
	// Recover the exact original deadline; different payloads must still conflict.
	if err = s.pool.QueryRow(t.Context(), "SELECT expires_at FROM agent_requests WHERE id=$1", first.RequestID).Scan(&input.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	r, err := s.SubmitFromVM(t.Context(), current, "one", input)
	if err != nil || !r.Replayed || r.RequestID != first.RequestID {
		t.Fatalf("new boot failed replay: %+v %v", r, err)
	}
	if _, err = s.SearchDirectoryFromVM(t.Context(), old, []string{"a", "b", "c"}); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	ids, err := s.SearchDirectoryFromVM(t.Context(), current, []string{"a", "b", "c", "missing"})
	if err != nil || !reflect.DeepEqual(ids, []string{"b", "c"}) {
		t.Fatalf("directory: %v %v", ids, err)
	}
	if err = s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitFromVM(t.Context(), current, "one", input); !errors.Is(err, ErrPlacement) {
		t.Fatal("quiescing replay disclosed receipt:", err)
	}
	if remaining(t, s, "mandate-a") != 2 {
		t.Fatal("stale calls consumed mandate budget")
	}
	assertRows(t, s, 1, 1, 1)
}

func TestVMReplyGuardRunsBeforeReceiptReplay(t *testing.T) {
	s, _, _, _, request := processingRequest(t, "auto")
	b := confirmedCaller(t, s, "b")
	a := confirmedCaller(t, s, "a")
	if _, err := s.ReplyFromVM(t.Context(), a, request.RequestID, "reply", completedReply()); !errors.Is(err, ErrNotFound) {
		t.Fatal("sender impersonated recipient:", err)
	}
	first, err := s.ReplyFromVM(t.Context(), b, request.RequestID, "reply", completedReply())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(t.Context(), "b", "host", b.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), "b", "host", b.Generation, false); err != nil {
		t.Fatal(err)
	}
	newB := confirmedCaller(t, s, "b")
	if _, err = s.ReplyFromVM(t.Context(), b, request.RequestID, "reply", completedReply()); !errors.Is(err, ErrPlacement) {
		t.Fatal("stale reply replay accepted:", err)
	}
	r, err := s.ReplyFromVM(t.Context(), newB, request.RequestID, "reply", completedReply())
	if err != nil || !r.Replayed || r.RequestID != first.RequestID {
		t.Fatalf("new recipient boot replay: %+v %v", r, err)
	}
}

func TestVMReplacementWhileAdmissionWaitsForAgentLock(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	old := confirmedCaller(t, s, "a")
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, "a", "b"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.SubmitFromVM(ctx, old, "delayed", submission()); done <- err }()
	waitUntil(t, func() bool {
		var blocked bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM agents WHERE id = ANY%')`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		return blocked
	})
	// Force the placement transition while owning the same agent lock that the
	// real placement methods take. The waiting call has already reached SQL.
	if _, err = tx.Exec(ctx, `UPDATE agent_placements SET generation=2,vm_id='0000000000000002' WHERE agent_id='a'`); err != nil {
		t.Fatal(err)
	}
	if err = commit(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrPlacement) {
		t.Fatal("generation was checked before its lock:", err)
	}
	assertRows(t, s, 0, 0, 0)
	if remaining(t, s, "mandate-a") != 3 {
		t.Fatal("rejected stale call consumed budget")
	}
}

func TestVMAdmissionKeepsAuthorityLockedThroughCommit(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	caller := confirmedCaller(t, s, "a")
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	blocker, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(blocker)
	if _, err = blocker.Exec(ctx, "SELECT id FROM mandates WHERE id='mandate-a' FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	submitted := make(chan error, 1)
	go func() { _, err := s.SubmitFromVM(ctx, caller, "ordered", submission()); submitted <- err }()
	waitUntil(t, func() bool {
		var blocked bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%UPDATE mandates SET remaining=remaining-1%')`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		return blocked
	})
	stopped := make(chan error, 1)
	go func() { stopped <- s.BeginPlacementStop(ctx, "a", "host", caller.Generation) }()
	waitUntil(t, func() bool {
		var blocked bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM agents WHERE id = ANY%')`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		return blocked
	})
	rollback(blocker)
	if err = <-submitted; err != nil {
		t.Fatal(err)
	}
	if err = <-stopped; err != nil {
		t.Fatal(err)
	}
	assertRows(t, s, 1, 1, 1)
	if err = s.ValidateVMCaller(ctx, caller); !errors.Is(err, ErrPlacement) {
		t.Fatal("stopping caller remains authorized:", err)
	}
}
