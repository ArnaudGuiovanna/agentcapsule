package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPlacementConcurrentLeasesAndFencing(t *testing.T) {
	s, dsn := freshStore(t, "auto", 3)
	peer, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = s.RegisterPlacement(t.Context(), "a", "host-a"); err != nil {
		t.Fatal(err)
	}
	if err = peer.RegisterPlacement(t.Context(), "a", "host-b"); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type result struct {
		p   Placement
		err error
	}
	results := make(chan result, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			store := s
			if i%2 == 1 {
				store = peer
			}
			p, err := store.ClaimPlacement(t.Context(), "a", "host-a", fmt.Sprint("worker-", i), time.Minute)
			results <- result{p, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner Placement
	wins := 0
	for r := range results {
		if r.err == nil {
			wins++
			winner = r.p
		} else if !errors.Is(r.err, ErrPlacementBusy) {
			t.Fatal(r.err)
		}
	}
	if wins != 1 || winner.Generation != 1 {
		t.Fatalf("wins=%d winner=%+v", wins, winner)
	}
	replayed, err := s.ClaimPlacement(t.Context(), "a", "host-a", winner.WorkerID, time.Hour)
	if err != nil || replayed.Generation != 1 || !replayed.LeaseUntil.Equal(*winner.LeaseUntil) {
		t.Fatalf("claim retry changed generation/deadline: %+v %v", replayed, err)
	}
	if _, err = s.pool.Exec(t.Context(), `UPDATE agent_placements SET lease_until=clock_timestamp()-interval '1 second' WHERE agent_id='a'`); err != nil {
		t.Fatal(err)
	}
	second, err := peer.ClaimPlacement(t.Context(), "a", "host-a", "replacement", time.Minute)
	if err != nil || second.Generation != 2 {
		t.Fatalf("%+v %v", second, err)
	}
	if err = s.ConfirmPlacement(t.Context(), "a", "host-a", winner.WorkerID, 1, "old-vm"); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	if err = peer.ConfirmPlacement(t.Context(), "a", "host-a", "replacement", 2, "new-vm"); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []func() error{
		func() error { return s.BeginPlacementStop(t.Context(), "a", "host-a", 1) },
		func() error { return s.ObservePlacementStopped(t.Context(), "a", "host-a", 1, true) },
		func() error { return s.ConfirmPlacement(t.Context(), "a", "host-a", "replacement", 2, "wrong-vm") },
		func() error { return s.ValidatePlacement(t.Context(), "a", "host-b", 2, "new-vm") },
	} {
		if err := stale(); !errors.Is(err, ErrPlacement) {
			t.Fatalf("stale mutation accepted: %v", err)
		}
	}
	if err = s.ValidatePlacement(t.Context(), "a", "host-a", 2, "new-vm"); err != nil {
		t.Fatal(err)
	}
	adopted, err := s.ClaimPlacement(t.Context(), "a", "host-a", "new-process", time.Minute)
	if err != nil || adopted.State != "RUNNING" || adopted.Generation != 2 || adopted.LeaseUntil != nil {
		t.Fatalf("%+v %v", adopted, err)
	}
	if err = s.BeginPlacementStop(t.Context(), "a", "host-a", 2); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimPlacement(t.Context(), "a", "host-a", "new-process", time.Minute); !errors.Is(err, ErrPlacementBusy) {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), "a", "host-a", 2, false); err != nil {
		t.Fatal(err)
	}
	third, err := s.ClaimPlacement(t.Context(), "a", "host-a", "new-process", time.Minute)
	if err != nil || third.Generation != 3 {
		t.Fatalf("%+v %v", third, err)
	}
}

func TestPlacementExpiryWhileConfirmationWaitsForLock(t *testing.T) {
	s, _ := freshStore(t, "auto", 1)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := s.RegisterPlacement(ctx, "a", "host"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimPlacement(ctx, "a", "host", "worker", 400*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, "a"); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- s.ConfirmPlacement(ctx, "a", "host", "worker", 1, "vm") }()
	// Observe the real database lock wait, then let the database clock cross the
	// deadline. The confirming transaction began BEFORE expiry.
	for {
		var blocked bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%FROM agents WHERE id = ANY%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	for {
		var expired bool
		if err := s.pool.QueryRow(ctx, `SELECT lease_until<=clock_timestamp() FROM agent_placements WHERE agent_id='a'`).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	rollback(tx)
	if err := <-finished; !errors.Is(err, ErrPlacement) {
		t.Fatalf("expired confirmation accepted: %v", err)
	}
	p, err := s.Placements(ctx, "host")
	if err != nil || len(p) != 1 || p[0].State != "STARTING" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestPlacementDeletionAndDurabilityGuards(t *testing.T) {
	s, dsn := freshStore(t, "auto", 1)
	for _, id := range []string{"a", "b"} {
		if err := s.RegisterPlacement(t.Context(), id, "host"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ClaimPlacement(t.Context(), id, "host", "worker", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ConfirmPlacement(t.Context(), "a", "host", "worker", 1, "vm-a"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if err := s.RequestDeletion(t.Context(), "user-"+id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ValidatePlacement(t.Context(), "a", "host", 1, "vm-a"); err != nil {
		t.Fatal("quiescing must retain data-fence guest:", err)
	}
	if err := s.ConfirmPlacement(t.Context(), "b", "host", "worker", 1, "vm-b"); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	if _, err := s.ClaimPlacement(t.Context(), "a", "host", "worker", time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE agents SET phase='DELETING' WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidatePlacement(t.Context(), "a", "host", 1, "vm-a"); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	// Isolate the durability guard: PostgreSQL also protects a logged child's
	// foreign key from an unlogged parent. Remove only that test-schema FK first.
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE store_seals DROP CONSTRAINT store_seals_agent_id_fkey;
        ALTER TABLE placement_renewals DROP CONSTRAINT placement_renewals_agent_id_fkey;
        ALTER TABLE placement_control_contracts DROP CONSTRAINT placement_control_contracts_agent_id_fkey;
        ALTER TABLE agent_placements SET UNLOGGED`); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(t.Context(), dsn); !errors.Is(err, ErrUnsafeDatabase) {
		if opened != nil {
			opened.Close()
		}
		t.Fatalf("unlogged placement accepted: %v", err)
	}
}

func TestPlacementFenceOnlyAdmission(t *testing.T) {
	s, _ := freshStore(t, "auto", 1)
	if err := s.RegisterPlacement(t.Context(), "a", "host"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimPlacement(t.Context(), "a", "host", "worker", time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("work admitted while quiescing: %v", err)
	}
	p, err := s.ClaimFencePlacement(t.Context(), "a", "host", "worker", time.Minute)
	if err != nil || !p.FenceOnly || p.Generation != 1 {
		t.Fatalf("barrier admission: %+v %v", p, err)
	}
	if err = s.ConfirmPlacement(t.Context(), "a", "host", "worker", 1, "vm"); !errors.Is(err, ErrPlacement) {
		t.Fatal("normal confirmation upgraded fence-only lease:", err)
	}
	if err = s.ConfirmFencePlacement(t.Context(), "a", "host", "worker", 1, "vm"); err != nil {
		t.Fatal(err)
	}
	if err = s.ValidatePlacement(t.Context(), "a", "host", 1, "vm"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `UPDATE agents SET phase='DELETING' WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimFencePlacement(t.Context(), "a", "host", "worker", time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tombstoned agent admitted:", err)
	}
}
