package controlplane

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func workPlacements(t *testing.T, s *Store) {
	t.Helper()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.RegisterPlacement(t.Context(), id, "host"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkDiscoveryFIFOAndExactMailboxIdentity(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	workPlacements(t, s)
	for _, key := range []string{"first", "second"} {
		if _, err := s.Submit(t.Context(), "a", key, submission()); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if err := s.DiscoverWork(t.Context(), "host", 10); err != nil {
			t.Fatal(err)
		}
	}
	if count(t, s, "worker_jobs") != 1 {
		t.Fatal("discovery duplicated a head or admitted its successor")
	}
	if err := s.DiscoverWork(t.Context(), "foreign", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimWork(t.Context(), "foreign", time.Minute); !errors.Is(err, ErrNoWork) {
		t.Fatal(err)
	}
	j, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil || j.Kind != "delivery" || j.AgentID != "b" {
		t.Fatal(j, err)
	}
	r := mockStores(t, t.TempDir(), "a", "b", "c")
	r.SetHandler(func(ctx context.Context, _ string, _ harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		return localEffect(ctx, tx)
	})
	if err = s.DispatchMailbox(t.Context(), j.ID, time.Minute, r); err != nil {
		t.Fatal(err)
	}
	// The obsolete scheduler identity must never dispatch the new head.
	if err = s.DispatchMailbox(t.Context(), j.ID, time.Minute, r); !errors.Is(err, ErrNoDelivery) {
		t.Fatal(err)
	}
	var attempts int
	if err = s.pool.QueryRow(t.Context(), "SELECT attempts FROM agent_mailboxes WHERE dest_agent_id='b' AND delivery_state='PENDING'").Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal(attempts, err)
	}
	if err = s.CompleteWork(t.Context(), j); err != nil {
		t.Fatal(err)
	}
	if err = s.DiscoverWork(t.Context(), "host", 10); err != nil {
		t.Fatal(err)
	}
	next, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil || next.ID == j.ID {
		t.Fatal(next, err)
	}
	if err = s.DispatchMailbox(t.Context(), next.ID, time.Minute, r); err != nil {
		t.Fatal(err)
	}
}

func TestWorkFairRetryLeaseAndConcurrentClaims(t *testing.T) {
	s, dsn := freshStore(t, "auto", 10)
	workPlacements(t, s)
	peer, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, dest := range []string{"b", "c"} {
		in := submission()
		in.RecipientAgentID = dest
		if _, err = s.Submit(t.Context(), "a", dest, in); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.DiscoverWork(t.Context(), "host", 10); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RetryWork(t.Context(), first, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, err := peer.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil || first.ID == second.ID {
		t.Fatal(second, err)
	}
	if _, err = s.ClaimWork(t.Context(), "host", time.Minute); !errors.Is(err, ErrNoWork) {
		t.Fatal("retry delay or current lease ignored", err)
	}
	// Lease expiration makes the job eligible, without acknowledging its work.
	if _, err = s.pool.Exec(t.Context(), "UPDATE worker_jobs SET available_at=clock_timestamp()-interval '1 second',lease_until=CASE WHEN lease_token='' THEN NULL ELSE clock_timestamp()-interval '1 second' END"); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteWork(t.Context(), second); !errors.Is(err, ErrWorkLeaseLost) {
		t.Fatal(err)
	}
	if err = s.RetryWork(t.Context(), second, time.Second); !errors.Is(err, ErrWorkLeaseLost) {
		t.Fatal(err)
	}
	retry, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil || retry.ID != first.ID || retry.Failures != 1 || retry.Token == first.Token {
		t.Fatal("failed job lost its place", retry, err)
	}
	if err = s.CompleteWork(t.Context(), first); !errors.Is(err, ErrWorkLeaseLost) {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE worker_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE lease_token<>''"); err != nil {
		t.Fatal(err)
	}
	type result struct {
		j   WorkerJob
		err error
	}
	out := make(chan result, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store := s
			if i%2 == 1 {
				store = peer
			}
			j, e := store.ClaimWork(t.Context(), "host", time.Minute)
			out <- result{j, e}
		}()
	}
	wg.Wait()
	close(out)
	seen := map[string]bool{}
	for r := range out {
		if errors.Is(r.err, ErrNoWork) {
			continue
		}
		if r.err != nil || seen[r.j.ID] {
			t.Fatal("duplicate concurrent claim", r, seen)
		}
		seen[r.j.ID] = true
	}
	if len(seen) != 2 {
		t.Fatal(seen)
	}
}

func TestWorkDiscoveryOtherIntentsAndTransactionalTicket(t *testing.T) {
	s, _ := freshStore(t, "manual", 10)
	workPlacements(t, s)
	r, err := s.Submit(t.Context(), "a", "cancel", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(t.Context(), "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	expires, err := s.Submit(t.Context(), "a", "expires", submission())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", expires.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	if err = s.DiscoverWork(t.Context(), "host", 10); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 3 {
		j, e := s.ClaimWork(t.Context(), "host", time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		seen[j.Kind] = true
	}
	if !seen["closure"] || !seen["expiration"] || !seen["deletion"] || len(seen) != 3 {
		t.Fatal(seen)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE worker_jobs SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err = s.pool.QueryRow(t.Context(), "SELECT next_ticket FROM worker_hosts WHERE host_id='host'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_work() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected work claim failure'; END $$;
        CREATE TRIGGER reject_work BEFORE UPDATE ON worker_jobs FOR EACH ROW EXECUTE FUNCTION reject_work()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimWork(t.Context(), "host", time.Minute); err == nil {
		t.Fatal("injected failure not observed")
	}
	var after int64
	if err = s.pool.QueryRow(t.Context(), "SELECT next_ticket FROM worker_hosts WHERE host_id='host'").Scan(&after); err != nil || after != before {
		t.Fatal("claim split ticket and lease", before, after, err)
	}
}

func TestWorkRejectsUnloggedQueue(t *testing.T) {
	for _, table := range []string{"worker_jobs", "worker_hosts"} {
		t.Run(table, func(t *testing.T) {
			s, _ := freshStore(t, "auto", 1)
			if _, err := s.pool.Exec(t.Context(), "ALTER TABLE worker_jobs SET UNLOGGED"); err != nil {
				t.Fatal(err)
			}
			if table == "worker_hosts" {
				// Isolate the deliberately unsafe host table. Its new catalogue
				// dependents remain logged; otherwise PostgreSQL rejects the test
				// setup before our durability check can be exercised.
				if _, err := s.pool.Exec(t.Context(), `ALTER TABLE agent_specs DROP CONSTRAINT agent_specs_host_id_fkey;
                    ALTER TABLE platform_operations DROP CONSTRAINT platform_operations_host_id_fkey;
                    ALTER TABLE worker_hosts SET UNLOGGED;
                    ALTER TABLE worker_jobs DROP CONSTRAINT worker_jobs_host_id_fkey;
                    ALTER TABLE worker_jobs SET LOGGED`); err != nil {
					t.Fatal(err)
				}
			}
			var unsafeTables []string
			if err := s.pool.QueryRow(t.Context(), `SELECT array_agg(relname::text) FROM pg_class
                WHERE relnamespace=current_schema()::regnamespace AND relname=ANY($1) AND relpersistence<>'p'`, durableTables).Scan(&unsafeTables); err != nil {
				t.Fatal(err)
			}
			if len(unsafeTables) != 1 || unsafeTables[0] != table {
				t.Fatal("fixture does not isolate the tested table", unsafeTables)
			}
			if err := s.DiscoverWork(t.Context(), "host", 1); !errors.Is(err, ErrUnsafeDatabase) {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkDatabaseRecovery(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_PG_RECOVERY")
	if phase == "" {
		return
	}
	dsn := databaseURL(t)
	admin, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const schema = "work_recovery"
	if phase == "prepare" {
		if _, err = admin.pool.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(t.Context(), scopedURL(t, dsn, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if phase == "prepare" {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		seed(t, s, "auto", 1)
		workPlacements(t, s)
		if _, err = s.Submit(t.Context(), "a", "durable", submission()); err != nil {
			t.Fatal(err)
		}
		if err = s.DiscoverWork(t.Context(), "host", 10); err != nil {
			t.Fatal(err)
		}
		if _, err = s.ClaimWork(t.Context(), "host", time.Hour); err != nil {
			t.Fatal(err)
		}
		return
	}
	var n int64
	var token string
	var attempts int
	if err = s.pool.QueryRow(t.Context(), `SELECT h.next_ticket,j.lease_token,m.attempts FROM worker_hosts h JOIN worker_jobs j USING(host_id) JOIN agent_mailboxes m ON m.id=j.object_id WHERE h.host_id='host' AND j.ticket=2 AND j.lease_until>clock_timestamp()`).Scan(&n, &token, &attempts); err != nil || n != 2 || token == "" || attempts != 0 {
		t.Fatal("WAL lost atomic scheduler claim", n, token != "", attempts, err)
	}
	if _, err = s.ClaimWork(t.Context(), "host", time.Minute); !errors.Is(err, ErrNoWork) {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE worker_jobs SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil || j.Token == token {
		t.Fatal(j, err)
	}
	if err = s.CompleteWork(t.Context(), j); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.pool.Exec(t.Context(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
		t.Fatal(err)
	}
}

// The worker host row is locked while work is discovered. Foreign-key checks
// from operations and jobs only need a KEY SHARE lock and must not wait for it,
// while two discoveries on the same host must still serialize.
func TestWorkerHostLockDoesNotBlockForeignKeyChecks(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	ctx := t.Context()
	if _, err := s.pool.Exec(ctx, "INSERT INTO worker_hosts(host_id) VALUES ('lock-host')"); err != nil {
		t.Fatal(err)
	}
	holder, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(holder)
	if err = lockWorkerHost(ctx, holder, "lock-host"); err != nil {
		t.Fatal(err)
	}

	reader, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(reader)
	if _, err = reader.Exec(ctx, "SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	var one int
	if err = reader.QueryRow(ctx, "SELECT 1 FROM worker_hosts WHERE host_id=$1 FOR KEY SHARE", "lock-host").Scan(&one); err != nil {
		t.Fatal("foreign-key style lock waited for the worker scan:", err)
	}

	rival, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(rival)
	if _, err = rival.Exec(ctx, "SET LOCAL lock_timeout='300ms'"); err != nil {
		t.Fatal(err)
	}
	if err = lockWorkerHost(ctx, rival, "lock-host"); err == nil {
		t.Fatal("two worker scans on one host were not serialized")
	}
}
