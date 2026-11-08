package controlplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func databaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL test database is missing")
		}
		t.Skip("run scripts/verify-postgres.py for real PostgreSQL integration checks")
	}
	return dsn
}

func scopedURL(t *testing.T, dsn, schema string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema+",pg_catalog")
		u.RawQuery = q.Encode()
		return u.String()
	}
	// schema is generated internally using only SQL-safe identifier characters.
	return cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
}

func freshStore(t *testing.T, mode string, budget int) (*Store, string) {
	t.Helper()
	rootURL := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), rootURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := newID("test")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	dsn := scopedURL(t, rootURL, schema)
	s, err := Open(t.Context(), dsn)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	seed(t, s, mode, budget)
	return s, dsn
}

func seed(t *testing.T, s *Store, mode string, budget int) {
	t.Helper()
	for _, name := range []string{"a", "b", "c"} {
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO agents(id,owner_user_id,discoverable,inbound_mode)
            VALUES ($1,$2,true,$3)`, name, "user-"+name, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
            VALUES ($1,$2,'owner-instruction',$3,$3,clock_timestamp()+interval '1 hour')`, "mandate-"+name, name, budget); err != nil {
			t.Fatal(err)
		}
	}
}

func submission() Submission {
	return Submission{RecipientAgentID: "b", MandateID: "mandate-a", PayloadRef: "encrypted-transit-reference",
		PayloadHash: sha256.Sum256([]byte("test message")), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertRows(t *testing.T, s *Store, requests, keys, events int) {
	t.Helper()
	for table, want := range map[string]int{"agent_requests": requests, "idempotency_keys": keys, "agent_mailboxes": events, "outbox": events} {
		if got := count(t, s, table); got != want {
			t.Fatalf("%s: got %d, want %d", table, got, want)
		}
	}
}

func remaining(t *testing.T, s *Store, mandate string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), "SELECT remaining FROM mandates WHERE id=$1", mandate).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestConcurrentIdempotencyAndMandateBudget(t *testing.T) {
	s, dsn := freshStore(t, "auto", 3)
	peer, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	input := submission()
	start := make(chan struct{})
	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 18)
	var wg sync.WaitGroup
	for i := range 18 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			store := s
			if i%2 == 1 {
				store = peer
			}
			r, err := store.Submit(t.Context(), "a", "same-key", input)
			results <- result{r, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	id := ""
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if id == "" {
			id = r.receipt.RequestID
		}
		if r.receipt.RequestID != id || r.receipt.State != Delivering {
			t.Fatalf("different replies: %+v", r)
		}
	}
	assertRows(t, s, 1, 1, 1)
	if n := remaining(t, s, "mandate-a"); n != 2 {
		t.Fatalf("replays consumed mandate: %d", n)
	}
	// Four distinct new keys now compete for the two remaining authorizations.
	errs := make(chan error, 4)
	for i := range 4 {
		go func() { _, err := s.Submit(t.Context(), "a", fmt.Sprintf("key-%d", i), input); errs <- err }()
	}
	ok, exhausted := 0, 0
	for range 4 {
		err := <-errs
		if err == nil {
			ok++
		} else if errors.Is(err, ErrMandate) {
			exhausted++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 2 || exhausted != 2 || remaining(t, s, "mandate-a") != 0 {
		t.Fatalf("success=%d exhausted=%d", ok, exhausted)
	}
	assertRows(t, s, 3, 3, 3)
}

func TestManualConsentAndAtomicOutboxFailure(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	r, err := s.Submit(t.Context(), "a", "request", submission())
	if err != nil || r.State != PendingApproval {
		t.Fatalf("%+v %v", r, err)
	}
	assertRows(t, s, 1, 1, 0)
	if _, err := s.Accept(t.Context(), "user-a", r.RequestID, "wrong-owner"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$;
        CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_outbox()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err == nil {
		t.Fatal("failed outbox was acknowledged")
	}
	assertRows(t, s, 1, 1, 0)
	var state string
	var accepted bool
	if err := s.pool.QueryRow(t.Context(), "SELECT state,accepted FROM agent_requests WHERE id=$1", r.RequestID).Scan(&state, &accepted); err != nil {
		t.Fatal(err)
	}
	if state != string(PendingApproval) || accepted {
		t.Fatalf("consent escaped rollback: %s %v", state, accepted)
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_outbox ON outbox; UPDATE agents SET discoverable=false WHERE id='b'"); err != nil {
		t.Fatal(err)
	}
	// Hiding the recipient does not invalidate an already pending request.
	acceptedReceipt, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept")
	if err != nil || acceptedReceipt.State != Delivering {
		t.Fatalf("%+v %v", acceptedReceipt, err)
	}
	if r, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil || !r.Replayed {
		t.Fatalf("%+v %v", r, err)
	}
	assertRows(t, s, 1, 2, 1)
}

func TestAdmissionGuardsAndConflictsRollBack(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	input := submission()
	bad := input
	bad.MandateID = "mandate-c"
	if _, err := s.Submit(t.Context(), "a", "wrong-mandate", bad); !errors.Is(err, ErrMandate) {
		t.Fatal(err)
	}
	bad = input
	bad.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := s.Submit(t.Context(), "a", "expired", bad); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=false WHERE id='b'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), "a", "hidden", input); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	bad = input
	bad.RecipientAgentID = "missing"
	if _, err := s.Submit(t.Context(), "a", "missing", bad); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	assertRows(t, s, 0, 0, 0)
	if remaining(t, s, "mandate-a") != 5 {
		t.Fatal("rejections consumed mandate")
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true WHERE id='b'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), "a", "key", input); err != nil {
		t.Fatal(err)
	}
	bad = input
	bad.PayloadHash = sha256.Sum256([]byte("different"))
	if _, err := s.Submit(t.Context(), "a", "key", bad); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.QuiesceAgent(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), "a", "after-quiesce", input); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	assertRows(t, s, 1, 1, 1)
}

func TestTerminalStateCannotBeResurrected(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	r, err := s.Submit(t.Context(), "a", "request", submission())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_requests SET state='CANCELED' WHERE id=$1", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	assertRows(t, s, 1, 1, 0)
	if _, err := s.pool.Exec(t.Context(), "UPDATE agent_requests SET state='DELIVERING' WHERE id=$1", r.RequestID); err == nil {
		t.Fatal("database allowed terminal resurrection")
	}
}

func TestDurabilitySettingsAndLoggedTables(t *testing.T) {
	s, dsn := freshStore(t, "auto", 2)
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION require_sync_commit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF current_setting('synchronous_commit') <> 'on' THEN RAISE EXCEPTION 'async commit'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER require_sync_commit BEFORE INSERT ON agent_requests FOR EACH ROW EXECUTE FUNCTION require_sync_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	async, err := Open(t.Context(), dsn+" synchronous_commit=off")
	if err != nil {
		t.Fatal(err)
	}
	defer async.Close()
	if _, err := async.Submit(t.Context(), "a", "key", submission()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), "ALTER TABLE outbox SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(t.Context(), dsn); !errors.Is(err, ErrUnsafeDatabase) {
		if opened != nil {
			opened.Close()
		}
		t.Fatalf("unsafe table accepted: %v", err)
	}
}

func waitUntil(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("condition timed out")
		case <-ticker.C:
		}
	}
}

func TestAPIProcessCrash(t *testing.T) {
	for _, point := range []string{"before-commit", "after-commit"} {
		t.Run(point, func(t *testing.T) {
			s, dsn := freshStore(t, "auto", 3)
			input := submission()
			var gate *pgxpool.Conn
			if point == "before-commit" {
				var err error
				gate, err = s.pool.Acquire(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Release()
				if _, err = gate.Exec(t.Context(), "SELECT pg_advisory_lock(756610043)"); err != nil {
					t.Fatal(err)
				}
				defer gate.Exec(context.Background(), "SELECT pg_advisory_unlock(756610043)")
				_, err = s.pool.Exec(t.Context(), `CREATE FUNCTION pause_request() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN PERFORM pg_advisory_xact_lock(756610043); RETURN NEW; END $$;
                    CREATE TRIGGER pause_request AFTER INSERT ON agent_requests FOR EACH ROW EXECUTE FUNCTION pause_request()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAPIChild$", "-test.timeout=35s")
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_PG_CHILD="+point, "AGENTCAPSULE_PG_CHILD_DSN="+dsn,
				"AGENTCAPSULE_PG_DEADLINE="+input.ExpiresAt.Format(time.RFC3339Nano))
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			if point == "before-commit" {
				waitUntil(t, func() bool {
					var waiting bool
					if err := s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=756610043 AND NOT granted)").Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					return waiting
				})
			} else {
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err != nil || line != "COMMITTED\n" {
					t.Fatalf("child=%q err=%v stderr=%s", line, err, stderr.String())
				}
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("child was not killed")
			}
			if gate != nil {
				if _, err := gate.Exec(t.Context(), "SELECT pg_advisory_unlock(756610043)"); err != nil {
					t.Fatal(err)
				}
				waitUntil(t, func() bool {
					var waiting bool
					if err := s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=756610043)").Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					return !waiting
				})
			}
			want := 0
			if point == "after-commit" {
				want = 1
			}
			assertRows(t, s, want, want, want)
			if remaining(t, s, "mandate-a") != 3-want {
				t.Fatal("mandate did not recover atomically")
			}
			r, err := s.Submit(t.Context(), "a", "child-key", input)
			if err != nil || r.Replayed != (want == 1) {
				t.Fatalf("retry=%+v err=%v", r, err)
			}
			assertRows(t, s, 1, 1, 1)
		})
	}
}

func TestAPIChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_PG_CHILD") == "" {
		return
	}
	s, err := Open(context.Background(), os.Getenv("AGENTCAPSULE_PG_CHILD_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	input := submission()
	input.ExpiresAt, err = time.Parse(time.RFC3339Nano, os.Getenv("AGENTCAPSULE_PG_DEADLINE"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(context.Background(), "a", "child-key", input); err != nil {
		t.Fatal(err)
	}
	fmt.Println("COMMITTED") // transaction committed; protocol response has not been sent
	for {
		time.Sleep(time.Hour)
	}
}

// verify-postgres.py invokes this twice, with an immediate database shutdown and
// WAL recovery in between. The fixture intentionally survives the prepare run.
func TestDurableDatabaseRestart(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_PG_RECOVERY")
	if phase == "" {
		return
	}
	rootURL := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), rootURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if phase == "prepare" {
		if _, err := admin.Exec(t.Context(), "CREATE SCHEMA restart_probe"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(t.Context(), scopedURL(t, rootURL, "restart_probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input := submission()
	if phase == "prepare" {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		seed(t, s, "auto", 3)
		for _, id := range []string{"a", "b"} {
			if err := s.RegisterPlacement(t.Context(), id, "recovery-host"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimPlacement(t.Context(), id, "recovery-host", "recovery-worker", time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.ConfirmPlacement(t.Context(), "a", "recovery-host", "recovery-worker", 1, "durable-vm"); err != nil {
			t.Fatal(err)
		}
		if err := s.BeginPlacementStop(t.Context(), "b", "recovery-host", 1); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Submit(t.Context(), "a", "auto", input); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET inbound_mode='manual' WHERE id='b'"); err != nil {
			t.Fatal(err)
		}
		r, err := s.Submit(t.Context(), "a", "manual", input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil {
			t.Fatal(err)
		}
		if err := s.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
			t.Fatal(err)
		}
		if err := s.RequestCancellation(t.Context(), "user-a", r.RequestID); err != nil {
			t.Fatal(err)
		}
	} else if phase == "verify" {
		if err := s.pool.QueryRow(t.Context(), "SELECT expires_at FROM agent_requests ORDER BY created_at LIMIT 1").Scan(&input.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"auto", "manual"} {
			r, err := s.Submit(t.Context(), "a", key, input)
			if err != nil || !r.Replayed {
				t.Fatalf("recovery replay=%+v err=%v", r, err)
			}
			if key == "manual" {
				if r.State != PendingApproval {
					t.Fatal("original idempotency response changed")
				}
				if r, err := s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil || !r.Replayed {
					t.Fatalf("%+v %v", r, err)
				}
			}
		}
	} else {
		t.Fatalf("unknown recovery phase %s", phase)
	}
	assertRows(t, s, 2, 3, 2)
	placements, err := s.Placements(t.Context(), "recovery-host")
	if err != nil || len(placements) != 2 || placements[0].State != "RUNNING" || placements[0].VMID != "durable-vm" ||
		placements[0].Generation != 1 || placements[1].State != "STOPPING" || placements[1].Generation != 1 {
		t.Fatalf("placements lost on WAL recovery: %+v %v", placements, err)
	}
	if remaining(t, s, "mandate-a") != 1 {
		t.Fatal("mandate budget changed across recovery/replay")
	}
	assertPhase(t, s, "c", "QUIESCING")
	var phaseAfterCrash string
	var targets int
	if err := s.pool.QueryRow(t.Context(), `SELECT phase,
        (SELECT count(*) FROM deletion_targets WHERE agent_id='c' AND NOT acknowledged)
        FROM deletion_operations WHERE agent_id='c'`).Scan(&phaseAfterCrash, &targets); err != nil {
		t.Fatal(err)
	}
	if phaseAfterCrash != "FENCING" || targets != 3 {
		t.Fatalf("deletion intent lost: phase=%s targets=%d", phaseAfterCrash, targets)
	}
	if count(t, s, "request_closures") != 1 || count(t, s, "request_closure_targets") != 3 {
		t.Fatal("request cancellation manifest lost during recovery")
	}
}
