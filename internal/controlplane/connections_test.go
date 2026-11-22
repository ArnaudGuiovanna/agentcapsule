package controlplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// P-08: a process's connections are bounded. The pool holds at most
// MaxConns; a lock wait, an advisory lock's included, ends at LockTimeout
// and gives its connection back to the pool; a statement ends at
// StatementTimeout; a transaction left idle ends at
// IdleInTransactionTimeout; a bound the database URL sets is kept.
func TestConnectionsBoundTheirWaits(t *testing.T) {
	_, dsn := freshStore(t, "auto", 2)
	s, err := OpenWith(t.Context(), dsn, Connections{MaxConns: 2, StatementTimeout: time.Second,
		LockTimeout: 200 * time.Millisecond, IdleInTransactionTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.pool.Config().MaxConns != 2 {
		t.Fatal("pool size", s.pool.Config().MaxConns)
	}
	holder, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(context.Background())
	if _, err = holder.Exec(t.Context(), "SELECT pg_advisory_lock(hashtextextended('organization-quota/org',0))"); err != nil {
		t.Fatal(err)
	}
	for range 3 { // more waits than the pool has connections
		tx, err := s.begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err = lockOrganizationQuota(t.Context(), tx, "org")
		rollback(tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Since(started) > 5*time.Second {
			t.Fatalf("an advisory lock wait: %v after %s", err, time.Since(started))
		}
	}
	var pgErr *pgconn.PgError
	if _, err = s.pool.Exec(t.Context(), "SELECT pg_sleep(3)"); !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatal("a statement past its bound:", err)
	}
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	_, err = tx.Exec(t.Context(), "SELECT 1")
	rollback(tx)
	if err == nil {
		t.Fatal("an idle transaction outlived its bound")
	}
	// A bound the database URL sets wins.
	set, err := OpenWith(t.Context(), dsn+" lock_timeout=1234", Connections{LockTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	var lock string
	if err = set.pool.QueryRow(t.Context(), "SHOW lock_timeout").Scan(&lock); err != nil || lock != "1234ms" {
		t.Fatal(lock, err)
	}
	for _, c := range []Connections{APIConnections, WorkerConnections, AdminConnections} {
		if !c.Valid() || c.MaxConns < 1 {
			t.Error("invalid defaults", c)
		}
	}
	if (Connections{MaxConns: MaxPoolConnections + 1}).Valid() || (Connections{LockTimeout: -time.Second}).Valid() {
		t.Error("invalid bounds accepted")
	}
	if _, err = OpenWith(t.Context(), dsn, Connections{MaxConns: -1}); !errors.Is(err, ErrInput) {
		t.Error("an invalid pool size:", err)
	}
}

// A migration runs without the session's statement and lock bounds: it
// waits for another migration past the session's lock bound.
func TestMigrationsIgnoreTheSessionBounds(t *testing.T) {
	rootURL := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), rootURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := newID("test")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	s, err := OpenWith(t.Context(), scopedURL(t, rootURL, schema), Connections{StatementTimeout: time.Minute, LockTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Another migration holds the migrations' lock for a second.
	holder, err := admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = holder.Exec(t.Context(), "SELECT pg_advisory_xact_lock(756610042)"); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(time.Second)
		_ = holder.Rollback(context.Background())
	}()
	started := time.Now()
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < time.Second {
		t.Fatal("the migration did not wait for the other")
	}
}

// statementCounter counts the statements its connections send: with the
// simple protocol of the transaction preamble, one statement is one round
// trip.
type statementCounter struct{ n atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// tracedStore opens a second store on dsn whose statements counter counts.
func tracedStore(t testing.TB, dsn string) (*Store, *statementCounter) {
	t.Helper()
	cfg, err := poolConfig(dsn, Connections{})
	if err != nil {
		t.Fatal(err)
	}
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return newStore(pool), counter
}

// P-06: a transaction's preamble (the shared or exclusive gate, the request
// ID, synchronous commit and the durability check) is one round trip, BEGIN
// included, with or without a request ID, shared or exclusive.
func TestTransactionPreambleIsOneRoundTrip(t *testing.T) {
	_, dsn := freshStore(t, "auto", 2)
	s, counter := tracedStore(t, dsn)
	if err := s.pool.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	requestID := telemetry.WithRequestID(t.Context(), "0123456789abcdef0123456789abcdef")
	for name, begin := range map[string]func() (pgx.Tx, error){
		"shared":            func() (pgx.Tx, error) { return s.begin(t.Context()) },
		"with a request ID": func() (pgx.Tx, error) { return s.begin(requestID) },
		"exclusive":         func() (pgx.Tx, error) { return s.beginCensus(t.Context(), true) },
		"snapshot": func() (pgx.Tx, error) {
			return s.beginWithOptions(t.Context(), false, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		},
	} {
		before := counter.n.Load()
		tx, err := begin()
		if err != nil {
			t.Fatal(name, err)
		}
		sent := counter.n.Load() - before
		var id, commit, isolation, readOnly string
		var gate bool
		err = tx.QueryRow(t.Context(), `SELECT coalesce(current_setting('agentcapsule.request_id',true),''),current_setting('synchronous_commit'),
            current_setting('transaction_isolation'),current_setting('transaction_read_only'),
            EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted)`).
			Scan(&id, &commit, &isolation, &readOnly, &gate)
		rollback(tx)
		if err != nil {
			t.Fatal(name, err)
		}
		if sent != 1 {
			t.Errorf("%s: the preamble sent %d statements, want 1", name, sent)
		}
		if commit != "on" || !gate {
			t.Errorf("%s: synchronous_commit %s, gate held %v", name, commit, gate)
		}
		if (name == "with a request ID") != (id == "0123456789abcdef0123456789abcdef") {
			t.Errorf("%s: request ID %q", name, id)
		}
		if (name == "snapshot") != (isolation == "repeatable read" && readOnly == "on") {
			t.Errorf("%s: %s, read only %s", name, isolation, readOnly)
		}
	}
}

// A pool whose connections did not prepare the durability check (its own
// connect hook replaced the store's) begins with the check written out, and
// refuses an UNLOGGED table as the store's pool does.
func TestPreambleWithoutThePreparedCheck(t *testing.T) {
	s, dsn := freshStore(t, "auto", 2)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	bare := newStore(pool)
	tx, err := bare.begin(t.Context())
	if err != nil {
		t.Fatal("a connection without the prepared check:", err)
	}
	var commit string
	err = tx.QueryRow(t.Context(), "SELECT current_setting('synchronous_commit')").Scan(&commit)
	rollback(tx)
	if err != nil || commit != "on" {
		t.Fatal(commit, err)
	}
	if _, err = s.pool.Exec(t.Context(), "ALTER TABLE llm_budget_windows SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]*Store{"prepared": s, "written out": bare} {
		if tx, err := store.begin(t.Context()); !errors.Is(err, ErrUnsafeDatabase) {
			if tx != nil {
				rollback(tx)
			}
			t.Errorf("%s: an UNLOGGED table accepted: %v", name, err)
		}
	}
}

// BenchmarkTransactionPreamble measures an empty transaction: its preamble
// and its commit. AGENTCAPSULE_BENCHMARK_POSTGRES, when set, names the
// database to measure on (a TCP address, to count the network).
func BenchmarkTransactionPreamble(b *testing.B) {
	dsn := os.Getenv("AGENTCAPSULE_BENCHMARK_POSTGRES")
	if dsn == "" {
		dsn = os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	}
	if dsn == "" {
		b.Skip("no database")
	}
	admin, err := pgxpool.New(b.Context(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer admin.Close()
	schema := newID("bench")
	if _, err = admin.Exec(b.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		b.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	s, err := Open(b.Context(), dsn+" search_path="+schema+",pg_catalog")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	if err = s.Migrate(b.Context()); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		tx, err := s.begin(b.Context())
		if err != nil {
			b.Fatal(err)
		}
		if err = commit(b.Context(), tx); err != nil {
			b.Fatal(err)
		}
	}
}
