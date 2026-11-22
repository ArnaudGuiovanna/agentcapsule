package controlplane

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	return &Store{pool: pool}, counter
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
