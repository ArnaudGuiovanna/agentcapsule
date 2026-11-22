package controlplane

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Connections are the database connections of a process (v0.1.0 audit, P-08,
// docs/install.md): how many the pool holds at most, and how long one
// statement, one lock wait and one idle transaction may last on them. A
// timeout that the database URL sets is kept; zero leaves PostgreSQL's
// default, which waits forever. The zero value is pgx's pool and
// PostgreSQL's defaults (Open).
type Connections struct {
	// MaxConns bounds the pool; 0 keeps pgx's default, max(4, processors),
	// or pool_max_conns of the database URL.
	MaxConns int32
	// StatementTimeout, LockTimeout and IdleInTransactionTimeout are the
	// session's statement_timeout, lock_timeout and
	// idle_in_transaction_session_timeout. LockTimeout bounds every lock
	// wait, row locks and advisory locks alike: a caller waiting for a lock
	// gives its pooled connection back once it is spent.
	StatementTimeout, LockTimeout, IdleInTransactionTimeout time.Duration
}

// The defaults of each process. Its longest legitimate operations fit:
//   - the API answers requests that each take milliseconds; a lock wait or a
//     statement past its bound answers 503 temporarily_unavailable;
//   - the worker's retention batches, revocation commits and archive
//     records take seconds, its transactions never wait for a guest;
//   - agentcapsule-admin's migrations and key rotations have no statement
//     bound, and a migration waits for another without bound (migrate).
var (
	APIConnections    = Connections{MaxConns: 32, StatementTimeout: time.Minute, LockTimeout: 15 * time.Second, IdleInTransactionTimeout: time.Minute}
	WorkerConnections = Connections{MaxConns: 16, StatementTimeout: 10 * time.Minute, LockTimeout: time.Minute, IdleInTransactionTimeout: 5 * time.Minute}
	AdminConnections  = Connections{MaxConns: 4, LockTimeout: time.Minute, IdleInTransactionTimeout: 10 * time.Minute}
)

// MaxPoolConnections bounds Connections.MaxConns: PostgreSQL's own
// max_connections is 100 by default.
const MaxPoolConnections = 1000

// Valid reports whether every bound is in range.
func (c Connections) Valid() bool {
	in := func(d time.Duration) bool { return d >= 0 && d <= 24*time.Hour && d%time.Millisecond == 0 }
	return c.MaxConns >= 0 && c.MaxConns <= MaxPoolConnections && in(c.StatementTimeout) && in(c.LockTimeout) && in(c.IdleInTransactionTimeout)
}

// OpenWith opens the store with a process's connections.
func OpenWith(ctx context.Context, connectionString string, c Connections) (*Store, error) {
	cfg, err := poolConfig(connectionString, c)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	tx, err := s.begin(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	rollback(tx)
	return s, nil
}

// poolConfig is the pool of OpenWith: c's bounds, and the durability check
// prepared on each connection.
func poolConfig(connectionString string, c Connections) (*pgxpool.Config, error) {
	if !c.Valid() {
		return nil, ErrInput
	}
	cfg, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, err
	}
	if c.MaxConns > 0 {
		cfg.MaxConns = c.MaxConns
		cfg.MinConns = min(cfg.MinConns, cfg.MaxConns)
	}
	// Sent in the startup message: no round trip.
	for name, d := range map[string]time.Duration{"statement_timeout": c.StatementTimeout, "lock_timeout": c.LockTimeout,
		"idle_in_transaction_session_timeout": c.IdleInTransactionTimeout} {
		if _, set := cfg.ConnConfig.RuntimeParams[name]; !set && d > 0 {
			cfg.ConnConfig.RuntimeParams[name] = strconv.FormatInt(d.Milliseconds(), 10)
		}
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, durabilityCheck)
		return err
	}
	return cfg, nil
}

// The preamble of every transaction (P-06) is one message of the simple
// protocol, BEGIN included: one round trip. It takes the gate (store.go),
// carries the API request's ID, then runs the durability check that each
// connection prepared when it opened, whose plan PostgreSQL keeps: the check
// makes the commit synchronous (SET LOCAL synchronous_commit = on) only when
// the database can keep a commit. With fsync or full_page_writes off, or a
// table of durableTables UNLOGGED (ADR 006), it sets a value PostgreSQL
// refuses (unsafeValue), and begin reports ErrUnsafeDatabase. The check runs
// in each transaction, as before: both settings change on a reload, and a
// table can be made UNLOGGED at any time.
const unsafeValue = "database durability settings are unsafe"

var (
	durabilityQuery = `SELECT pg_catalog.set_config('synchronous_commit',
  CASE WHEN pg_catalog.current_setting('fsync') = 'on' AND pg_catalog.current_setting('full_page_writes') = 'on'
    AND NOT EXISTS(SELECT FROM pg_catalog.pg_class WHERE relnamespace = pg_catalog.current_schema()::regnamespace
      AND relname = ANY('{` + strings.Join(durableTables, ",") + `}'::name[]) AND relpersistence <> 'p')
  THEN 'on' ELSE '` + unsafeValue + `' END, true)`
	durabilityCheck = `PREPARE agentcapsule_durability AS ` + durabilityQuery
)

// requestIDForm is telemetry's: 32 lowercase hex digits, which need no
// quoting.
var requestIDForm = regexp.MustCompile(`^[0-9a-f]{32}$`)

// preamble is the statement that begins a transaction with options; inline
// writes the durability check out instead of executing the prepared one.
func preamble(ctx context.Context, exclusive bool, options pgx.TxOptions, inline bool) string {
	var b strings.Builder
	b.WriteString("BEGIN ISOLATION LEVEL ")
	b.WriteString(strings.ToUpper(string(options.IsoLevel)))
	if options.AccessMode != "" {
		b.WriteString(" " + strings.ToUpper(string(options.AccessMode)))
	}
	if options.DeferrableMode != "" {
		b.WriteString(" " + strings.ToUpper(string(options.DeferrableMode)))
	}
	lock := "pg_advisory_xact_lock_shared"
	if exclusive {
		lock = "pg_advisory_xact_lock"
	}
	b.WriteString(";\nSELECT " + lock + "(hashtextextended(current_schema()::text,756610045))")
	// An API request's ID, for the operations this transaction creates
	// (migration 0027). Local to the transaction; validated by telemetry.
	if id := telemetry.RequestIDFrom(ctx); requestIDForm.MatchString(id) {
		b.WriteString(", set_config('agentcapsule.request_id','" + id + "',true)")
	}
	if inline {
		b.WriteString(";\n" + durabilityQuery)
	} else {
		b.WriteString(";\nEXECUTE agentcapsule_durability")
	}
	return b.String()
}

// beginPreamble begins a transaction with its whole preamble in one round
// trip. A preamble that fails leaves its connection in a failed transaction:
// the pool closes it. A connection that did not prepare the check (a pool
// whose own connect hook replaced poolConfig's) begins again with the check
// written out.
func (s *Store) beginPreamble(ctx context.Context, exclusive bool, options pgx.TxOptions) (pgx.Tx, error) {
	if options.IsoLevel == "" {
		options.IsoLevel = pgx.ReadCommitted
	}
	begin := options
	begin.BeginQuery = preamble(ctx, exclusive, options, false)
	tx, err := s.pool.BeginTx(ctx, begin)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "26000" {
		begin.BeginQuery = preamble(ctx, exclusive, options, true)
		tx, err = s.pool.BeginTx(ctx, begin)
	}
	if errors.As(err, &pgErr) && pgErr.Code == "22023" && strings.Contains(pgErr.Message, unsafeValue) {
		return nil, ErrUnsafeDatabase
	}
	return tx, err
}
