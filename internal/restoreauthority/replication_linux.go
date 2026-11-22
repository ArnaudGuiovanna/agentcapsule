//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// Synchronous replication of both authorities (ADR 005, option a).
//
// Standalone mode, the default: the catalogue has no replication row, or one
// without a recipient. Nothing is logged and nothing leaves the host. The
// authorities then give no protection against the host's loss.
//
// Synchronous mode: a snapshot arms the catalogue with the recipient of the
// operator's unlock key. From then on, every transaction of either authority
// that changes state appends one record to the primary's log, in the same
// SQLite transaction, with the next sequence number of the stream. A record
// is committed on the primary when that transaction commits: its effect and
// the record are then durable together, and the record is the only thing
// left to send. The operation returns only after the replica acknowledges
// that it holds the record durably.
//
// The barrier: no transaction acts on state the replica lacks. Before its
// callback runs, a transaction compares the log's last sequence number with
// the last one the replica acknowledged; if it is behind, it rolls back,
// sends what is missing, and starts again. So an unacknowledged record left
// by a crash is resent by the next transaction of any process, from the
// replica's last sequence, before anything reads or builds on it.
//
// Crash points on the primary, for a write:
//
//  1. before the commit: nothing is durable, nothing was sent; the caller
//     retries the operation;
//  2. after the commit, before the send: the record is in the log; the next
//     transaction resends it (the barrier);
//  3. after the send, before the acknowledgment arrives: the replica may hold
//     it; the resend is a duplicate with the same content, which the replica
//     acknowledges without applying it twice;
//  4. after the acknowledgment, before the caller learns it: the caller
//     retries; the operation finds its effect and records nothing new.
//
// The key authority writes through Append, so its records share the stream
// and the barrier. The log keeps a record only until the replica acknowledges
// it: the next write deletes it, and a record carrying a wrapped key is
// deleted as soon as it is acknowledged. SQLite's secure_delete overwrites the
// deleted content.
//
// Degraded mode (ADR 005, question 2; items 16 to 18). When this process has
// failed to reach the replica for longer than the delay (30 seconds by
// default), it enters degraded mode. Every operation names its kind
// (authoritylog.WriteKinds), and each statement is classified
// (statementKinds). In degraded mode:
//
//   - the kinds degraded mode lets through (outcome records, reruns, fence
//     revisions, the start of a revocation, and reads) run without the
//     barrier, and their writes return once committed here. Their records
//     stay in the log;
//   - nothing runs on a record that degraded mode does not let through while
//     the replica lacks it: such a record, left by a write whose
//     acknowledgment never came, holds every operation until it is resent;
//   - the other kinds wait for the replica, at the barrier, before they act.
//     They fail when their context ends, with ErrWaitsForReplica.
//
// When the replica answers again, the log is resent in order, so the
// degraded writes reach it before any later write, and degraded mode ends
// once the replica holds the last of them. A monitor keeps reaching for the
// replica while the stream fails, so this happens without a new operation.
//
// Only a process that has reached the replica at the stream's epoch may
// enter degraded mode. A process that restarts, or that the replica refused
// (another epoch, a promotion, a divergence), cannot tell an unreachable
// standby from a promoted one (finding 2): it runs nothing, reads included,
// until it reaches the replica again.

// ErrNotArmed means that synchronous replication was configured for a
// catalogue that no snapshot armed.
var ErrNotArmed = errors.New("authority not armed for a replica: take a snapshot first")

// ErrReplicaRequired means that the catalogue is armed and this process has
// no link to the replica: it refuses every operation rather than write behind
// the replica's back.
var ErrReplicaRequired = errors.New("authority armed for a replica: configure the replica")

// ErrDiverged means that the primary's log and the replica disagree.
var ErrDiverged = authoritylog.ErrDiverged

// ErrWaitsForReplica means that degraded mode held the operation: it waited
// for the replica, and its context ended first. It is also ErrUnavailable.
// Retry it once the standby answers.
var ErrWaitsForReplica = errors.New("degraded mode: this authority operation waits for the replica")

// errMisclassified means that an operation ran a statement of another kind.
var errMisclassified = errors.New("authority statement outside its operation's kind")

// statement numbers are part of the record format: never renumber them, and
// never change their text without a new number. The replica runs only these.
type statement int

const (
	stmtRegister statement = iota + 1
	stmtReserveStore
	stmtReserveInsert
	stmtRevision
	stmtRevocation
	stmtFence
	stmtOutcome
	stmtSeal
	stmtLoss
	stmtRerun
	// Schema version 4 (ADR 006 wave 5): a replica of an older release does
	// not know them, and refuses the first record that carries one.
	stmtAccess
	stmtOutcomeEvent
	// Schema version 5 (holds per store and scoped revocations, after the
	// v0.1.0 audit): a replica of an older release refuses it.
	stmtScope
)

var statements = map[statement]string{
	stmtRegister:      "INSERT INTO stores(id,volume,incarnation) VALUES(?,?,1) ON CONFLICT DO NOTHING",
	stmtReserveStore:  "UPDATE stores SET incarnation=?,ack_revision=-1 WHERE id=?",
	stmtReserveInsert: "INSERT INTO reservations VALUES(?,?,?,?)",
	stmtRevision:      "UPDATE authority SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807",
	stmtRevocation:    "INSERT INTO revocations VALUES(?,?)",
	stmtFence:         "UPDATE stores SET ack_revision=? WHERE id=? AND ack_revision<=?",
	stmtOutcome:       "INSERT INTO outcomes VALUES(?,?,?) ON CONFLICT(id) DO NOTHING",
	stmtSeal:          "UPDATE stores SET sealed=1 WHERE id=?",
	stmtLoss:          "INSERT INTO losses VALUES(?,?,?) ON CONFLICT DO NOTHING",
	stmtRerun:         "INSERT INTO reruns VALUES(?,?,?) ON CONFLICT DO NOTHING",
	stmtAccess:        "INSERT INTO access_revocations VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
	stmtOutcomeEvent:  "INSERT INTO outcome_events VALUES(?,?) ON CONFLICT(outcome) DO NOTHING",
	stmtScope:         "INSERT INTO revocation_scopes VALUES(?,?,?) ON CONFLICT DO NOTHING",
}

// statementKinds classifies every statement for degraded mode
// (authoritylog.ContinuesDegraded). A new statement needs its kind here:
// TestEveryStatementAndKeyWriteIsClassified fails otherwise, and exec refuses
// a statement without one.
var statementKinds = map[statement]string{
	stmtRegister:      authoritylog.WriteRegistration,
	stmtReserveStore:  authoritylog.WriteReservation,
	stmtReserveInsert: authoritylog.WriteReservation,
	stmtRevision:      authoritylog.WriteRevocationStart,
	stmtRevocation:    authoritylog.WriteRevocationStart,
	stmtFence:         authoritylog.WriteFence,
	stmtOutcome:       authoritylog.WriteOutcome,
	stmtSeal:          authoritylog.WriteSeal,
	stmtLoss:          authoritylog.WriteLoss,
	stmtRerun:         authoritylog.WriteRerun,
	stmtAccess:        authoritylog.WriteAccess,
	stmtOutcomeEvent:  authoritylog.WriteOutcome,
	stmtScope:         authoritylog.WriteRevocationStart,
}

// allows reports whether an operation of kind may run statement s: one of its
// own kind, or the rerun that RecordOutcome records for a declared loss.
func allows(kind string, s statement) bool {
	k, ok := statementKinds[s]
	return ok && (k == kind || kind == authoritylog.WriteOutcome && k == authoritylog.WriteRerun)
}

// opKind is the kind of one operation of a record; "" when unknown.
func opKind(op authoritylog.Op) string {
	switch op.Kind {
	case authoritylog.OpStatement:
		return statementKinds[statement(op.Statement)]
	case authoritylog.OpKeyCreate, authoritylog.OpKeyRevoke:
		return keyKind(op.Kind == authoritylog.OpKeyRevoke, op.Agent, op.Volume)
	}
	return ""
}

// keyKind is the kind of a key write: a volume key's, or a daily receipt
// key's, whose creation continues in degraded mode (ADR 006, answer 4(b)).
// The receipt keys' agent with a volume that names no day has no kind.
func keyKind(revoke bool, agent, volume string) string {
	_, receipt := keyauthority.ReceiptKeyDay(agent, volume)
	switch {
	case receipt && revoke:
		return authoritylog.WriteReceiptKeyDestroy
	case receipt:
		return authoritylog.WriteReceiptKeyCreate
	case agent == keyauthority.ReceiptKeyAgent:
		return ""
	case revoke:
		return authoritylog.WriteKeyDestroy
	}
	return authoritylog.WriteKeyCreate
}

// continues reports whether degraded mode lets every operation of r through.
func continues(r authoritylog.Record) bool {
	for _, op := range r.Ops {
		if !authoritylog.ContinuesDegraded(opKind(op)) {
			return false
		}
	}
	return len(r.Ops) > 0
}

// replicationSchema is version 3: the primary's side of the stream.
const replicationSchema = `
CREATE TABLE replication (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 epoch INTEGER NOT NULL CHECK(epoch>0),
 recipient BLOB CHECK(recipient IS NULL OR length(recipient)=32),
 seq INTEGER NOT NULL CHECK(seq>=0),
 digest BLOB NOT NULL CHECK(length(digest)=32)
);
CREATE TABLE replication_log (seq INTEGER PRIMARY KEY NOT NULL CHECK(seq>0), record BLOB NOT NULL);
PRAGMA user_version=3;
`

// replication is the stream's row; nil when the catalogue never had one.
type replication struct {
	epoch     uint64
	recipient []byte
	seq       uint64
	digest    []byte
}

func (r *replication) armed() bool { return r != nil && r.recipient != nil }

func readReplication(ctx context.Context, tx *sql.Tx) (*replication, error) {
	r := &replication{}
	err := tx.QueryRowContext(ctx, "SELECT epoch,recipient,seq,digest FROM replication WHERE singleton=1").Scan(&r.epoch, &r.recipient, &r.seq, &r.digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || len(r.digest) != 32 || (r.recipient != nil && len(r.recipient) != 32) {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return r, nil
}

// txRecord collects the operations of one transaction of kind.
type txRecord struct {
	state *replication
	ops   []authoritylog.Op
	kind  string
}

func (c *Catalog) recordingOf(tx *sql.Tx) *txRecord {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	return c.recording[tx]
}

// exec runs one of the fixed statements and records it when it changed rows.
// Statements that change nothing are left out: replaying them changes nothing.
// The statement must be of its operation's kind: so an operation that
// degraded mode lets through never writes a kind that waits.
func (c *Catalog) exec(ctx context.Context, tx *sql.Tx, s statement, args ...any) (sql.Result, error) {
	rec := c.recordingOf(tx)
	if rec == nil || !allows(rec.kind, s) {
		return nil, errors.Join(ErrUnavailable, errMisclassified)
	}
	result, err := tx.ExecContext(ctx, statements[s], args...)
	if err != nil {
		return nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows > 0 && rec.state.armed() {
		op := authoritylog.Op{Kind: authoritylog.OpStatement, Statement: int(s), Rows: rows}
		for _, a := range args {
			arg, err := authoritylog.ArgOf(a)
			if err != nil {
				return nil, errors.Join(ErrInput, err)
			}
			op.Args = append(op.Args, arg)
		}
		rec.ops = append(rec.ops, op)
	}
	return result, nil
}

// appendRecord adds the transaction's record to the log, after deleting the
// records the replica acknowledged.
func (c *Catalog) appendRecord(ctx context.Context, tx *sql.Tx, state *replication, ops []authoritylog.Op) (authoritylog.Record, error) {
	r := authoritylog.Record{Version: authoritylog.Version, Epoch: state.epoch, Seq: state.seq + 1, Prev: state.digest, Ops: ops}
	b, err := r.Encode()
	if err != nil {
		return r, errors.Join(ErrInput, err)
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM replication_log WHERE seq<=?", c.repl.acknowledged(state.epoch)); err != nil {
		return r, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO replication_log VALUES(?,?)", r.Seq, b); err != nil {
		return r, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE replication SET seq=?,digest=? WHERE singleton=1 AND seq=?", r.Seq, authoritylog.Digest(b), state.seq)
	if err != nil {
		return r, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return r, errors.Join(ErrUnavailable, err)
	}
	return r, nil
}

// readLog returns the logged records after from, up to upTo, in order.
func (c *Catalog) readLog(ctx context.Context, from, upTo uint64) ([][]byte, uint64, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT seq,record FROM replication_log WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?", from, upTo, authoritylog.MaxRecords)
	if err != nil {
		return nil, 0, errors.Join(ErrUnavailable, err)
	}
	defer rows.Close()
	var records [][]byte
	var first, last uint64
	for rows.Next() {
		var seq uint64
		var b []byte
		if err = rows.Scan(&seq, &b); err != nil {
			return nil, 0, errors.Join(ErrUnavailable, err)
		}
		if first == 0 {
			first = seq
		} else if seq != last+1 {
			return nil, 0, ErrUnavailable
		}
		last = seq
		records = append(records, b)
	}
	return records, first, rows.Err()
}

// logged returns the digest of the logged record seq, if the log holds it,
// and the stream's last sequence number.
func (c *Catalog) logged(ctx context.Context, seq uint64) ([]byte, uint64, error) {
	var tail uint64
	if err := c.db.QueryRowContext(ctx, "SELECT seq FROM replication WHERE singleton=1").Scan(&tail); err != nil {
		return nil, 0, errors.Join(ErrUnavailable, err)
	}
	var b []byte
	err := c.db.QueryRowContext(ctx, "SELECT record FROM replication_log WHERE seq=?", seq).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tail, nil
	}
	if err != nil {
		return nil, 0, errors.Join(ErrUnavailable, err)
	}
	return authoritylog.Digest(b), tail, nil
}

// prune deletes acknowledged records at once, for those that carry a wrapped
// key. A failure leaves them to the next write.
func (c *Catalog) prune(ctx context.Context, seq uint64) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM replication_log WHERE seq<=?", seq); err == nil {
		_ = tx.Commit()
	}
}

// replicator is a process's end of the stream.
type replicator struct {
	link    authoritylog.Link
	metrics atomic.Pointer[authoritylog.Metrics]
	lock    chan struct{} // one exchange at a time
	catalog *Catalog
	after   time.Duration    // degraded mode after this long without the replica
	now     func() time.Time // the clock of degraded mode; tests replace it
	stop    context.Context  // ends the monitor, at Close
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	mu    sync.Mutex
	known authoritylog.Position // the replica's last position seen by this process
	valid bool
	degradedState
}

func (r *replicator) acknowledged(epoch uint64) uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid || r.known.Epoch != epoch {
		return 0
	}
	return r.known.Seq
}

func (r *replicator) position(epoch uint64) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.known.Seq, r.valid && r.known.Epoch == epoch
}

// caughtUp reports whether the replica holds every record up to seq, as
// this process learned from it since its last failed exchange. A process
// that never reached the replica is never caught up, even at sequence 0.
func (r *replicator) caughtUp(epoch, seq uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.valid && r.known.Epoch == epoch && r.known.Seq >= seq
}

// permanent errors stop a sync at once; the others are retried until the
// context ends.
func permanent(err error) bool {
	var refusal *authoritylog.Refusal
	if errors.As(err, &refusal) {
		return refusal.Kind != authoritylog.RefusedGap && refusal.Kind != authoritylog.RefusedUnavailable
	}
	return errors.Is(err, authoritylog.ErrBehind) || errors.Is(err, ErrDiverged) || errors.Is(err, ErrUnavailable) ||
		errors.Is(err, ErrInput) || errors.Is(err, authoritylog.ErrRecord)
}

// sync returns once the replica holds every record up to upTo, or once
// enough, when not nil, holds. kind is the waiting operation's, for the
// metrics.
func (r *replicator) sync(ctx context.Context, c *Catalog, epoch, upTo uint64, kind string, enough func() bool) error {
	waiting := false
	defer func() {
		if waiting {
			r.metrics.Load().Waiting(kind, -1)
		}
	}()
	// done reports whether the wait is over; it counts a wait in degraded mode.
	done := func() bool {
		if r.caughtUp(epoch, upTo) || enough != nil && enough() {
			return true
		}
		if !waiting && r.degraded(epoch) {
			waiting = true
			r.metrics.Load().Waiting(kind, 1)
		}
		return false
	}
	var last error
	gaveUp := func() error {
		if waiting {
			r.metrics.Load().GaveUp(kind)
			return errors.Join(ErrUnavailable, ErrWaitsForReplica, last, ctx.Err())
		}
		return errors.Join(ErrUnavailable, last, ctx.Err())
	}
	// Another exchange may hold the link: wake on its news, and at least
	// every pollEvery to see the delay pass.
	for !done() {
		changed := r.changes()
		poll := time.NewTimer(pollEvery)
		select {
		case r.lock <- struct{}{}:
			poll.Stop()
			err := r.syncHolding(ctx, c, epoch, upTo, done)
			<-r.lock
			if err == nil {
				return nil
			}
			last = err
			if ctx.Err() != nil {
				return gaveUp()
			}
			if permanent(err) {
				return errors.Join(ErrUnavailable, err)
			}
		case <-changed:
			poll.Stop()
		case <-poll.C:
		case <-ctx.Done():
			poll.Stop()
			return gaveUp()
		}
	}
	return nil
}

// pollEvery bounds how long a waiting operation goes without looking at the
// stream's state.
const pollEvery = 100 * time.Millisecond

// syncHolding retries the exchange, holding the link, until done or the
// context ends. It returns the last error, nil when done.
func (r *replicator) syncHolding(ctx context.Context, c *Catalog, epoch, upTo uint64, done func() bool) error {
	delay := 20 * time.Millisecond
	for !done() {
		err := r.exchange(ctx, c, epoch, upTo)
		if err == nil {
			delay = 20 * time.Millisecond
			continue
		}
		if permanent(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
	return nil
}

// exchange is one attempt, with the link held. It keeps the time of an
// exchange in progress, and of the first failure, for the degraded delay.
func (r *replicator) exchange(ctx context.Context, c *Catalog, epoch, upTo uint64) error {
	r.mu.Lock()
	start := r.now()
	r.inflight = start
	r.mu.Unlock()
	err := r.attempt(ctx, c, epoch, upTo)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight = time.Time{}
	if err == nil {
		r.succeeded()
		return nil
	}
	r.metrics.Load().Failed(err)
	r.failed(err, start)
	return err
}

func (c *Catalog) request(epoch uint64, records [][]byte) authoritylog.Request {
	return authoritylog.Request{RestoreAuthority: c.identity, KeyAuthority: c.keyIdentity, Epoch: epoch, Records: records}
}

func (r *replicator) attempt(ctx context.Context, c *Catalog, epoch, upTo uint64) error {
	from, known := r.position(epoch)
	var records [][]byte
	var first uint64
	var err error
	if known {
		if records, first, err = c.readLog(ctx, from, upTo); err != nil {
			return err
		}
	}
	if !known || len(records) == 0 || first != from+1 {
		// Ask where the replica stands, then send from there.
		position, err := r.link.Sync(ctx, c.request(epoch, nil))
		if err != nil {
			return err
		}
		if err = r.learn(ctx, c, epoch, position); err != nil || position.Seq >= upTo {
			return err
		}
		if records, first, err = c.readLog(ctx, position.Seq, upTo); err != nil {
			return err
		}
		if len(records) == 0 || first != position.Seq+1 {
			return authoritylog.ErrBehind
		}
	}
	position, err := r.link.Sync(ctx, c.request(epoch, records))
	if err != nil {
		return err
	}
	if position.Seq < first+uint64(len(records))-1 {
		return authoritylog.ErrProtocol
	}
	return r.learn(ctx, c, epoch, position)
}

// learn checks the replica's answer against the primary's own history.
func (r *replicator) learn(ctx context.Context, c *Catalog, epoch uint64, p authoritylog.Position) error {
	if p.Epoch != epoch || len(p.Digest) != 32 {
		return authoritylog.ErrProtocol
	}
	digest, tail, err := c.logged(ctx, p.Seq)
	if err != nil {
		return err
	}
	if p.Seq > tail || (digest != nil && !bytes.Equal(digest, p.Digest)) {
		return ErrDiverged // the primary was set back, or the histories differ
	}
	r.mu.Lock()
	if r.valid && r.known.Epoch == epoch && p.Seq < r.known.Seq {
		r.mu.Unlock()
		return authoritylog.ErrBehind // the replica lost acknowledged records
	}
	r.known, r.valid = p, true
	r.reached()
	r.mu.Unlock()
	r.metrics.Load().Acknowledged(p.Seq)
	return nil
}

// ReplicationState is the catalogue's side of the stream.
type ReplicationState struct {
	// Armed is true once a snapshot armed the catalogue for a replica.
	Armed     bool
	Recipient authoritylog.Recipient
	// Committed is the last record committed on this host; Seq 0 when none.
	Committed authoritylog.Position
}

// Replication reads the stream's state. It works without a link.
func (c *Catalog) Replication(ctx context.Context) (ReplicationState, error) {
	var s ReplicationState
	err := c.run(ctx, false, func(tx *sql.Tx) error {
		v, err := version(ctx, tx)
		if err != nil || v < 3 {
			return err
		}
		r, err := readReplication(ctx, tx)
		if err != nil || r == nil {
			return err
		}
		s.Armed = r.armed()
		copy(s.Recipient[:], r.recipient)
		s.Committed = authoritylog.Position{Epoch: r.epoch, Seq: r.seq, Digest: r.digest}
		return nil
	})
	return s, err
}

// Replicate makes this catalogue, and the key authority whose journal it
// becomes, synchronous with the replica behind link, with the default delay
// before degraded mode. Call it once, after Open and before any use. The
// catalogue must be armed.
func (c *Catalog) Replicate(ctx context.Context, link authoritylog.Link) error {
	return c.ReplicateWith(ctx, link, ReplicationOptions{})
}

// ReplicationOptions tune the link to the replica.
type ReplicationOptions struct {
	// DegradedAfter is how long the replica may stay unreachable before
	// degraded mode begins: authoritylog.DefaultDegradedAfter when zero,
	// else between authoritylog.MinDegradedAfter and MaxDegradedAfter.
	DegradedAfter time.Duration
}

// ReplicateWith is Replicate with options.
func (c *Catalog) ReplicateWith(ctx context.Context, link authoritylog.Link, o ReplicationOptions) error {
	after := cmp.Or(o.DegradedAfter, authoritylog.DefaultDegradedAfter)
	if link == nil || after < authoritylog.MinDegradedAfter || after > authoritylog.MaxDegradedAfter {
		return ErrInput
	}
	s, err := c.Replication(ctx)
	if err != nil {
		return err
	}
	if !s.Armed {
		return ErrNotArmed
	}
	c.repl.close()
	c.repl = newReplicator(c, link, after)
	return nil
}

// ReachReplica starts the monitor now, without waiting for an operation: it
// reaches the replica in the background, and keeps trying while the replica
// does not answer. Until it does, this process runs nothing, reports
// waiting, and may not enter degraded mode (finding 2), as before. The
// authority service calls it at start: an idle service then reports its
// mode, and its failed attempts reach the metrics and the alerts. Without a
// link to a replica it does nothing.
func (c *Catalog) ReachReplica() {
	if c.repl == nil {
		return
	}
	c.repl.mu.Lock()
	defer c.repl.mu.Unlock()
	c.repl.watch()
}

// ObserveReplication sends the stream's metrics to m. Without a link it
// records the standalone mode.
func (c *Catalog) ObserveReplication(m *authoritylog.Metrics) {
	if c.repl == nil {
		m.Enabled(false)
		return
	}
	c.repl.metrics.Store(m)
	m.Enabled(true)
	m.Degraded(c.repl.degradedSince())
}

// Append is the key authority's journal: one stream for both authorities.
var _ keyauthority.Journal = (*Catalog)(nil)

// Append runs write in a catalogue transaction, after the barrier, and
// records the key change it returns, wrapped to the unlock key's recipient.
// Both kinds of volume key write wait for the replica in degraded mode,
// before write runs. A daily receipt key's have their own kinds (ADR 006
// §7): its creation continues in degraded mode, its destruction waits.
//
// A volume key's destruction is refused before write runs unless this
// catalogue holds the store (the agent's ID) sealed with that volume
// (ErrNotSealed, ADR 006 §3). The check runs in the transaction that records
// the destruction, so that the seal is in the stream before it: a replica
// that holds the destruction holds the seal. A receipt key has no store, so
// no seal: the authority service destroys it once its day's receipts have
// expired.
func (c *Catalog) Append(ctx context.Context, intent keyauthority.Change, write func() (*keyauthority.Change, error)) error {
	if write == nil || intent.Key != nil {
		return ErrInput
	}
	kind := keyKind(intent.Revoke, intent.Agent, intent.Volume)
	if kind == "" {
		return ErrInput // the receipt keys' agent names days only
	}
	receipt := kind == authoritylog.WriteReceiptKeyCreate || kind == authoritylog.WriteReceiptKeyDestroy
	return c.operate(ctx, kind, func(tx *sql.Tx) error {
		rec := c.recordingOf(tx)
		if rec == nil || !rec.state.armed() || c.repl == nil {
			return ErrUnavailable
		}
		if intent.Revoke && !receipt {
			if err := sealedWith(ctx, tx, intent.Agent, intent.Volume, 0); err != nil {
				return err
			}
		}
		change, err := write()
		if change != nil {
			defer clear(change.Key)
		}
		if err != nil || change == nil {
			return err
		}
		if change.Revoke != intent.Revoke || change.Agent != intent.Agent || change.Volume != intent.Volume {
			return ErrInput
		}
		op, err := c.keyOp(rec.state, change)
		if err != nil {
			return err
		}
		rec.ops = append(rec.ops, op)
		return nil
	})
}

func (c *Catalog) keyOp(state *replication, change *keyauthority.Change) (authoritylog.Op, error) {
	op := authoritylog.Op{Kind: authoritylog.OpKeyRevoke, Agent: change.Agent, Volume: change.Volume}
	if !authoritylog.ValidID(change.Agent, "agt_") || !authoritylog.ValidID(change.Volume, "vol_") {
		return op, ErrInput
	}
	if change.Revoke {
		return op, nil
	}
	if len(change.Key) != 32 {
		return op, ErrInput
	}
	var recipient authoritylog.Recipient
	copy(recipient[:], state.recipient)
	wrapped, err := authoritylog.Seal(recipient, authoritylog.KeyContext(c.keyIdentity, change.Agent, change.Volume), change.Key)
	if err != nil {
		return op, errors.Join(ErrUnavailable, err)
	}
	op.Kind, op.Wrapped = authoritylog.OpKeyCreate, wrapped
	op.Commitment = authoritylog.KeyCommitment(c.keyIdentity, change.Agent, change.Volume, change.Key)
	return op, nil
}
