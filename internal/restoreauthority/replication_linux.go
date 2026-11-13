//go:build linux && cgo

package restoreauthority

import (
	"bytes"
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

// ErrNotArmed means that synchronous replication was configured for a
// catalogue that no snapshot armed.
var ErrNotArmed = errors.New("authority not armed for a replica: take a snapshot first")

// ErrReplicaRequired means that the catalogue is armed and this process has
// no link to the replica: it refuses every operation rather than write behind
// the replica's back.
var ErrReplicaRequired = errors.New("authority armed for a replica: configure the replica")

// ErrDiverged means that the primary's log and the replica disagree.
var ErrDiverged = authoritylog.ErrDiverged

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

// txRecord collects the operations of one transaction.
type txRecord struct {
	state *replication
	ops   []authoritylog.Op
}

func (c *Catalog) recordingOf(tx *sql.Tx) *txRecord {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	return c.recording[tx]
}

// exec runs one of the fixed statements and records it when it changed rows.
// Statements that change nothing are left out: replaying them changes nothing.
func (c *Catalog) exec(ctx context.Context, tx *sql.Tx, s statement, args ...any) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, statements[s], args...)
	if err != nil {
		return nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rec := c.recordingOf(tx); rec != nil && rows > 0 && rec.state.armed() {
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
	mu      sync.Mutex
	known   authoritylog.Position // the replica's last position seen by this process
	valid   bool
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

func (r *replicator) invalidate() {
	r.mu.Lock()
	r.valid = false
	r.mu.Unlock()
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

// sync returns once the replica holds every record up to upTo.
func (r *replicator) sync(ctx context.Context, c *Catalog, epoch, upTo uint64) error {
	select {
	case r.lock <- struct{}{}:
	case <-ctx.Done():
		return errors.Join(ErrUnavailable, ctx.Err())
	}
	defer func() { <-r.lock }()
	delay := 20 * time.Millisecond
	for {
		if r.acknowledged(epoch) >= upTo {
			return nil
		}
		err := r.attempt(ctx, c, epoch, upTo)
		if err == nil {
			continue
		}
		r.metrics.Load().Failed(err)
		r.invalidate()
		if permanent(err) {
			return errors.Join(ErrUnavailable, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ErrUnavailable, err, ctx.Err())
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
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
// becomes, synchronous with the replica behind link. Call it once, after Open
// and before any use. The catalogue must be armed.
func (c *Catalog) Replicate(ctx context.Context, link authoritylog.Link) error {
	if link == nil {
		return ErrInput
	}
	s, err := c.Replication(ctx)
	if err != nil {
		return err
	}
	if !s.Armed {
		return ErrNotArmed
	}
	c.repl = &replicator{link: link, lock: make(chan struct{}, 1)}
	return nil
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
}

// Append is the key authority's journal: one stream for both authorities.
var _ keyauthority.Journal = (*Catalog)(nil)

// Append runs write in a catalogue transaction, after the barrier, and
// records the key change it returns, wrapped to the unlock key's recipient.
func (c *Catalog) Append(ctx context.Context, write func() (*keyauthority.Change, error)) error {
	if write == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		rec := c.recordingOf(tx)
		if rec == nil || !rec.state.armed() || c.repl == nil {
			return ErrUnavailable
		}
		change, err := write()
		if change != nil {
			defer clear(change.Key)
		}
		if err != nil || change == nil {
			return err
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
