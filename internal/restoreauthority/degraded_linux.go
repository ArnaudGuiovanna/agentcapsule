//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

// Degraded mode of the stream (replication_linux.go has the overview).

// degradedState is the replicator's view of degraded mode, under its mu.
type degradedState struct {
	// atEpoch is set once this process has reached the replica at the
	// stream's epoch; a permanent error clears it. Only then may degraded
	// mode begin (finding 2).
	atEpoch bool
	// failing is the start of the first failed exchange since the last
	// successful one; inflight, the start of the exchange in progress.
	failing, inflight time.Time
	// since is when degraded mode began; zero outside it.
	since time.Time
	// last is the last record committed in degraded mode: degraded mode
	// ends once the replica holds it.
	last uint64
	// The log is classified up to scanned; held is the last record in it
	// that degraded mode does not let through.
	scanned, held    uint64
	watching, closed bool
	// changed is closed, and replaced, at each change of mode or position.
	changed chan struct{}
}

func newReplicator(c *Catalog, link authoritylog.Link, after time.Duration) *replicator {
	stop, cancel := context.WithCancel(context.Background())
	r := &replicator{link: link, lock: make(chan struct{}, 1), catalog: c, after: after, now: time.Now, stop: stop, cancel: cancel}
	r.changed = make(chan struct{})
	return r
}

// close stops the monitor and waits for it.
func (r *replicator) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}

// notify wakes every waiter. Under mu.
func (r *replicator) notify() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *replicator) changes() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

// setSince records the start or the end of degraded mode. Under mu.
func (r *replicator) setSince(t time.Time) {
	r.since = t
	r.metrics.Load().Degraded(t)
	r.notify()
}

// check enters degraded mode once the replica has been unreachable for the
// delay: since the first failed exchange, or for as long as the exchange in
// progress has run. Under mu.
func (r *replicator) check() {
	if !r.since.IsZero() || !r.atEpoch {
		return
	}
	start := r.failing
	if !r.inflight.IsZero() && (start.IsZero() || r.inflight.Before(start)) {
		start = r.inflight
	}
	if now := r.now(); !start.IsZero() && now.Sub(start) >= r.after {
		r.setSince(now)
	}
}

// reached records an answer of the replica at the stream's epoch. Degraded
// mode ends once the replica holds the last degraded write. Under mu, after
// learn updated known. It leaves failing alone: a replica that answers where
// it stands but applies nothing (a full or read-only disk) is still
// unreachable for the delay; only an exchange that completes clears it
// (succeeded).
func (r *replicator) reached() {
	r.atEpoch = true
	if !r.since.IsZero() && r.known.Seq >= r.last {
		r.setSince(time.Time{})
		return
	}
	r.notify()
}

// succeeded records an exchange that completed: the replica holds what it
// was sent, or there was nothing to send. Under mu.
func (r *replicator) succeeded() {
	r.failing = time.Time{}
}

// fenced reports whether err says that this process may no longer write at
// the stream's epoch: the replica refused it (another epoch, a promotion,
// another history), or the histories differ.
func fenced(err error) bool {
	var refusal *authoritylog.Refusal
	if errors.As(err, &refusal) {
		return refusal.Kind != authoritylog.RefusedGap && refusal.Kind != authoritylog.RefusedUnavailable
	}
	return errors.Is(err, authoritylog.ErrBehind) || errors.Is(err, ErrDiverged)
}

// failed records a failed exchange that started at start. Fenced, the
// process leaves degraded mode, and may not enter it again before it reaches
// the replica. Under mu.
func (r *replicator) failed(err error, start time.Time) {
	r.valid = false
	if r.failing.IsZero() {
		r.failing = start
	}
	if fenced(err) {
		r.atEpoch = false
		if !r.since.IsZero() {
			r.setSince(time.Time{})
			return
		}
	} else {
		r.check()
		r.watch()
	}
	r.notify()
}

// degraded reports whether degraded mode is on, for a writer at epoch.
func (r *replicator) degraded(epoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.check()
	return !r.since.IsZero() && r.atEpoch && r.known.Epoch == epoch
}

// degradedCommit makes the committed record seq a degraded write, if degraded
// mode is on: it then returns without the replica.
func (r *replicator) degradedCommit(epoch, seq uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.check()
	if r.since.IsZero() || !r.atEpoch || r.known.Epoch != epoch {
		return false
	}
	r.last = max(r.last, seq)
	return true
}

func (r *replicator) degradedSince() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.since
}

// admission is the barrier's answer for one transaction: run it, or wait
// until the replica holds upTo. A kind degraded mode lets through, held
// before it began, also stops waiting when it begins, to be admitted again.
type admission struct {
	ok            bool
	upTo          uint64
	untilDegraded bool
}

// admit is the barrier. In step with the replica, everything runs. In
// degraded mode, a kind it lets through runs, on records the replica may
// lack, if the replica holds every record it does not let through. Anything
// else waits. exec then keeps each statement to its operation's kind.
func (r *replicator) admit(ctx context.Context, tx *sql.Tx, state *replication, kind string) (admission, error) {
	if r.caughtUp(state.epoch, state.seq) {
		return admission{ok: true}, nil
	}
	if !authoritylog.ContinuesDegraded(kind) {
		return admission{upTo: state.seq}, nil
	}
	if !r.degraded(state.epoch) {
		return admission{upTo: state.seq, untilDegraded: true}, nil
	}
	held, err := r.heldUpTo(ctx, tx, state.epoch, state.seq)
	if err != nil {
		return admission{}, err
	}
	r.mu.Lock()
	acked := r.known.Seq
	r.mu.Unlock()
	if acked >= held {
		return admission{ok: true}, nil
	}
	return admission{upTo: held}, nil
}

// wait is the barrier's wait, for an operation of kind it did not admit.
func (r *replicator) wait(ctx context.Context, c *Catalog, epoch uint64, a admission, kind string) error {
	var enough func() bool
	if a.untilDegraded {
		enough = func() bool { return r.degraded(epoch) }
	}
	return r.sync(ctx, c, epoch, a.upTo, kind, enough)
}

// acknowledge waits for the replica to hold a record just committed. In
// degraded mode, a record of kinds it lets through is a degraded write: it
// returns without the replica.
func (r *replicator) acknowledge(ctx context.Context, c *Catalog, epoch uint64, record authoritylog.Record, kind string) error {
	var enough func() bool
	if continues(record) {
		enough = func() bool { return r.degradedCommit(epoch, record.Seq) }
	}
	return r.sync(ctx, c, epoch, record.Seq, kind, enough)
}

// heldUpTo returns the last record, up to seq, that degraded mode does not
// let through. It classifies, in the transaction, the records it has not
// seen; a record already deleted was acknowledged.
func (r *replicator) heldUpTo(ctx context.Context, tx *sql.Tx, epoch, seq uint64) (uint64, error) {
	r.mu.Lock()
	from, held := r.scanned, r.held
	if r.known.Epoch == epoch {
		from = max(from, r.known.Seq)
	}
	r.mu.Unlock()
	if from >= seq {
		return held, nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT seq,record FROM replication_log WHERE seq>? AND seq<=? ORDER BY seq", from, seq)
	if err != nil {
		return 0, errors.Join(ErrUnavailable, err)
	}
	defer rows.Close()
	for rows.Next() {
		var s uint64
		var b []byte
		if err = rows.Scan(&s, &b); err != nil {
			return 0, errors.Join(ErrUnavailable, err)
		}
		record, err := authoritylog.Decode(b)
		if err != nil || record.Seq != s {
			return 0, errors.Join(ErrUnavailable, err)
		}
		if !continues(record) {
			held = max(held, s)
		}
	}
	if err = rows.Err(); err != nil {
		return 0, errors.Join(ErrUnavailable, err)
	}
	r.mu.Lock()
	r.scanned, r.held = max(r.scanned, seq), max(r.held, held)
	r.mu.Unlock()
	return held, nil
}

// watch starts the monitor, unless it runs. Under mu.
func (r *replicator) watch() {
	if r.watching || r.closed {
		return
	}
	r.watching = true
	r.wg.Add(1)
	go r.monitor()
}

// monitor keeps reaching for the replica after a failed exchange, without
// waiting for an operation: it sees the delay pass, resends the log in order
// once the replica answers, so degraded writes first, and so ends degraded
// mode. It stops once the replica holds the whole log, when the replica
// fences this process, and at Close.
func (r *replicator) monitor() {
	defer r.wg.Done()
	delay := 20 * time.Millisecond
	for {
		epoch, tail, err := r.catalog.tail(r.stop)
		if err == nil {
			r.mu.Lock()
			r.check()
			done := r.valid && r.known.Epoch == epoch && r.known.Seq >= tail && r.since.IsZero()
			if done {
				r.watching = false
			}
			r.mu.Unlock()
			if done {
				return
			}
			select {
			case r.lock <- struct{}{}:
			case <-r.stop.Done():
				return
			}
			err = r.exchange(r.stop, r.catalog, epoch, tail)
			<-r.lock
			if err == nil {
				delay = 20 * time.Millisecond
				continue
			}
			if fenced(err) {
				r.mu.Lock()
				r.watching = false
				r.mu.Unlock()
				return
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-r.stop.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
}

// tail returns the stream's epoch and last sequence number.
func (c *Catalog) tail(ctx context.Context) (uint64, uint64, error) {
	var epoch, seq uint64
	err := c.db.QueryRowContext(ctx, "SELECT epoch,seq FROM replication WHERE singleton=1").Scan(&epoch, &seq)
	if err != nil {
		return 0, 0, errors.Join(ErrUnavailable, err)
	}
	return epoch, seq, nil
}
