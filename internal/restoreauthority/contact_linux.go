//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// The standby's last contact with the primary (docs/adr/005-keys-outside-restored-domain.md,
// "What the code must do", item 14; docs/adr/006-authority-service.md §7,
// wave 7).
//
// Degraded mode begins only after the primary has failed to reach the
// replica for the degraded delay, counted from an exchange that started after
// its last success. The replica answers a request only once it has written
// the time that request arrived: so every success the primary saw came after
// a contact the replica holds on disk, and no degraded period began less than
// the delay after the last contact. The promotion compares that contact with
// the failover: within the delay, no degraded period ran; beyond it, one may
// have, and the promotion announces the window from the last contact.
//
// The replica writes at most one contact per contactEvery: the time on disk
// may be older than the last contact by that much, which only widens the
// window. A replica that never answered holds none: its primary never reached
// it at this epoch, so it never entered degraded mode (finding 2).
//
// An idle primary reaches its replica every heartbeat (KeepContact), so the
// contact is that recent even when nothing is written.

// contactEvery bounds how often the replica writes its last contact.
const contactEvery = time.Second

// contactSchema is the replica's own table of its last contact. It is not
// part of the snapshot's schema: the replica creates it at its first contact.
const contactSchema = `CREATE TABLE IF NOT EXISTS replica_contact (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 contact_at INTEGER NOT NULL CHECK(contact_at>0)
)`

func (r *Replica) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// contact writes at, the arrival of a request the replica is about to
// answer, as its last contact. Under r.lock.
func (r *Replica) contact(ctx context.Context, at time.Time) error {
	if !r.contacted.IsZero() && at.Before(r.contacted.Add(contactEvery)) {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, contactSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO replica_contact VALUES(1,?)
  ON CONFLICT(singleton) DO UPDATE SET contact_at=max(contact_at,excluded.contact_at)`, at.UnixMilli()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	r.contacted = at
	return nil
}

// lastContact reads the replica's last contact; zero when it has none.
func lastContact(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (time.Time, error) {
	if _, err := q.ExecContext(ctx, contactSchema); err != nil {
		return time.Time{}, err
	}
	var ms int64
	err := q.QueryRowContext(ctx, "SELECT contact_at FROM replica_contact WHERE singleton=1").Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms), nil
}

// LastContact is the replica's last contact with the primary: the arrival
// of the last request it answered, to within contactEvery; zero when it
// answered none.
func (r *Replica) LastContact(ctx context.Context) (time.Time, error) {
	return lastContact(ctx, r.db)
}

// KeepContact makes this catalogue's link reach the replica at least every
// every while it is linked: an exchange that only asks where the replica
// stands, when nothing else ran meanwhile. The standby's last contact is then
// at most that old, even when nothing is written, and an idle primary also
// learns at once that its standby went away. Without a link it does nothing.
// It stops at Close, or once the replica fences this process.
func (c *Catalog) KeepContact(every time.Duration) {
	r := c.repl
	if r == nil || every <= 0 {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop.Done():
				return
			case <-ticker.C:
			}
			// An exchange in progress is a contact already.
			select {
			case r.lock <- struct{}{}:
			default:
				continue
			}
			epoch, tail, err := c.tail(r.stop)
			if err == nil {
				err = r.exchange(r.stop, c, epoch, tail)
			}
			<-r.lock
			if err != nil && fenced(err) {
				return
			}
		}
	}()
}

// HeartbeatEvery is the heartbeat of a link whose degraded delay is after:
// a sixth of it, and at least half a second.
func HeartbeatEvery(after time.Duration) time.Duration {
	return max(after/6, 500*time.Millisecond)
}
