package audit

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// The feed's horizon (migration append-only-audit, finding L-03). Each event
// of the feed's tables is stamped (created_at, or replayed_at) once its
// transaction holds its organization's feed lock in shared mode, which it
// keeps until it commits; a lock is released only once its transaction's
// commit is visible. A reader takes the time, then the lock's holders, and
// waits for those to end: every event stamped before that time is then
// committed or rolled back, and every later one is stamped after it. The
// feed pages on (created_at, id) up to that time, so that an event that
// commits late is never behind a cursor already given. The reader takes no
// lock: writers never wait for it.

// auditFeedLock is the first key of an organization's feed lock; the second
// is hashtext of its schema and its ID, "<schema>/<id>" (stamp_audit_event):
// the table's schema there, the transaction's current schema here, which is
// the store's (connections.go). A page never waits for the writers of
// another schema of the database.
const auditFeedLock = 756610047

// auditWriterWait bounds how long a page waits for the organization's
// audited transactions still open when it was asked for.
const auditWriterWait = 5 * time.Second

// ErrBusy: an audited transaction of the organization stayed open
// longer than auditWriterWait. Nothing is lost: ask again.
var ErrBusy = errors.New("an audited transaction of the organization is still open; retry")

// auditWriters are the transactions that hold the organization's feed lock,
// among $3 when it is not null.
const auditWriters = `SELECT coalesce(array_agg(virtualtransaction),'{}') FROM pg_locks
    WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
      AND classid=$1::bigint::oid AND objid=(hashtext(current_schema()||'/'||$2)::bigint & 4294967295)::oid AND objsubid=2 AND granted
      AND ($3::text[] IS NULL OR virtualtransaction=ANY($3::text[]))`

// Horizon returns the time before which the organization's trail is
// complete for this transaction's next statements.
func Horizon(ctx context.Context, tx pgx.Tx, tenant string) (time.Time, error) {
	var horizon time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&horizon); err != nil {
		return time.Time{}, err
	}
	var open []string
	if err := tx.QueryRow(ctx, auditWriters, auditFeedLock, tenant, nil).Scan(&open); err != nil {
		return time.Time{}, err
	}
	deadline := time.Now().Add(auditWriterWait)
	for len(open) > 0 {
		if !time.Now().Before(deadline) {
			return time.Time{}, ErrBusy
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		if err := tx.QueryRow(ctx, auditWriters, auditFeedLock, tenant, open).Scan(&open); err != nil {
			return time.Time{}, err
		}
	}
	return horizon, nil
}
