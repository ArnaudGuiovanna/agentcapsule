// Package mailbox owns FIFO ordering and durable lease transitions for agent mailboxes.
package mailbox

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// A Reader can look up the destination head and its retirement state on the pool or inside a transaction.
type Reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

var (
	ErrNoDelivery        = errors.New("no pending delivery")
	ErrNotHead           = errors.New("delivery is not the FIFO head")
	ErrDeliveryBusy      = errors.New("delivery lease is active")
	ErrLeaseLost         = errors.New("delivery lease is no longer current")
	ErrAttemptsExhausted = errors.New("delivery attempt budget exhausted")
	ErrDeliveryClosing   = errors.New("delivery is waiting for its durable barrier")
)

type Row struct {
	ID, Destination, Kind, State, Token string
	StatusReason                        string
	Sequence                            int64
	Attempts, Limit                     int
	Closing                             bool
	MayHaveReached                      bool
	Deadline                            time.Time
	LeaseUntil                          *time.Time
}

func firstPending(ctx context.Context, db Reader, destination string) (string, error) {
	var id string
	err := db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE dest_agent_id=$1 AND delivery_state='PENDING' ORDER BY seq LIMIT 1", destination).Scan(&id)
	return id, err
}

// HeadDelivery returns the destination's first pending delivery.
func HeadDelivery(ctx context.Context, db Reader, agentID string) (string, error) {
	id, err := firstPending(ctx, db, agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNoDelivery
	}
	return id, err
}

// RequireHead checks that the locked row is still the first pending delivery.
func RequireHead(ctx context.Context, tx pgx.Tx, m Row) error {
	if m.State != "PENDING" {
		return ErrNoDelivery
	}
	first, err := firstPending(ctx, tx, m.Destination)
	if err != nil {
		return err
	}
	if first != m.ID {
		return ErrNotHead
	}
	return nil
}

// CheckLease runs with the mailbox row locked, before an attempt can
// claim the head. Expiry takes precedence over a busy or exhausted lease.
func CheckLease(ctx context.Context, tx pgx.Tx, m Row) error {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return err
	}
	if !m.Deadline.After(now) {
		return persistence.ErrExpired
	}
	if m.LeaseUntil != nil && m.LeaseUntil.After(now) {
		return ErrDeliveryBusy
	}
	if m.Attempts >= m.Limit {
		return ErrAttemptsExhausted
	}
	return nil
}

// TakeLease consumes the attempt in both the mailbox and its outbox
// entry. The caller still holds the head's lock in the same transaction.
func TakeLease(ctx context.Context, tx pgx.Tx, id string, lease time.Duration) (string, error) {
	token := persistence.ID("lease")
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET attempts=attempts+1,lease_token=$2,dispatch_authorized=false,
        lease_until=clock_timestamp()+$3::bigint*interval '1 microsecond' WHERE id=$1`, id, token, lease.Microseconds()); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1 WHERE mailbox_id=$1", id); err != nil {
		return "", err
	}
	return token, nil
}

// RetirementDue reports whether a pending reply, status or instruction is to
// be retired, however its destination fares: closing, past its deadline, or
// out of attempts with no live lease. A request is closed by its own closure;
// a delivery to an agent being deleted is canceled by the deletion. It reads
// without locks: the retirement checks the agents again under theirs.
func RetirementDue(ctx context.Context, db Reader, id string) (bool, error) {
	var due bool
	err := db.QueryRow(ctx, `SELECT m.kind<>'request' AND m.delivery_state='PENDING' AND a.phase='LIVE' AND (m.closing
        OR m.expires_at<=clock_timestamp() OR m.attempts>=m.attempt_limit AND (m.lease_until IS NULL OR m.lease_until<=clock_timestamp()))
        FROM agent_mailboxes m JOIN agents a ON a.id=m.dest_agent_id WHERE m.id=$1`, id).Scan(&due)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return due, err
}
