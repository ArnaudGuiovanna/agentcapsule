package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// checkMailboxLease runs with the mailbox row locked, before an attempt can
// claim the head. Expiry takes precedence over a busy or exhausted lease.
func checkMailboxLease(ctx context.Context, tx pgx.Tx, m mailboxRow) error {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return err
	}
	if !m.Deadline.After(now) {
		return ErrExpired
	}
	if m.LeaseUntil != nil && m.LeaseUntil.After(now) {
		return ErrDeliveryBusy
	}
	if m.Attempts >= m.Limit {
		return ErrAttemptsExhausted
	}
	return nil
}

// takeMailboxLease consumes the attempt in both the mailbox and its outbox
// entry. The caller still holds the head's lock in the same transaction.
func takeMailboxLease(ctx context.Context, tx pgx.Tx, id string, lease time.Duration) (string, error) {
	token := newID("lease")
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET attempts=attempts+1,lease_token=$2,dispatch_authorized=false,
        lease_until=clock_timestamp()+$3::bigint*interval '1 microsecond' WHERE id=$1`, id, token, lease.Microseconds()); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1 WHERE mailbox_id=$1", id); err != nil {
		return "", err
	}
	return token, nil
}

// dispatchPending runs an attempt inside the destination's admission turn.
// A claim that finds the delivery due to retire releases admission first:
// the retirement may need another turn to fence the destination.
func (s *Store) dispatchPending(ctx context.Context, agentID, id string, runtime DeliveryRuntime, retire func() error, attempt func(context.Context) (bool, error)) error {
	// A delivery due to die needs no prepared destination: an agent that
	// never boots must not keep it, nor its mailbox, alive (EVT-005, EVT-006).
	// The retirement boots the agent only to fence an attempt that may have
	// reached it. Preparation still spends no attempt.
	if due, err := s.retirementDue(ctx, id); err != nil {
		return err
	} else if due {
		return retire()
	}
	// A disabled organization's deliveries wait, and boot no VM: they die
	// at their deadline, as above.
	if disabled, err := agentSuspended(ctx, s.pool, agentID); err != nil {
		return err
	} else if disabled {
		return errors.Join(ErrNoDelivery, ErrOrganizationDisabled)
	}
	var err error
	var shouldRetire bool
	dispatch := func(turn context.Context) error {
		var err error
		shouldRetire, err = attempt(turn)
		return err
	}
	if admission, ok := runtime.(PreparedDeliveryAdmission); ok {
		err = admission.WithPreparedDelivery(ctx, agentID, dispatch)
	} else if admission, ok := runtime.(DeliveryAdmission); ok {
		err = admission.WithDeliveryAdmission(ctx, dispatch)
	} else {
		err = dispatch(ctx)
	}
	if err != nil {
		return err
	}
	if shouldRetire {
		return retire()
	}
	return nil
}
