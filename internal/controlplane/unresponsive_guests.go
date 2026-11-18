package controlplane

import (
	"context"
	"errors"
	"fmt"
)

// UnresponsiveGuestError is what a runtime's Fence returns when the guest of
// the agent's running VM, booted for work, did not answer the fence in time,
// or answered that it could not fence: its harness holds its store, or does
// not answer at all. Generation is that boot's. A runtime never returns it
// for the platform's own failure: an authority, PostgreSQL or the host
// failing, or the caller's deadline (ADR 012, question 7).
type UnresponsiveGuestError struct {
	Generation uint64
	Err        error
}

func (e *UnresponsiveGuestError) Error() string {
	return fmt.Sprintf("the guest of generation %d did not answer its fence: %v", e.Generation, e.Err)
}

func (e *UnresponsiveGuestError) Unwrap() error { return e.Err }

// UnresponsiveGuestStopper is implemented by the product worker.
// StopUnresponsiveGuest stops the agent's VM of that generation if it still
// runs, booted for work: a quiesce, then a forced stop, as a sleep does. It
// records a guest failure of kind GuestUnresponsive for that generation,
// which counts against the agent's restart budget while the agent is live
// (ObserveGuestFailure). It does nothing for a VM that is gone or was
// replaced.
type UnresponsiveGuestStopper interface {
	StopUnresponsiveGuest(ctx context.Context, agentID string, generation uint64) error
}

// fencePastAttempts fences subject in target's store, for a delivery that
// dies or a request that closes. When target's guest refuses the fence
// (UnresponsiveGuestError) while target's mailbox is held by a delivery past
// its attempts (deliveryStuck), the runtime stops that VM, and the fence is
// tried again: with no VM running, the runtime fences through a restricted
// boot, which runs no work (ADR 012, question 7, option (b)). Otherwise the
// failure is returned, and the caller's job tries again later.
func (s *Store) fencePastAttempts(ctx context.Context, runtime RevocationRuntime, target, subject string) error {
	return fenceStoppingRefusal(ctx, runtime, target, subject, func() (bool, error) { return s.deliveryStuck(ctx, target) })
}

// fenceDeletion fences the deletion of agentID in target's store. When
// target is agentID itself and the guest of its running VM refuses the
// fence (UnresponsiveGuestError), its harness holds the store: the runtime
// stops that VM, and the fence is tried again, through a restricted boot
// (ADR 012, question 7, sub-question 2, option (b)). No delivery need be
// past its attempts: the deletion cancels all of the agent's work, and no
// attempt can begin once the deletion is requested. Any other failure, and
// a refusal by another agent's guest, live, are returned, and the
// deletion's job tries again later.
func fenceDeletion(ctx context.Context, runtime RevocationRuntime, agentID, target string) error {
	return fenceStoppingRefusal(ctx, runtime, target, "agent/"+agentID, func() (bool, error) { return target == agentID, nil })
}

// fenceStoppingRefusal fences subject in target's store. When target's
// running guest refuses (UnresponsiveGuestError), the runtime can stop a VM
// and stoppable allows it, the runtime stops that VM of the refusing
// generation, and the fence is tried again: with no VM running, it goes
// through a restricted boot. Otherwise the fence's failure is returned.
func fenceStoppingRefusal(ctx context.Context, runtime RevocationRuntime, target, subject string, stoppable func() (bool, error)) error {
	err := runtime.Fence(ctx, target, subject)
	var refused *UnresponsiveGuestError
	stopper, ok := runtime.(UnresponsiveGuestStopper)
	if err == nil || !ok || !errors.As(err, &refused) {
		return err
	}
	stop, checkErr := stoppable()
	if checkErr != nil {
		return errors.Join(err, checkErr)
	}
	if !stop {
		return err
	}
	if err = stopper.StopUnresponsiveGuest(ctx, target, refused.Generation); err != nil {
		return err
	}
	return runtime.Fence(ctx, target, subject)
}

// deliveryStuck reports whether target's mailbox is held by a delivery past
// its attempts: its head, pending, which an attempt may have reached, with
// no attempt under way (no live lease), and which can no longer be
// attempted: closing, past its deadline, or with its attempts spent. Only
// then may a refused fence stop the guest's VM: the harness had every
// attempt, each bounded by the host's timeout, and still holds its store
// with none under way. A guest busy with an attempt is never stopped.
func (s *Store) deliveryStuck(ctx context.Context, target string) (bool, error) {
	var stuck bool
	err := s.pool.QueryRow(ctx, `SELECT coalesce((SELECT m.may_have_reached
        AND (m.lease_until IS NULL OR m.lease_until<=clock_timestamp())
        AND (m.closing OR m.expires_at<=clock_timestamp() OR m.attempts>=m.attempt_limit)
        FROM agent_mailboxes m WHERE m.dest_agent_id=$1 AND m.delivery_state='PENDING' ORDER BY m.seq LIMIT 1),false)`, target).Scan(&stuck)
	return stuck, err
}
