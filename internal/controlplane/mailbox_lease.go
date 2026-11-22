package controlplane

import (
	"context"
	"errors"
)

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
