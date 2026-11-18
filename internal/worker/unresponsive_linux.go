//go:build linux

package worker

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// A harness that never answers an invocation holds its store, and the fence
// that ends the invocation after its attempts cannot commit; the agent's
// other work waits behind it (ADR 012, question 7, option (b)). The worker
// tells the control plane which fences its guest refused, and stops that VM
// when the control plane asks: the fence then goes through a restricted
// boot, which runs no work.

// unresponsiveGuest returns err, the failure of the fence RPCs to the guest
// of identity's boot, as that guest's (controlplane.UnresponsiveGuestError)
// when the guest is to blame, and as is otherwise. The guest is to blame
// when, while the worker's own context is live, either the guest answered
// that it could not fence (capsuleprotocol's client turns its error codes,
// such as a busy store's "unavailable", into the bare ErrTransport), or
// nothing answered before the RPC's own timeout. Never for a restricted
// boot, which runs no work, nor for what the platform failed: the worker's
// deadline, a connection the host could not open or that a VMM gone refused
// (the census counts a crash), an authority or PostgreSQL, which never fail
// with ErrTransport.
func unresponsiveGuest(ctx context.Context, identity capsuleprotocol.Identity, err error) error {
	if err == nil || ctx.Err() != nil || identity.FenceOnly || !guestDidNotAnswer(err) {
		return err
	}
	return &controlplane.UnresponsiveGuestError{Generation: identity.Generation, Err: err}
}

func guestDidNotAnswer(err error) bool {
	if errors.Is(err, capsuleprotocol.ErrTransport) && !isJoin(err) {
		return true // the guest's answer: an error code, not a failed request
	}
	var timeout interface{ Timeout() bool }
	return errors.Is(err, capsuleprotocol.ErrTransport) && errors.As(err, &timeout) && timeout.Timeout()
}

// isJoin reports whether err, or what it wraps, joins several errors: the
// client joins ErrTransport with the request's own failure when nothing
// answered, and returns the sentinel alone for an answer.
func isJoin(err error) bool {
	for err != nil {
		if _, ok := err.(interface{ Unwrap() []error }); ok {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

// StopUnresponsiveGuest stops the agent's VM of generation, booted for work,
// whose guest did not answer the fence of a delivery past its attempts:
// under the host's exclusive admission for the agent, the way a sleep stops
// a VM, a quiesce, then the VMM's forced removal. The stop records a guest
// failure of kind unresponsive for that boot, counted against the agent's
// restart budget. A VM that is gone (the census counted a crash), was
// replaced, or boots only for barriers, is left alone.
func (w *Placements) StopUnresponsiveGuest(ctx context.Context, target string, generation uint64) error {
	return w.host.WithBarrier(ctx, target, func(ctx context.Context) error {
		runs, err := w.reconcileAgent(ctx, target)
		if err != nil {
			return err
		}
		if run, ok := runs[target]; !ok || run.Generation != generation || run.FenceOnly {
			return nil
		}
		return w.quiesceStopAs(ctx, target, generation, controlplane.GuestUnresponsive)
	})
}

var _ controlplane.UnresponsiveGuestStopper = (*Placements)(nil)
