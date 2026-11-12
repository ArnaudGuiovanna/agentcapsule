//go:build linux

package worker

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func (w *Placements) control(ctx context.Context, target string, forFence bool) (*capsuleprotocol.Client, error) {
	c, err := w.host.Control(ctx, target)
	if errors.Is(err, runtime.ErrNoVM) {
		if _, err = w.start(ctx, target, forFence); err != nil {
			return nil, err
		}
		return w.host.Control(ctx, target)
	}
	return c, err
}

// Send accepts only control-plane-derived envelopes. Caller must first commit
// AuthorizeDispatch. The guest commits effect/dedup/result before this returns.
// Identity is derived from the verified placement, not an event payload field.
func (w *Placements) Send(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	return w.deliver(ctx, target, event, false)
}

// Invoke uses the same current-boot/admission checks as ordinary delivery, but
// the guest enforces a distinct owner-instruction envelope and JSON result.
func (w *Placements) Invoke(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	return w.deliver(ctx, target, event, true)
}

func (w *Placements) deliver(ctx context.Context, target string, event harnessstore.Event, invoke bool) (harnessstore.Receipt, error) {
	var result harnessstore.Receipt
	send := func(ctx context.Context) error {
		c, err := w.control(ctx, target, false)
		if err != nil {
			return err
		}
		// Owner instructions are not between agents: they never cross SLIM.
		if link := w.slim.Load(); link != nil && !invoke {
			result, err = w.sendSLIM(ctx, link, target, c, event)
			return err
		}
		result, err = w.deliverToGuest(ctx, target, c, event, invoke)
		return err
	}
	var err error
	if prepared, _ := ctx.Value(preparedDeliveryKey{}).(string); prepared == target {
		// Still validate the host scope; an escaped callback context must fail.
		err = w.host.WithApplication(ctx, send)
	} else {
		err = w.withFreshApplication(ctx, send)
	}
	return result, err
}

type preparedDeliveryKey struct{}

// WithPreparedDelivery owns a FIFO exclusive turn through preparation and the
// synchronous SQL-only control callback. Slow boot/capacity/health failures occur
// before ClaimDelivery spends an RPC attempt. Guest-initiated platform work is
// asynchronous and joins the common shared queue after this turn.
func (w *Placements) WithPreparedDelivery(ctx context.Context, target string, fn func(context.Context) error) error {
	return w.host.WithBarrier(ctx, target, func(ctx context.Context) error {
		runs, err := w.Reconcile(ctx)
		if err != nil {
			return err
		}
		if run, ok := runs[target]; ok && run.FenceOnly {
			if err = w.stop(ctx, target, run.Generation, true); err != nil {
				return err
			}
		}
		if _, _, err = w.retireDueCredentials(ctx, target); err != nil {
			return err
		}
		_, err = w.start(ctx, target, false)
		if errors.Is(err, runtime.ErrCapacity) {
			if err = w.makeBarrierCapacity(ctx, target); err != nil {
				return err
			}
			_, err = w.start(ctx, target, false)
		}
		if err != nil {
			return err
		}
		client, err := w.host.Control(ctx, target)
		if err != nil {
			return err
		}
		if err = client.Health(ctx); err != nil {
			return err
		}
		if err = w.serveSLIM(ctx, target); err != nil {
			return err
		}
		return fn(context.WithValue(ctx, preparedDeliveryKey{}, target))
	})
}

// DispatchOne acquires this scope before consuming a delivery attempt. A queued
// barrier is backpressure, not a failed application delivery.
func (w *Placements) WithDeliveryAdmission(ctx context.Context, fn func(context.Context) error) error {
	return w.withFreshApplication(ctx, fn)
}

// Fence requires a committed SQL barrier or a revalidated permanent host seal.
// A stopped QUIESCING target boots only for barriers. A tombstoned store stays in
// every manifest; it is acknowledged only after managed execution is sealed.
func (w *Placements) Fence(ctx context.Context, target, subject string) error {
	if w.authority != nil {
		if _, err := w.authority.BeginRevocation(ctx, subject); err != nil {
			return err
		}
	}
	return w.host.WithBarrier(ctx, target, func(ctx context.Context) error { return w.fence(ctx, target, subject) })
}

func (w *Placements) fence(ctx context.Context, target, subject string) (result error) {
	p, ready, err := w.store.StoreSealTarget(ctx, target, w.hostID)
	if err != nil {
		return err
	}
	if ready {
		return w.seal(ctx, p)
	}
	if _, _, err = w.retireDueCredentials(ctx, target); err != nil {
		return err
	}
	c, err := w.host.Control(ctx, target)
	if errors.Is(err, runtime.ErrNoVM) {
		var run runtime.VMRun
		run, err = w.start(ctx, target, true)
		if errors.Is(err, runtime.ErrCapacity) {
			if err = w.makeBarrierCapacity(ctx, target); err != nil {
				return err
			}
			run, err = w.start(ctx, target, true)
		}
		if err != nil {
			return err
		}
		// This worker woke the store only for a barrier. Release its slot after
		// the RPC (also on lost ACK/error), rather than accumulating idle guests.
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result = errors.Join(result, w.stop(cleanup, target, run.Generation, true))
		}()
		c, err = w.host.Control(ctx, target)
	}
	if err != nil {
		return err
	}
	if w.authority != nil {
		e, err := w.store.VolumeEnrollment(ctx, target, w.hostID)
		if err != nil {
			return err
		}
		_, err = w.synchronizeAuthority(ctx, e, c)
		return err
	}
	return c.Fence(ctx, subject)
}

// The exclusive admission scope prevents another worker from filling the slot
// between retirement and target boot. Existing control/platform calls have
// finished. Background guest computation is interrupted and must be replayable;
// SQLite transactions/WAL and stable business keys provide that contract here.
func (w *Placements) makeBarrierCapacity(ctx context.Context, target string) error {
	runs, err := w.Reconcile(ctx)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(runs))
	for id := range runs {
		if id != target {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return runtime.ErrCapacity
	}
	id := ids[0]
	return w.stop(ctx, id, runs[id].Generation, true)
}
