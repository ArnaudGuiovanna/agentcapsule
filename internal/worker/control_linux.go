//go:build linux

package worker

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
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
	ctx, span := deliverSpan.Start(ctx)
	span.ID("agentcapsule.agent", target)
	if invoke {
		span.Code("agentcapsule.delivery.kind", "invocation")
	} else {
		span.Code("agentcapsule.delivery.kind", "agent_message")
	}
	var result harnessstore.Receipt
	slim := false
	send := func(ctx context.Context) error {
		c, err := w.control(ctx, target, false)
		if err != nil {
			return err
		}
		// The guest's platform calls during the delivery join its span.
		defer w.turn(target, span)()
		// Owner instructions are not between agents: they never cross SLIM.
		if link := w.slim.Load(); link != nil && !invoke {
			slim = true
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
	endDelivery(span, slim, err)
	return result, err
}

type preparedDeliveryKey struct{}

// WithPreparedDelivery owns a FIFO exclusive turn through preparation and the
// synchronous SQL-only control callback. Slow boot/capacity/health failures occur
// before ClaimDelivery spends an RPC attempt. A stopped recipient boots in the
// order of its host's capacity queue (bootForWork). Guest-initiated platform work is
// asynchronous and joins the common shared queue after this turn.
func (w *Placements) WithPreparedDelivery(ctx context.Context, target string, fn func(context.Context) error) error {
	return w.host.WithBarrier(ctx, target, func(ctx context.Context) error {
		// The recipient's VM alone: a stopped recipient boots below
		// (bootForWork), which settles every placement first.
		runs, err := w.reconcileAgent(ctx, target)
		if err != nil {
			return err
		}
		run, running := runs[target]
		if running && run.FenceOnly {
			if err = w.stop(ctx, target, run.Generation, true); err != nil {
				return err
			}
			running = false
		}
		// A request between agents of an organization wakes a sleeping
		// recipient only within the organization's wake budget (INT-04). An
		// exhausted budget is backpressure: no attempt is spent. A running
		// VM, and a VM restarted only to renew its credentials, cost nothing.
		var wake string
		if !running {
			if wake, err = w.store.ReservePeerWake(ctx, target); err != nil {
				return err
			}
		}
		if _, _, err = w.retireDueCredentials(ctx, target); err != nil {
			return errors.Join(err, w.releaseWake(ctx, wake))
		}
		if running {
			// Its own slot: a VM restarted to renew its credentials keeps it.
			_, err = w.start(ctx, target, false)
		} else {
			_, err = w.bootForWork(ctx, target)
		}
		if err != nil {
			// A recipient that cannot boot must not use up the budget by retrying.
			return errors.Join(err, w.releaseWake(ctx, wake))
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
	// A running guest that does not answer its fence is reported as such: past
	// a delivery's attempts, or for its agent's deletion, the control plane
	// has its VM stopped.
	if w.authority != nil {
		e, err := w.store.VolumeEnrollment(ctx, target, w.hostID)
		if err != nil {
			return err
		}
		_, err = w.synchronizeAuthority(ctx, e, c)
		return unresponsiveGuest(ctx, c.Identity(), err)
	}
	return unresponsiveGuest(ctx, c.Identity(), c.Fence(ctx, subject))
}

// bootForWork boots target for work (a delivery, a wake, a resume) in the
// order of its host's capacity queue (ADR 017). The caller holds the host's
// exclusive admission turn and stopped any fence-only VM of target. A full
// host stops a VM that is not computing for it, an idle one first; with none,
// target waits in the queue and ErrCapacity makes its job try again later.
// Past its organization's quotas (ADR 021), target stops its organization's
// own VMs here that are not computing, or waits in the same queue, and an
// OrganizationQuotaError makes its job try again later.
func (w *Placements) bootForWork(ctx context.Context, target string) (_ runtime.VMRun, err error) {
	ctx, span := wakeSpan.Start(ctx)
	span.ID("agentcapsule.agent", target)
	outcome, evicted := "booted", false
	defer func() { endWake(span, outcome, evicted, err) }()
	runs, err := w.Reconcile(ctx)
	if err != nil {
		return runtime.VMRun{}, err
	}
	if run, ok := runs[target]; ok && !run.FenceOnly {
		outcome = "running"
		return w.start(ctx, target, false)
	}
	others := make([]string, 0, len(runs))
	for id := range runs {
		if id != target {
			others = append(others, id)
		}
	}
	sort.Strings(others)
	d, err := w.store.AdmitToSlot(ctx, w.hostID, target, others, max(w.host.MaxActive()-len(others), 0))
	if err != nil {
		return runtime.VMRun{}, err
	}
	if !d.Admit {
		if d.Quota != "" {
			return runtime.VMRun{}, &controlplane.OrganizationQuotaError{Quota: d.Quota}
		}
		return runtime.VMRun{}, runtime.ErrCapacity
	}
	for _, id := range d.EvictForQuota {
		evicted = true
		if err = w.stop(ctx, id, runs[id].Generation, true); err != nil {
			return runtime.VMRun{}, err
		}
	}
	if d.Evict != "" {
		evicted = true
		if err = w.stop(ctx, d.Evict, runs[d.Evict].Generation, true); err != nil {
			return runtime.VMRun{}, err
		}
	}
	run, err := w.start(ctx, target, false)
	if err != nil {
		return run, err
	}
	return run, w.store.SlotTaken(ctx, w.hostID, target)
}

// The exclusive admission scope prevents another worker from filling the slot
// between retirement and target boot. Existing control/platform calls have
// finished. A barrier may stop any VM: an idle one first, the least recently
// active first (ADR 017). Background guest computation is interrupted and must
// be replayable; SQLite transactions/WAL and stable business keys provide that
// contract here, and the resume job boots the stopped agent again once
// capacity returns if it held work in progress.
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
	order, err := w.store.EvictionOrder(ctx, w.hostID, ids)
	if err != nil {
		return err
	}
	id := order[0]
	return w.stop(ctx, id, runs[id].Generation, true)
}

// releaseWake gives a reserved wake back when the boot it paid for failed,
// even if the delivery's own context has ended.
func (w *Placements) releaseWake(ctx context.Context, wake string) error {
	if wake == "" {
		return nil
	}
	release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return w.store.ReleasePeerWake(release, wake)
}
