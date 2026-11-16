//go:build linux

package worker

import (
	"context"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func enrollmentBinding(e controlplane.Enrollment) restoreauthority.Binding {
	return restoreauthority.Binding{Store: e.AgentID, Volume: e.VolumeID, Incarnation: e.Incarnation}
}

// deliverToGuest runs inside the caller's host admission scope. The short root
// check admits this incarnation; it is not held across the RPC. Already admitted
// work may finish during Draining, but cannot receive an external success after
// reservation. Physical retirement remains mandatory before image installation.
func (w *Placements) deliverToGuest(ctx context.Context, target string, client *capsuleprotocol.Client, event harnessstore.Event, invoke bool) (harnessstore.Receipt, error) {
	var binding restoreauthority.Binding
	if w.authority != nil {
		e, err := w.store.VolumeEnrollment(ctx, target, w.hostID)
		if err != nil {
			return harnessstore.Receipt{}, err
		}
		identity := client.Identity()
		if identity.AgentID != target || identity.Incarnation != e.Incarnation || identity.FenceOnly {
			return harnessstore.Receipt{}, restoreauthority.ErrStale
		}
		binding = enrollmentBinding(e)
		if err = w.authority.CheckBinding(ctx, binding); err != nil {
			return harnessstore.Receipt{}, err
		}
	}
	if !client.Accepts(capsuleprotocol.ControlContentJSON) {
		// A harness that did not negotiate JSON content receives each JSON
		// part as text (ADR 016). The same boot always gets the same bytes,
		// and the outcome below is recorded for the event it received.
		if downgraded, err := capsuleprotocol.TextOnlyEvent(event); err == nil {
			event = downgraded
		}
	}
	var result harnessstore.Receipt
	var err error
	if invoke {
		result, err = client.Invoke(ctx, event)
	} else {
		result, err = client.Send(ctx, event)
	}
	if err == nil && w.authority != nil {
		var outcome restoreauthority.Outcome
		outcome.ID, outcome.Digest, err = harnessstore.OutcomeFingerprint(target, event, result.Result)
		if err == nil {
			err = w.authority.RecordOutcome(ctx, binding, outcome)
		}
	}
	if err != nil {
		clear(result.Result)
		return harnessstore.Receipt{}, err
	}
	// RecordOutcome is the model's ACK linearization point. A lost downstream SQL
	// ACK leaves a conservative history obligation and retries this same digest.
	return result, nil
}

// synchronizeAuthority records a snapshot only after every authenticated guest
// fence succeeds. Its MAC alone is not a guest receipt. Sequential fence calls
// remain durable and idempotent across a partial/lost response.
func (w *Placements) synchronizeAuthority(ctx context.Context, e controlplane.Enrollment, client *capsuleprotocol.Client) (restoreauthority.Receipt, error) {
	var r restoreauthority.Receipt
	if w.authority == nil || client == nil || client.Identity().AgentID != e.AgentID || client.Identity().Incarnation != e.Incarnation {
		return r, restoreauthority.ErrStale
	}
	subjects, err := w.store.RevocationSubjects(ctx)
	if err != nil {
		return r, err
	}
	for _, subject := range subjects {
		if _, err = w.authority.BeginRevocation(ctx, subject); err != nil {
			return r, err
		}
	}
	r, err = w.authority.Scan(ctx, enrollmentBinding(e))
	if err != nil {
		return r, err
	}
	// Authenticate even an empty snapshot; it must still describe this live boot.
	if err = client.Health(ctx); err != nil {
		return r, err
	}
	for _, subject := range r.Subjects {
		if err = client.Fence(ctx, subject); err != nil {
			return r, err
		}
	}
	return r, w.authority.RecordVerifiedFence(ctx, r)
}

// CommitBarrier is called without SQL locks. A previously acknowledged SQL row
// can be stale after restoration, so all targets are checked in the independent
// catalogue. Physical host operations precede, never nest inside, its SQL gate.
func (w *Placements) CommitBarrier(ctx context.Context, subject string, targets []string, publish func() error) error {
	if w.authority == nil {
		return publish()
	} // explicit legacy/probe runtime
	if _, err := w.authority.BeginRevocation(ctx, subject); err != nil {
		return err
	}
	bindings := make([]restoreauthority.Binding, 0, len(targets))
	for _, target := range targets {
		e, err := w.store.VolumeEnrollment(ctx, target, w.hostID)
		if err != nil {
			return err
		}
		b := enrollmentBinding(e)
		ack, sealed, err := w.authority.SubjectBarrier(ctx, b, subject)
		if err != nil {
			return err
		}
		if !ack || sealed {
			if err = w.Fence(ctx, target, subject); err != nil {
				return err
			}
		}
		bindings = append(bindings, b)
	}
	// publish comes from internal/controlplane, in its caller's context: a
	// lost hold does not cancel it (ADR 006 §3, What a lost hold can do).
	return w.authority.HoldRevocation(ctx, subject, bindings, func(context.Context) error { return publish() })
}

// NewPlacementsWithAuthority is the encrypted product path. In production
// keys and authority are both the authority service's client, which pinned
// both identities at its hello; the caller owns its lifetime. Ordinary
// boot/adoption never enrolls a missing store.
func NewPlacementsWithAuthority(store *controlplane.Store, hostID, workerID string, lease time.Duration, opts runtime.FirecrackerOptions, keys keyauthority.Provider, authority restoreauthority.Authority) (*Placements, error) {
	if keys == nil || authority == nil {
		return nil, restoreauthority.ErrInput
	}
	if err := authority.SeparateFrom(opts.Root); err != nil {
		return nil, err
	}
	return newPlacements(store, hostID, workerID, lease, opts, keys, authority)
}
