//go:build linux

package runtime

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

// Capacity stays host-wide (S-02): host.lock counts the slots, vCPUs and
// memory of every run when a boot records its intent. Boots of different
// agents no longer wait for one another, so a slot an eviction frees could
// go to another boot before the evictor's own. ReserveSlot keeps it: the
// evicting turn claims its victim's slot, which counts for every other boot
// once the victim is stopped, and until the evictor's boot records its
// intent or the evicting turn ends. A barrier thus keeps the priority over
// ordinary work that spec/barrier_capacity.qnt states.

// slotReservation is the slot agent's eviction of Victim frees, held by the
// admission turn Request.
type slotReservation struct {
	Request string `json:"request"`
	Victim  string `json:"victim"`
}

// reservationLive: the evicting turn still holds its admission.
func (h *FirecrackerHost) reservationLive(res slotReservation) bool {
	alive, err := h.requestAlive(res.Request)
	return alive || err != nil
}

// pruneReservations drops, under host.lock, the reservations whose turn ended.
func (h *FirecrackerHost) pruneReservations(r *hostRegistry) {
	for id, res := range r.Reservations {
		if !h.reservationLive(res) || r.Agents[id] == nil {
			delete(r.Reservations, id)
		}
	}
	if len(r.Reservations) == 0 {
		r.Reservations = nil
	}
}

func validReservations(r *hostRegistry) error {
	for id, res := range r.Reservations {
		raw, err := hex.DecodeString(res.Request)
		if err != nil || len(raw) != 16 || strings.ToLower(res.Request) != res.Request || r.Agents[id] == nil || r.Agents[res.Victim] == nil || res.Victim == id {
			return errors.New("invalid slot reservation in runtime registry")
		}
	}
	return nil
}

// ReserveSlot claims victim's slot for the agent whose exclusive turn evicts
// it: ctx is that eviction's scope (WithEviction). A victim another eviction
// claimed already is ErrCapacity: its slot will not be this agent's. The
// claim ends when the agent records its boot, or when its turn ends.
func (h *FirecrackerHost) ReserveSlot(ctx context.Context, victim string) error {
	s, err := h.admission(ctx)
	if err != nil {
		return err
	}
	var evictor *admissionScope
	if s != nil {
		if n := s.find(victim); n != nil && !n.shared {
			for p := n.parent; p != nil; p = p.parent {
				if !p.shared && p.request != "" && p.agent != victim {
					evictor = p
					break
				}
			}
		}
	}
	if evictor == nil {
		return ErrAdmissionLost
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		h.pruneReservations(r)
		if r.Agents[victim] == nil || r.Agents[evictor.agent] == nil {
			return errors.New("unregistered agent")
		}
		for id, res := range r.Reservations {
			if res.Victim == victim && id != evictor.agent {
				return ErrCapacity
			}
		}
		if res, held := r.Reservations[evictor.agent]; held && res.Request == evictor.request {
			return h.save(r)
		}
		if r.Reservations == nil {
			r.Reservations = map[string]slotReservation{}
		}
		r.Reservations[evictor.agent] = slotReservation{Request: evictor.request, Victim: victim}
		return h.save(r)
	})
}
