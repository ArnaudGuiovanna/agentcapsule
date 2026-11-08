//go:build linux

// Package worker connects durable placements and authenticated capsule control
// to the real host driver and provides durable bounded business dispatch passes.
package worker

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type Placements struct {
	authority        *restoreauthority.Catalog
	store            *controlplane.Store
	host             *runtime.FirecrackerHost
	hostID, workerID string
	lease            time.Duration
	provisioning     *provisioner
	transit          atomic.Pointer[controlplane.Transit]
	llm              atomic.Pointer[controlplane.LLMService]
	// Tests inject cancellation/crashes at the durable claim boundary.
	afterClaim          func()
	afterConfirm        func(runtime.VMRun)
	afterSeal           func()
	afterRemoval        func() error
	credentialNow       func() time.Time
	afterStopIntent     func()
	afterCredentialStop func()
	afterRunning        func(runtime.VMRun)
	afterWorkClaim      func(controlplane.WorkerJob)
	afterWork           func(controlplane.WorkerJob)
}

// NewPlacements requires a stable, unique host ID bound to this private runtime
// root and a fresh worker ID per worker process. The trusted operator provisions
// and registers volumes beforehand. Migration to other hosts is unsupported.
func NewPlacements(store *controlplane.Store, hostID, workerID string, lease time.Duration, opts runtime.FirecrackerOptions) (*Placements, error) {
	return newPlacements(store, hostID, workerID, lease, opts, nil, nil)
}

// NewPlacementsWithVolumeKeys boots encrypted product guests. Keys must come
// from the installation's independently configured authority. The host proves
// physical exclusion before invoking the callback installed here; SQL authority
// and the authenticated volume ACK are checked before publishing RUNNING.
// Container provisioning and registration remain separate from this constructor.
func NewPlacementsWithVolumeKeys(store *controlplane.Store, hostID, workerID string, lease time.Duration, opts runtime.FirecrackerOptions, keys keyauthority.Provider) (*Placements, error) {
	if keys == nil {
		return nil, capsuleprotocol.ErrVolumeBoot
	}
	return newPlacements(store, hostID, workerID, lease, opts, keys, nil)
}

func newPlacements(store *controlplane.Store, hostID, workerID string, lease time.Duration, opts runtime.FirecrackerOptions, keys keyauthority.Provider, authority *restoreauthority.Catalog) (*Placements, error) {
	if store == nil || hostID == "" || workerID == "" || lease < time.Microsecond || lease > 24*time.Hour {
		return nil, controlplane.ErrPlacement
	}
	w := &Placements{authority: authority, store: store, hostID: hostID, workerID: workerID, lease: lease}
	opts, err := w.runtimeOptions(opts, keys)
	if err != nil {
		return nil, err
	}
	w.host, err = runtime.NewFirecrackerHost(opts)
	return w, err
}

func (w *Placements) runtimeOptions(opts runtime.FirecrackerOptions, keys keyauthority.Provider) (runtime.FirecrackerOptions, error) {
	store, hostID, workerID := w.store, w.hostID, w.workerID
	if opts.AuthenticatedControl {
		opts.ObserveControl = func(ctx context.Context, id string, run runtime.VMRun, compatible bool) error {
			return store.ObservePlacementControl(ctx, controlplane.PlacementControlObservation{
				AgentID: id, HostID: hostID, VMID: run.ID, Generation: run.Generation,
				Incarnation: run.Incarnation, Compatible: compatible,
			})
		}
		opts.PlatformHandler = func(id string, run runtime.VMRun) (http.Handler, error) {
			identity := capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: id, Generation: run.Generation, VMID: run.ID, FenceOnly: run.FenceOnly}
			api := platformAPI{store: store, host: w.host, caller: controlplane.VMCaller{AgentID: id, HostID: hostID, Generation: run.Generation, VMID: run.ID}, transit: w.transit.Load, llm: w.llm.Load, authority: w.authority, incarnation: run.Incarnation}
			return capsuleprotocol.NewPlatformHandler(identity, api)
		}
	}
	opts.Confirm = func(ctx context.Context, id string, run runtime.VMRun) error {
		var err error
		if run.FenceOnly {
			err = store.ConfirmFencePlacement(ctx, id, hostID, workerID, run.Generation, run.ID)
		} else {
			err = store.ConfirmPlacement(ctx, id, hostID, workerID, run.Generation, run.ID)
		}
		if err == nil && w.afterConfirm != nil {
			w.afterConfirm(run)
		}
		return err
	}
	opts.Adopt = func(ctx context.Context, id string, run runtime.VMRun) error {
		err := store.ValidatePlacement(ctx, id, hostID, run.Generation, run.ID)
		if errors.Is(err, controlplane.ErrPlacement) {
			return errors.Join(runtime.ErrGeneration, err)
		}
		return err
	}
	if w.authority != nil {
		opts.ResolveIncarnation = func(ctx context.Context, id string) (uint64, error) {
			e, err := store.VolumeEnrollment(ctx, id, hostID)
			if err != nil {
				return 0, err
			}
			err = w.authority.WithBinding(ctx, enrollmentBinding(e), func() error { return nil })
			return e.Incarnation, err
		}
		adopt := opts.Adopt
		opts.Adopt = func(ctx context.Context, id string, run runtime.VMRun) error {
			e, err := store.VolumeEnrollment(ctx, id, hostID)
			if err == nil && e.Incarnation != run.Incarnation {
				err = restoreauthority.ErrStale
			}
			if err == nil {
				err = w.authority.WithBinding(ctx, enrollmentBinding(e), func() error { return adopt(ctx, id, run) })
			}
			if errors.Is(err, restoreauthority.ErrStale) || errors.Is(err, restoreauthority.ErrSealed) || errors.Is(err, controlplane.ErrStoreEnrollment) {
				return errors.Join(runtime.ErrGeneration, err)
			}
			return err
		}
	}
	if keys != nil {
		return w.withVolumeBoot(opts, keys)
	}
	return opts, nil
}

// Register records a preprovisioned regular volume; it does not create/encrypt it.
// A partial registration blocks starts and must be completed by provisioning.
func (w *Placements) Register(ctx context.Context, id, volume string, uid uint32) error {
	if err := w.host.Register(ctx, id, volume, uid); err != nil {
		return err
	}
	return w.store.RegisterPlacement(ctx, id, w.hostID)
}

func (w *Placements) Reconcile(ctx context.Context) (map[string]runtime.VMRun, error) {
	runs, err := w.host.Reconcile(ctx)
	if err != nil {
		return nil, err
	}
	placements, err := w.store.Placements(ctx, w.hostID)
	if err != nil {
		return nil, err
	}
	for _, p := range placements {
		if p.State == "STOPPED" {
			continue
		}
		if run, ok := runs[p.AgentID]; ok && p.State == "RUNNING" &&
			run.Generation == p.Generation && run.ID == p.VMID {
			continue
		}
		// Another worker may own a start that has not reached host.lock yet.
		// Let its valid lease run; an expired or interrupted attempt can be retired.
		if p.State == "STARTING" && p.LeaseValid {
			continue
		}
		var err error
		if p.State == "RUNNING" {
			var retired bool
			retired, err = w.host.RetireMissing(ctx, p.AgentID, p.Generation, p.VMID)
			if err == nil && !retired {
				continue
			}
		} else {
			err = w.host.Retire(ctx, p.AgentID, p.Generation)
		}
		if err != nil {
			if errors.Is(err, runtime.ErrGeneration) {
				continue
			}
			return nil, err
		}
		if err := w.store.ObservePlacementStopped(ctx, p.AgentID, w.hostID, p.Generation, true); err != nil {
			if errors.Is(err, controlplane.ErrPlacement) {
				continue
			}
			return nil, err
		}
	}
	return w.host.Reconcile(ctx)
}

func (w *Placements) Start(ctx context.Context, id string) (runtime.VMRun, error) {
	var run runtime.VMRun
	err := w.withFreshApplication(ctx, func(ctx context.Context) error { var err error; run, err = w.start(ctx, id, false); return err })
	return run, err
}

func (w *Placements) start(ctx context.Context, id string, forFence bool) (runtime.VMRun, error) {
	return w.startRenewal(ctx, id, forFence, nil)
}

func (w *Placements) startRenewal(ctx context.Context, id string, forFence bool, renewal *controlplane.CredentialRenewal) (runtime.VMRun, error) {
	if _, err := w.Reconcile(ctx); err != nil {
		return runtime.VMRun{}, err
	}
	var p controlplane.Placement
	var err error
	if renewal != nil {
		p, err = w.store.ClaimRenewalPlacement(ctx, *renewal, w.workerID, w.lease)
	} else if forFence {
		p, err = w.store.ClaimFencePlacement(ctx, id, w.hostID, w.workerID, w.lease)
	} else {
		p, err = w.store.ClaimPlacement(ctx, id, w.hostID, w.workerID, w.lease)
	}
	if err != nil {
		return runtime.VMRun{}, err
	}
	if w.afterClaim != nil {
		w.afterClaim()
	}
	var run runtime.VMRun
	if p.FenceOnly {
		run, err = w.host.StartForFence(ctx, id, p.Generation)
	} else {
		run, err = w.host.Start(ctx, id, p.Generation)
	}
	if err == nil {
		if w.afterRunning != nil {
			w.afterRunning(run)
		}
		if !run.FenceOnly && !forFence {
			// The host has now durably published RUNNING. Failure to observe it
			// leaves the job retryable without killing this confirmed VMM.
			return run, w.store.ObserveRenewalSatisfied(ctx, id, w.hostID, run.Generation, run.ID)
		}
		return run, nil
	}
	// A request to reuse an existing placement must preserve its VMM on an
	// authority outage, just like Adopt. This call did not allocate a boot lease.
	if p.State == "RUNNING" {
		return run, err
	}
	// Even cancellation/unknown COMMIT cannot leave this failed attempt advertised
	// as usable. Keep durable state unresolved if physical retirement fails.
	cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if retire := w.host.Retire(cleanup, id, p.Generation); retire != nil {
		return run, errors.Join(err, retire)
	}
	return run, errors.Join(err, w.store.ObservePlacementStopped(cleanup, id, w.hostID, p.Generation, true))
}

func (w *Placements) Stop(ctx context.Context, id string, generation uint64) error {
	return w.host.WithBarrier(ctx, id, func(ctx context.Context) error {
		return w.quiesceStop(ctx, id, generation)
	})
}

// Forced retirement remains necessary for recovery and failed boot attempts.
// Normal owner sleep uses quiesceStop and an authenticated guest ACK instead.
func (w *Placements) stop(ctx context.Context, id string, generation uint64, unclean bool) error {
	if err := w.store.BeginPlacementStop(ctx, id, w.hostID, generation); err != nil {
		return err
	}
	return w.stopAfterIntent(ctx, id, generation, unclean)
}

func (w *Placements) stopAfterIntent(ctx context.Context, id string, generation uint64, unclean bool) error {
	if w.afterStopIntent != nil {
		w.afterStopIntent()
	}
	if err := w.host.Retire(ctx, id, generation); err != nil {
		return err
	}
	return w.store.ObservePlacementStopped(ctx, id, w.hostID, generation, unclean)
}
