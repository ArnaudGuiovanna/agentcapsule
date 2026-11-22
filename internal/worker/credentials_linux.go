//go:build linux

package worker

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func (w *Placements) credentialTime() time.Time {
	if w.credentialNow != nil {
		return w.credentialNow()
	}
	return time.Now()
}

// RefreshCredentials records and resumes owed replacements, including those
// interrupted after STOPPING or SQL confirmation. Restricted barrier guests are
// retired without an autonomous wake intent; their manifest owns any later wake.
// No timeout or certificate age is treated as physical absence.
func (w *Placements) RefreshCredentials(ctx context.Context) error {
	return w.refreshCredentials(ctx, 30*time.Second)
}

func (w *Placements) refreshCredentials(ctx context.Context, attemptTimeout time.Duration) error {
	step := func(fn func(context.Context) error) error {
		attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
		return fn(attempt)
	}
	var due map[string]runtime.VMRun
	err := step(func(ctx context.Context) error {
		if _, err := w.Reconcile(ctx); err != nil {
			return err
		}
		var err error
		due, err = w.host.CredentialRotations(ctx, w.credentialTime())
		return err
	})
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(due))
	for id := range due {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var result error
	for _, id := range ids {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		err := step(func(ctx context.Context) error {
			return w.host.WithBarrier(ctx, id, func(ctx context.Context) error {
				current, err := w.host.CredentialRotations(ctx, w.credentialTime())
				if err != nil {
					return err
				}
				run, ok := current[id]
				if !ok {
					return nil
				}
				if run.FenceOnly {
					return w.stop(ctx, id, run.Generation, true)
				}
				err = w.store.BeginCredentialRenewal(ctx, id, w.hostID, run.Generation, run.ID)
				if errors.Is(err, controlplane.ErrUnavailable) || errors.Is(err, controlplane.ErrNoRenewal) {
					return nil
				}
				if err != nil {
					return err
				}
				if err = w.stopAfterIntent(ctx, id, run.Generation, true); err != nil {
					return err
				}
				if w.afterCredentialStop != nil {
					w.afterCredentialStop()
				}
				return nil
			})
		})
		result = errors.Join(result, err)
	}
	var pending []controlplane.CredentialRenewal
	if err = step(func(ctx context.Context) error {
		var err error
		pending, err = w.store.PendingCredentialRenewals(ctx, w.hostID)
		return err
	}); err != nil {
		return errors.Join(result, err)
	}
	for _, renewal := range pending {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		err := step(func(ctx context.Context) error {
			return w.host.WithBarrier(ctx, renewal.AgentID, func(ctx context.Context) error {
				_, err := w.startRenewal(ctx, renewal.AgentID, false, &renewal)
				// A FAILED agent's replacement waits for its next wake (ADR 012);
				// one its organization's quotas refuse, for room (ADR 021).
				if errors.Is(err, controlplane.ErrNoRenewal) || errors.Is(err, controlplane.ErrAgentFailed) ||
					errors.Is(err, controlplane.ErrOrganizationQuota) {
					return nil
				}
				return err
			})
		})
		result = errors.Join(result, err)
	}
	return result
}

// Caller holds exclusive admission. Rechecking avoids retiring a fresh boot
// produced by another worker after the initial snapshot.
func (w *Placements) retireDueCredentials(ctx context.Context, id string) (runtime.VMRun, bool, error) {
	run, due, err := w.host.CredentialRotation(ctx, id, w.credentialTime())
	if err != nil || !due {
		return runtime.VMRun{}, false, err
	}
	if err = w.stop(ctx, id, run.Generation, true); err != nil {
		return run, false, err
	}
	if w.afterCredentialStop != nil {
		w.afterCredentialStop()
	}
	return run, true, nil
}

// Check under agent's shared admission BEFORE a delivery attempt or
// application callback starts: its boot's credentials, or, without an agent,
// every boot's. Release it before rotation: never upgrade a shared kernel
// lock. The callback executes at most once, even if it commits and returns an
// error.
func (w *Placements) withFreshApplication(ctx context.Context, agent string, fn func(context.Context) error) error {
	for pass := 0; ; pass++ {
		entered := false
		fresh := func(ctx context.Context) error {
			due := false
			if agent == "" {
				rotations, err := w.host.CredentialRotations(ctx, w.credentialTime())
				if err != nil {
					return err
				}
				due = len(rotations) != 0
			} else {
				_, d, err := w.host.CredentialRotation(ctx, agent, w.credentialTime())
				if err != nil {
					return err
				}
				due = d
			}
			if due {
				return runtime.ErrCredentialsDue
			}
			entered = true
			return fn(ctx)
		}
		var err error
		if agent == "" {
			err = fresh(ctx)
		} else {
			err = w.host.WithApplication(ctx, agent, fresh)
		}
		if entered || !errors.Is(err, runtime.ErrCredentialsDue) || pass != 0 {
			return err
		}
		if err = w.RefreshCredentials(ctx); err != nil {
			return err
		}
	}
}
