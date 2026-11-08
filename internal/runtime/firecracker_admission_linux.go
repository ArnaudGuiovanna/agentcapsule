//go:build linux

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrAdmissionBusy = errors.New("host admission cannot be upgraded or used for another target")
var ErrAdmissionLost = errors.New("host admission scope is no longer active")

type admissionWaiter struct {
	ID, Target string
	Shared     bool
}
type admissionKey struct{}
type admissionScope struct {
	root, request, target string
	shared                bool
	active                atomic.Bool
}

func (h *FirecrackerHost) requestLock(id string) string {
	return filepath.Join(h.root, "admission", id+".lock")
}

// pruneAdmissions runs under host.lock. Only the disappearance/release of the
// owner's kernel lock proves abandonment; no timeout/TTL is used as death.
func (h *FirecrackerHost) pruneAdmissions(r *hostRegistry) error {
	kept := make([]admissionWaiter, 0, len(r.Admissions))
	for _, w := range r.Admissions {
		f, err := os.OpenFile(h.requestLock(w.ID), os.O_RDWR, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			kept = append(kept, w)
			f.Close()
			continue
		}
		f.Close()
		if err != nil {
			return err
		}
		if err = os.Remove(h.requestLock(w.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if len(kept) != len(r.Admissions) {
		r.Admissions = kept
		return h.save(r)
	}
	return nil
}

func flockContext(ctx context.Context, f *os.File, mode int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (h *FirecrackerHost) admission(ctx context.Context) (*admissionScope, error) {
	s, _ := ctx.Value(admissionKey{}).(*admissionScope)
	if s == nil {
		return nil, nil
	}
	if s.root != h.root || !s.active.Load() {
		return nil, ErrAdmissionLost
	}
	return s, nil
}

// WithApplication joins the common FIFO queue in shared mode. Leading shared
// callers may run concurrently; later arrivals cannot overtake an exclusive
// waiter. Callbacks/children are synchronous and scoped contexts must not escape.
func (h *FirecrackerHost) WithApplication(ctx context.Context, fn func(context.Context) error) error {
	if s, err := h.admission(ctx); err != nil {
		return err
	} else if s != nil {
		return fn(ctx)
	}
	return h.withAdmission(ctx, "", true, fn)
}

// WithBarrier joins the same queue exclusively. This covers data barriers and
// short host scheduling operations that must reserve physical capacity. New
// barriers cannot starve an ordinary callback that is already queued.
func (h *FirecrackerHost) WithBarrier(ctx context.Context, target string, fn func(context.Context) error) error {
	if s, err := h.admission(ctx); err != nil {
		return err
	} else if s != nil {
		if s.shared || s.target != target {
			return ErrAdmissionBusy
		}
		return fn(ctx)
	}
	return h.withAdmission(ctx, target, false, fn)
}

// eligibleAdmission is checked under host.lock. Shared callers form only the
// initial consecutive group; an exclusive caller must be the first entry.
func eligibleAdmission(r *hostRegistry, w admissionWaiter) bool {
	for _, q := range r.Admissions {
		if q.ID == w.ID {
			return q == w
		}
		if !w.Shared || !q.Shared {
			return false
		}
	}
	return false
}

func (h *FirecrackerHost) withAdmission(ctx context.Context, target string, shared bool, fn func(context.Context) error) (result error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	w := admissionWaiter{ID: hex.EncodeToString(nonce), Target: target, Shared: shared}
	owner, err := os.OpenFile(h.requestLock(w.ID), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer owner.Close()
	if err = syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := h.locked(cleanup, func(r *hostRegistry) error {
			for i, q := range r.Admissions {
				if q.ID == w.ID {
					r.Admissions = append(r.Admissions[:i], r.Admissions[i+1:]...)
					if err := h.save(r); err != nil {
						return err
					}
					break
				}
			}
			if err := os.Remove(h.requestLock(w.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		})
		result = errors.Join(result, err)
	}()
	if err = h.locked(ctx, func(r *hostRegistry) error {
		if !shared && r.Agents[target] == nil {
			return errors.New("unregistered barrier target")
		}
		if err := h.pruneAdmissions(r); err != nil {
			return err
		}
		r.Admissions = append(r.Admissions, w)
		return h.save(r)
	}); err != nil {
		return err
	}
	if h.admissionHook != nil {
		h.admissionHook("queued", target)
	}
	for {
		first := false
		if err = h.locked(ctx, func(r *hostRegistry) error {
			if err := h.pruneAdmissions(r); err != nil {
				return err
			}
			first = eligibleAdmission(r, w)
			return nil
		}); err != nil {
			return err
		}
		if first {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	f, err := os.OpenFile(filepath.Join(h.root, "admission.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	if err = flockContext(ctx, f, mode); err != nil {
		return err
	}
	if h.admissionHook != nil {
		h.admissionHook("admitted", target)
	}
	scope := &admissionScope{root: h.root, request: w.ID, target: target, shared: shared}
	scope.active.Store(true)
	defer scope.active.Store(false)
	return fn(context.WithValue(ctx, admissionKey{}, scope))
}

func (h *FirecrackerHost) checkStartAdmission(ctx context.Context, r *hostRegistry, target string) error {
	s, err := h.admission(ctx)
	if err != nil {
		return err
	}
	if s == nil {
		return ErrAdmissionLost
	}
	if (!s.shared && s.target != target) || !eligibleAdmission(r, admissionWaiter{ID: s.request, Target: s.target, Shared: s.shared}) {
		return ErrAdmissionLost
	}
	return nil
}
