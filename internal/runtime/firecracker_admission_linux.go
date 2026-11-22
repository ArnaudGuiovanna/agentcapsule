//go:build linux

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrAdmissionBusy = errors.New("host admission cannot be upgraded or used for another target")
var ErrAdmissionLost = errors.New("host admission scope is no longer active")

// Each agent has its own admission queue (S-02): a FIFO of shared callers (the
// guest's platform calls, a boot or reuse of its VM) and exclusive ones
// (barriers: a delivery, a fence, a stop, an archive, a seal). Leading shared
// callers of an agent run together; an exclusive one runs alone, for that
// agent only. Another agent's callers do not wait for it. The queues live in
// <root>/admission/queue.json, written without fsync: a waiter exists only
// while its owner's kernel lock (<root>/admission/<id>.lock) does, so a crash
// loses nothing a restart needs. The turn itself is a kernel lock on the
// agent's turn file, shared or exclusive. No timeout or TTL is ever taken as
// a waiter's death.
type admissionWaiter struct {
	ID, Target string
	Shared     bool
}

type admissionQueue struct {
	Version int               `json:"version"`
	Waiters []admissionWaiter `json:"waiters"`
}

type admissionKey struct{}

// admissionScope is one turn held by a callback; parent is the turn the
// callback ran in when it took this one (an eviction, a non-blocking turn).
type admissionScope struct {
	root, agent, request string
	shared               bool
	active               atomic.Bool
	parent               *admissionScope
}

// find returns the turn of agent the scope holds, nil when it holds none.
func (s *admissionScope) find(agent string) *admissionScope {
	for n := s; n != nil; n = n.parent {
		if n.agent == agent {
			return n
		}
	}
	return nil
}

func (s *admissionScope) exclusive() bool {
	for n := s; n != nil; n = n.parent {
		if !n.shared {
			return true
		}
	}
	return false
}

func (h *FirecrackerHost) requestLock(id string) string {
	return filepath.Join(h.root, "admission", id+".lock")
}

func (h *FirecrackerHost) turnPath(agent string) string {
	return filepath.Join(h.root, "admission", "turn-"+agentKey(agent)+".lock")
}

// requestAlive tells whether the owner of waiter id still holds its lock.
func (h *FirecrackerHost) requestAlive(id string) (bool, error) {
	f, err := os.OpenFile(h.requestLock(id), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

// admissionSignals wakes the waiters of a root in this process whenever one
// of its queues changes. Another process's changes are polled.
var admissionSignals sync.Map // root -> *admissionSignal

type admissionSignal struct {
	mu sync.Mutex
	ch chan struct{}
}

func (h *FirecrackerHost) signal() *admissionSignal {
	s, _ := admissionSignals.LoadOrStore(h.root, &admissionSignal{ch: make(chan struct{})})
	return s.(*admissionSignal)
}

func (s *admissionSignal) wait() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch
}

func (s *admissionSignal) notify() {
	s.mu.Lock()
	close(s.ch)
	s.ch = make(chan struct{})
	s.mu.Unlock()
}

// admissionPoll bounds how late a waiter sees another process's change.
const admissionPoll = 50 * time.Millisecond

// queued runs fn on the admission queues under their lock; change says
// whether fn changed them.
func (h *FirecrackerHost) queued(ctx context.Context, fn func(*admissionQueue) (bool, error)) error {
	h.queueMu.Lock()
	defer h.queueMu.Unlock()
	dir := filepath.Join(h.root, "admission")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "queue.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = flockWait(ctx, f, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	q, err := h.loadQueue()
	if err != nil {
		return err
	}
	changed, err := fn(q)
	if err != nil || !changed {
		return err
	}
	if err = h.saveQueue(q); err != nil {
		return err
	}
	h.signal().notify()
	return nil
}

func (h *FirecrackerHost) queuePath() string { return filepath.Join(h.root, "admission", "queue.json") }

// loadQueue runs under the queue lock. A file that a crash left incomplete
// is read as empty: every waiter it held died with the crash.
func (h *FirecrackerHost) loadQueue() (*admissionQueue, error) {
	st, err := os.Stat(h.queuePath())
	if errors.Is(err, os.ErrNotExist) {
		return &admissionQueue{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	if h.queue != nil && h.queue.id == fileIdentity(st) {
		q := *h.queue.q
		q.Waiters = append([]admissionWaiter(nil), h.queue.q.Waiters...)
		return &q, nil
	}
	f, err := os.OpenFile(h.queuePath(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fst, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	q := &admissionQueue{}
	if json.Unmarshal(b, q) != nil || q.Version != 1 {
		q = &admissionQueue{Version: 1}
	}
	valid := q.Waiters[:0]
	for _, w := range q.Waiters {
		if raw, err := hex.DecodeString(w.ID); err == nil && len(raw) == 16 && w.Target != "" {
			valid = append(valid, w)
		}
	}
	q.Waiters = valid
	h.dropQueueCache()
	h.queue = &queueCache{q: q, id: fileIdentity(fst), pin: f}
	c := *q
	c.Waiters = append([]admissionWaiter(nil), q.Waiters...)
	return &c, nil
}

type queueCache struct {
	q   *admissionQueue
	id  fileID
	pin *os.File
}

func (h *FirecrackerHost) dropQueueCache() {
	if h.queue != nil {
		h.queue.pin.Close()
	}
	h.queue = nil
}

// saveQueue replaces the queue file without fsync (see admissionWaiter).
func (h *FirecrackerHost) saveQueue(q *admissionQueue) error {
	q.Version = 1
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Join(h.root, "admission"), "queue-*.tmp")
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = os.Rename(f.Name(), h.queuePath())
	}
	var st os.FileInfo
	if err == nil {
		st, err = f.Stat()
	}
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		h.dropQueueCache()
		return err
	}
	h.dropQueueCache()
	c := *q
	c.Waiters = append([]admissionWaiter(nil), q.Waiters...)
	h.queue = &queueCache{q: &c, id: fileIdentity(st), pin: f}
	return nil
}

// pruneAhead drops the waiters ahead of w, for w's agent, whose owners died.
// Only the release of an owner's kernel lock proves it, never a timeout.
func (h *FirecrackerHost) pruneAhead(q *admissionQueue, w admissionWaiter) (bool, error) {
	kept := q.Waiters[:0]
	changed, ahead := false, true
	for _, x := range q.Waiters {
		if x.ID == w.ID {
			ahead = false
		}
		if ahead && x.Target == w.Target && x.ID != w.ID {
			alive, err := h.requestAlive(x.ID)
			if err != nil {
				return false, err
			}
			if !alive {
				if err = os.Remove(h.requestLock(x.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return false, err
				}
				changed = true
				continue
			}
		}
		kept = append(kept, x)
	}
	q.Waiters = kept
	return changed, nil
}

func flockContext(ctx context.Context, f *os.File, mode int) error {
	return flockWait(ctx, f, mode)
}

func (h *FirecrackerHost) admission(ctx context.Context) (*admissionScope, error) {
	s, _ := ctx.Value(admissionKey{}).(*admissionScope)
	if s == nil {
		return nil, nil
	}
	for n := s; n != nil; n = n.parent {
		if n.root != h.root || !n.active.Load() {
			return nil, ErrAdmissionLost
		}
	}
	return s, nil
}

// WithApplication joins agent's queue in shared mode. Leading shared callers
// may run concurrently; later arrivals cannot overtake an exclusive waiter.
// Callbacks/children are synchronous and scoped contexts must not escape.
// Within a scope, only a turn the scope already holds is used.
func (h *FirecrackerHost) WithApplication(ctx context.Context, agent string, fn func(context.Context) error) error {
	if agent == "" {
		return errors.New("admission needs an agent")
	}
	if s, err := h.admission(ctx); err != nil {
		return err
	} else if s != nil {
		if s.find(agent) == nil {
			return ErrAdmissionBusy
		}
		return fn(ctx)
	}
	return h.withAdmission(ctx, agent, true, nil, fn)
}

// WithBarrier joins target's queue exclusively. This covers data barriers and
// the host scheduling operations of target. New barriers cannot starve an
// ordinary callback that is already queued. Other agents are not held.
func (h *FirecrackerHost) WithBarrier(ctx context.Context, target string, fn func(context.Context) error) error {
	if target == "" {
		return errors.New("admission needs an agent")
	}
	if s, err := h.admission(ctx); err != nil {
		return err
	} else if s != nil {
		if n := s.find(target); n == nil || n.shared {
			return ErrAdmissionBusy
		}
		return fn(ctx)
	}
	return h.withAdmission(ctx, target, false, nil, fn)
}

// WithEviction takes victim's exclusive turn from within an exclusive turn
// of another agent, to stop victim's VM for capacity (ADR 017): it waits, in
// victim's FIFO, for the calls and the delivery already admitted on victim,
// and new ones wait behind it. The caller holds no agent lock and no host
// lock while it waits. No cycle of evictions can form: a caller evicts only
// once its own agent's VM is stopped, and only VMs that ran in a census taken
// since, while no one else can boot its agent.
func (h *FirecrackerHost) WithEviction(ctx context.Context, victim string, fn func(context.Context) error) error {
	s, err := h.admission(ctx)
	if err != nil {
		return err
	}
	if s == nil || !s.exclusive() {
		return ErrAdmissionLost
	}
	if n := s.find(victim); n != nil {
		if n.shared {
			return ErrAdmissionBusy
		}
		return fn(ctx)
	}
	return h.withAdmission(ctx, victim, false, s, fn)
}

// TryBarrier runs fn under target's exclusive turn only if it can be had at
// once, ErrAgentBusy otherwise: a census or a reconciliation does not wait
// for an agent that someone uses. A scope that holds target already runs fn.
func (h *FirecrackerHost) TryBarrier(ctx context.Context, target string, fn func(context.Context) error) error {
	s, err := h.admission(ctx)
	if err != nil {
		return err
	}
	if s != nil && s.find(target) != nil {
		return fn(ctx)
	}
	release, err := h.tryTurn(target)
	if err != nil {
		return err
	}
	defer release()
	scope := &admissionScope{root: h.root, agent: target, parent: s}
	scope.active.Store(true)
	defer scope.active.Store(false)
	return fn(context.WithValue(ctx, admissionKey{}, scope))
}

// tryTurn takes target's turn exclusively if no caller holds it now.
func (h *FirecrackerHost) tryTurn(target string) (func(), error) {
	if err := os.MkdirAll(filepath.Join(h.root, "admission"), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(h.turnPath(target), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAgentBusy
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}

// eligibleAdmission is checked under the queue lock. Shared callers form only
// the initial consecutive group of their agent; an exclusive caller must be
// its agent's first entry.
func eligibleAdmission(q *admissionQueue, w admissionWaiter) bool {
	for _, x := range q.Waiters {
		if x.Target != w.Target {
			continue
		}
		if x.ID == w.ID {
			return x == w
		}
		if !w.Shared || !x.Shared {
			return false
		}
	}
	return false
}

func (h *FirecrackerHost) withAdmission(ctx context.Context, target string, shared bool, parent *admissionScope, fn func(context.Context) error) (result error) {
	if !shared {
		r, err := h.view()
		if err != nil {
			return err
		}
		if r.Agents[target] == nil {
			return errors.New("unregistered barrier target")
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	w := admissionWaiter{ID: hex.EncodeToString(nonce), Target: target, Shared: shared}
	if err := os.MkdirAll(filepath.Join(h.root, "admission"), 0700); err != nil {
		return err
	}
	owner, err := os.OpenFile(h.requestLock(w.ID), os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer owner.Close()
	if err = syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		os.Remove(owner.Name())
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		err := h.queued(cleanup, func(q *admissionQueue) (bool, error) {
			for i, x := range q.Waiters {
				if x.ID == w.ID {
					q.Waiters = append(q.Waiters[:i], q.Waiters[i+1:]...)
					return true, nil
				}
			}
			return false, nil
		})
		if remove := os.Remove(h.requestLock(w.ID)); remove != nil && !errors.Is(remove, os.ErrNotExist) {
			err = errors.Join(err, remove)
		}
		result = errors.Join(result, err)
	}()
	if err = h.queued(ctx, func(q *admissionQueue) (bool, error) {
		q.Waiters = append(q.Waiters, w)
		return true, nil
	}); err != nil {
		return err
	}
	if h.admissionHook != nil {
		h.admissionHook("queued", target)
	}
	sig := h.signal()
	for {
		changed := sig.wait()
		first := false
		if err = h.queued(ctx, func(q *admissionQueue) (bool, error) {
			pruned, err := h.pruneAhead(q, w)
			if err != nil {
				return false, err
			}
			first = eligibleAdmission(q, w)
			return pruned, nil
		}); err != nil {
			return err
		}
		if first {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-time.After(admissionPoll):
		}
	}
	turn, err := os.OpenFile(h.turnPath(target), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer turn.Close()
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	if err = flockContext(ctx, turn, mode); err != nil {
		return err
	}
	if h.admissionHook != nil {
		h.admissionHook("admitted", target)
	}
	scope := &admissionScope{root: h.root, agent: target, request: w.ID, shared: shared, parent: parent}
	scope.active.Store(true)
	defer scope.active.Store(false)
	return fn(context.WithValue(ctx, admissionKey{}, scope))
}

// checkAdmission: the caller still holds target's turn from its queue, or a
// turn taken at once (TryBarrier).
func (h *FirecrackerHost) checkAdmission(ctx context.Context, target string) error {
	s, err := h.admission(ctx)
	if err != nil {
		return err
	}
	var n *admissionScope
	if s != nil {
		n = s.find(target)
	}
	if n == nil {
		return ErrAdmissionLost
	}
	if n.request == "" {
		return nil
	}
	eligible := false
	if err = h.queued(ctx, func(q *admissionQueue) (bool, error) {
		eligible = eligibleAdmission(q, admissionWaiter{ID: n.request, Target: target, Shared: n.shared})
		return false, nil
	}); err != nil {
		return err
	}
	if !eligible {
		return ErrAdmissionLost
	}
	return nil
}
