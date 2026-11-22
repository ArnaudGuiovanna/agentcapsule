//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrAgentBusy: another caller holds the agent, its turn or its lock, and
// the operation that asked does not wait for it.
var ErrAgentBusy = errors.New("agent is in use")

// agentKey names an agent's lock files: agent IDs are not file names.
func agentKey(id string) string {
	sum := sha256.Sum256([]byte("agentcapsule-agent:" + id))
	return hex.EncodeToString(sum[:16])
}

// An agent's lock serializes what changes its VM run or reads its volume: a
// boot from its intent to RUNNING, a stop, a retirement, an adoption, a seal,
// a volume copy or install (S-03). It is held for the operation's whole
// length, and never while waiting for an admission turn. host.lock is taken
// under it only for short state transitions. Within the process a channel
// orders the waiters; a kernel lock on <root>/locks/agent-<key>.lock excludes
// other worker processes, which a worker's death releases.
type agentLock struct {
	ch   chan struct{}
	refs int
}

func (h *FirecrackerHost) agentLockPath(id string) string {
	return filepath.Join(h.root, "locks", "agent-"+agentKey(id)+".lock")
}

func (h *FirecrackerHost) agentEntry(id string) *agentLock {
	h.lockMu.Lock()
	defer h.lockMu.Unlock()
	if h.agentLocks == nil {
		h.agentLocks = map[string]*agentLock{}
	}
	l := h.agentLocks[id]
	if l == nil {
		l = &agentLock{ch: make(chan struct{}, 1)}
		h.agentLocks[id] = l
	}
	l.refs++
	return l
}

func (h *FirecrackerHost) releaseEntry(id string, l *agentLock) {
	h.lockMu.Lock()
	defer h.lockMu.Unlock()
	if l.refs--; l.refs == 0 {
		delete(h.agentLocks, id)
	}
}

func (h *FirecrackerHost) openAgentLock(id string) (*os.File, error) {
	path := h.agentLockPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
}

// lockAgent waits for the agent's lock, as long as ctx lasts. A free lock is
// taken even with ctx done, as host.lock always was: a cleanup that its
// caller gave up on still completes.
func (h *FirecrackerHost) lockAgent(ctx context.Context, id string) (func(), error) {
	l := h.agentEntry(id)
	select {
	case l.ch <- struct{}{}:
	default:
		select {
		case l.ch <- struct{}{}:
		case <-ctx.Done():
			h.releaseEntry(id, l)
			return nil, ctx.Err()
		}
	}
	f, err := h.openAgentLock(id)
	if err == nil {
		if err = flockWait(ctx, f, syscall.LOCK_EX); err != nil {
			f.Close()
		}
	}
	if err != nil {
		<-l.ch
		h.releaseEntry(id, l)
		return nil, err
	}
	return func() {
		f.Close()
		<-l.ch
		h.releaseEntry(id, l)
	}, nil
}

// tryLockAgent takes the agent's lock only if nobody holds it: a census
// does not wait for an agent that another operation is changing.
func (h *FirecrackerHost) tryLockAgent(id string) (func(), error) {
	l := h.agentEntry(id)
	select {
	case l.ch <- struct{}{}:
	default:
		h.releaseEntry(id, l)
		return nil, ErrAgentBusy
	}
	f, err := h.openAgentLock(id)
	if err == nil {
		if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); errors.Is(err, syscall.EWOULDBLOCK) {
			err = ErrAgentBusy
		}
		if err != nil {
			f.Close()
		}
	}
	if err != nil {
		<-l.ch
		h.releaseEntry(id, l)
		return nil, err
	}
	return func() {
		f.Close()
		<-l.ch
		h.releaseEntry(id, l)
	}, nil
}

// agent returns a copy of the registered agent id, nil when unregistered. It
// reads the current registry without host.lock: whoever changes an agent's
// run, fence, seal or volume holds that agent's lock, as the caller does, and
// each change is rechecked under host.lock when it is written.
func (h *FirecrackerHost) agent(_ context.Context, id string) (*HostAgent, error) {
	r, err := h.view()
	if err != nil {
		return nil, err
	}
	if a := r.Agents[id]; a != nil {
		return a.clone(), nil
	}
	return nil, nil
}

// endRun removes run from agent id once its VMM is cleaned up, unless the
// agent has moved to another run meanwhile.
func (h *FirecrackerHost) endRun(ctx context.Context, id string, run *VMRun) error {
	return h.locked(ctx, func(r *hostRegistry) error {
		if a := r.Agents[id]; a != nil && a.Run != nil && a.Run.ID == run.ID {
			a.Run = nil
			return h.save(r)
		}
		return nil
	})
}

// retireRun cleans run up and removes it from the registry: under the
// agent's lock, outside host.lock, since the attempt's cgroup may take up to
// ten seconds to empty.
func (h *FirecrackerHost) retireRun(ctx context.Context, id string, run *VMRun) error {
	if err := h.cleanup(ctx, id, run); err != nil {
		return err
	}
	// Recorded even when the caller gave up: the VMM is gone already.
	record, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return h.endRun(record, id, run)
}
