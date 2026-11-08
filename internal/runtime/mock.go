// Package runtime contains runtime contracts and test implementations.
package runtime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// MockRuntime uses real SQLite stores, but no VM, transport, volume encryption or
// process supervision. Its fault hook can model a lost ACK after durable fencing.
// Success here is not evidence about Firecracker or a production disk stack.
type MockRuntime struct {
	mu        sync.RWMutex
	stores    map[string]*harnessstore.Store
	fenceHook func(stage, target, subject string) error
	sendHook  func(stage, target string, event harnessstore.Event) error
	mutate    func(context.Context, string, harnessstore.Event, harnessstore.SQL) ([]byte, error)
}

func NewMock(ctx context.Context, root string, agentIDs ...string) (*MockRuntime, error) {
	m := &MockRuntime{stores: make(map[string]*harnessstore.Store)}
	for _, id := range agentIDs {
		if id == "" {
			m.Close()
			return nil, errors.New("empty mock agent ID")
		}
		if _, exists := m.stores[id]; exists {
			m.Close()
			return nil, errors.New("duplicate mock agent ID")
		}
		path := filepath.Join(root, fmt.Sprintf("%x", sha256.Sum256([]byte(id))))
		if err := os.MkdirAll(path, 0700); err != nil {
			m.Close()
			return nil, err
		}
		store, err := harnessstore.Open(ctx, filepath.Join(path, "harness.db"))
		if err != nil {
			m.Close()
			return nil, err
		}
		m.stores[id] = store
	}
	return m, nil
}

func (m *MockRuntime) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, store := range m.stores {
		store.Close()
		delete(m.stores, id)
	}
}

func (m *MockRuntime) SetFenceHook(hook func(stage, target, subject string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fenceHook = hook
}

// SetHandler supplies trusted local SQL application behavior for Send. Transport
// failures can be injected before processing or after the durable commit.
func (m *MockRuntime) SetHandler(handler func(context.Context, string, harnessstore.Event, harnessstore.SQL) ([]byte, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mutate = handler
}

func (m *MockRuntime) SetSendHook(hook func(stage, target string, event harnessstore.Event) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendHook = hook
}

func (m *MockRuntime) Send(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	m.mu.RLock()
	handler, hook := m.mutate, m.sendHook
	m.mu.RUnlock()
	if handler == nil {
		return harnessstore.Receipt{}, errors.New("mock delivery handler is required")
	}
	if hook != nil {
		if err := hook("before", target, event); err != nil {
			return harnessstore.Receipt{}, err
		}
	}
	receipt, err := m.Deliver(ctx, target, event, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		return handler(ctx, target, event, tx)
	})
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	if hook != nil {
		if err := hook("after_commit", target, event); err != nil {
			return harnessstore.Receipt{}, err
		}
	}
	return receipt, nil
}

func (m *MockRuntime) Fence(ctx context.Context, target, subject string) error {
	m.mu.RLock()
	store, hook := m.stores[target], m.fenceHook
	m.mu.RUnlock()
	if store == nil {
		return fmt.Errorf("mock store %s unavailable", target)
	}
	if hook != nil {
		if err := hook("before", target, subject); err != nil {
			return err
		}
	}
	if err := store.Fence(ctx, subject); err != nil {
		return err
	}
	if hook != nil {
		return hook("after_commit", target, subject)
	}
	return nil
}

func (m *MockRuntime) Deliver(ctx context.Context, target string, event harnessstore.Event,
	mutate func(context.Context, harnessstore.SQL) ([]byte, error)) (harnessstore.Receipt, error) {
	m.mu.RLock()
	store := m.stores[target]
	m.mu.RUnlock()
	if store == nil {
		return harnessstore.Receipt{}, fmt.Errorf("mock store %s unavailable", target)
	}
	// The target itself must always be a revocation subject, even for a terminal
	// status notification that does not execute work for the deleted participant.
	found := false
	for _, subject := range event.Subjects {
		found = found || subject == "agent/"+target
	}
	if !found {
		return harnessstore.Receipt{}, errors.New("delivery omits its target fence")
	}
	return store.Apply(ctx, event, mutate)
}
