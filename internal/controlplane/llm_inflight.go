package controlplane

import "sync"

// inflightKeys are the request keys whose model call runs in this process,
// from its admission until its outcome is recorded. A replay of such a key
// must neither call the provider nor touch the reservation: the running call
// settles it, marks it unknown or releases it. A model stream runs up to
// 300 s, so its key is likely to be replayed while it runs (ADR 022).
type inflightKeys struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func inflightKey(tenantID, agentID, requestKey string) string {
	return tenantID + "\x00" + agentID + "\x00" + requestKey
}

// claim reports whether key was free, and holds it if so.
func (k *inflightKeys) claim(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, held := k.keys[key]; held {
		return false
	}
	if k.keys == nil {
		k.keys = map[string]struct{}{}
	}
	k.keys[key] = struct{}{}
	return true
}

func (k *inflightKeys) release(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, key)
}

// release gives back the hold's request key, if it holds one.
func (h llmHold) release() {
	if h.done != nil {
		h.done()
	}
}
