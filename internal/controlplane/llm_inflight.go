package controlplane

import "sync"

// inflightKeys are the request keys whose model call runs in this process,
// from its admission until its outcome is recorded, and how many such calls
// each agent has. A replay of such a key must neither call the provider nor
// touch the reservation: the running call settles it, marks it unknown or
// releases it. A model stream runs up to 300 s, so its key is likely to be
// replayed while it runs (ADR 022). An agent's calls in flight are bounded
// (LLMService.LimitCallsPerAgent): each may cost more than its reservation
// says, and the bound limits how many at once.
type inflightKeys struct {
	mu     sync.Mutex
	keys   map[string]struct{}
	agents map[string]int
}

func inflightKey(tenantID, agentID, requestKey string) string {
	return tenantID + "\x00" + agentID + "\x00" + requestKey
}

func inflightAgent(tenantID, agentID string) string { return tenantID + "\x00" + agentID }

// What a claim found.
type inflightClaim int

const (
	claimed    inflightClaim = iota
	keyRunning               // a call with this key runs: nothing is held
	agentFull                // the agent has limit calls in flight: nothing is held
)

// claim holds key and a slot of agent, if the key is free and the agent has
// fewer than limit calls in flight.
func (k *inflightKeys) claim(key, agent string, limit int) inflightClaim {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, held := k.keys[key]; held {
		return keyRunning
	}
	if k.agents[agent] >= limit {
		return agentFull
	}
	if k.keys == nil {
		k.keys, k.agents = map[string]struct{}{}, map[string]int{}
	}
	k.keys[key] = struct{}{}
	k.agents[agent]++
	return claimed
}

func (k *inflightKeys) release(key, agent string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, held := k.keys[key]; !held {
		return
	}
	delete(k.keys, key)
	if k.agents[agent]--; k.agents[agent] <= 0 {
		delete(k.agents, agent)
	}
}

// release gives back the hold's request key and its agent's slot, if it holds
// them.
func (h llmHold) release() {
	if h.done != nil {
		h.done()
	}
}
