package api

import (
	"sync"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// An attachment's body passes through the API's memory, 8 MiB at most
// (v0.1.0 audit, S-09). The uploads whose bodies the process reads at once
// are bounded in the process and per principal; past either bound, an upload
// is refused before its body is read.
const (
	DefaultMaxUploads          = 16
	DefaultMaxPrincipalUploads = 2
)

type uploadSlots struct {
	mu                  sync.Mutex
	total, perPrincipal int // 0: the defaults
	active              int
	principals          map[string]int
}

// LimitUploads sets how many attachment bodies the process, and one
// principal, may read at once: from 1 to 1024, and the per-principal bound
// at most the process's. Call it before serving.
func (s *Server) LimitUploads(total, perPrincipal int) error {
	if total < 1 || total > 1024 || perPrincipal < 1 || perPrincipal > total {
		return controlplane.ErrInput
	}
	s.guards.uploads.total, s.guards.uploads.perPrincipal = total, perPrincipal
	return nil
}

// acquire takes a slot for principal, or names the bound that refused.
func (u *uploadSlots) acquire(principal string) (release func(), refused string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	total, perPrincipal := u.total, u.perPrincipal
	if total == 0 {
		total, perPrincipal = DefaultMaxUploads, DefaultMaxPrincipalUploads
	}
	switch {
	case u.principals[principal] >= perPrincipal:
		return nil, "principal_uploads"
	case u.active >= total:
		return nil, "process_uploads"
	}
	if u.principals == nil {
		u.principals = map[string]int{}
	}
	u.principals[principal]++
	u.active++
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.principals[principal]--; u.principals[principal] == 0 {
			delete(u.principals, principal)
		}
		u.active--
	}, ""
}
