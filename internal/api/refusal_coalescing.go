package api

import (
	"context"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// Refused attempts are coalesced (v0.1.0 audit, L-04; ADR 014 §10, question
// 7): a member refused a thousand times would otherwise add a thousand events
// to the organization's trail, and a transaction to each refusal. A window
// opens at an actor's refused attempt at an action, for one reason, and lasts
// refusalWindow. In it, the first attempt at each target is recorded in full,
// up to refusalTargets targets; the other attempts are counted, and their
// number becomes one event at the window's end, naming the organization. The
// windows live in the process's memory: each API process keeps its own, and
// a process that stops abruptly loses the counts of its open windows.
const (
	refusalWindow  = time.Minute
	refusalTargets = 10
)

type refusalKey struct{ tenant, principal, action, reason string }

type openRefusals struct {
	principal controlplane.Principal
	targets   map[[2]string]bool // (target, reference) recorded in full
	counted   int
	timer     *time.Timer
}

type refusalWindows struct {
	mu     sync.Mutex
	length time.Duration // 0: refusalWindow
	open   map[refusalKey]*openRefusals
	// record records a window's count; nil is Accounts.RecordRefusal.
	record func(context.Context, controlplane.Principal, controlplane.RefusedAttempt) error
}

// admitRefusal reports whether a refused attempt is recorded in full now;
// otherwise its window counts it.
func (s *Server) admitRefusal(p controlplane.Principal, a controlplane.RefusedAttempt) bool {
	w := &s.guards.refusals
	key := refusalKey{p.TenantID, p.ID, a.Action, a.Reason}
	target := [2]string{a.Target, a.Reference}
	w.mu.Lock()
	defer w.mu.Unlock()
	o := w.open[key]
	if o == nil {
		if w.open == nil {
			w.open = map[refusalKey]*openRefusals{}
		}
		length := w.length
		if length == 0 {
			length = refusalWindow
		}
		o = &openRefusals{principal: p, targets: map[[2]string]bool{target: true}}
		w.open[key] = o
		o.timer = time.AfterFunc(length, func() { s.closeRefusals(key, o) })
		return true
	}
	if !o.targets[target] && len(o.targets) < refusalTargets {
		o.targets[target] = true
		return true
	}
	o.counted++
	return false
}

// closeRefusals ends a window and records what it counted.
func (s *Server) closeRefusals(key refusalKey, o *openRefusals) {
	w := &s.guards.refusals
	w.mu.Lock()
	if w.open[key] != o {
		w.mu.Unlock()
		return
	}
	delete(w.open, key)
	w.mu.Unlock()
	s.recordCounted(key, o)
}

// recordCounted adds one event for the attempts a closed window counted:
// its actor, action and reason, the organization as target, and their number.
func (s *Server) recordCounted(key refusalKey, o *openRefusals) {
	if o.counted == 0 {
		return
	}
	record := s.guards.refusals.record
	if record == nil {
		record = s.accounts.RecordRefusal
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := record(ctx, o.principal, controlplane.RefusedAttempt{Action: key.action, Reason: key.reason, Attempts: o.counted})
	if err != nil && s.telemetry != nil {
		s.telemetry.refusalUnrecorded()
	}
}

// FlushRefusals closes every open window at once, recording what each
// counted. Call it once the server has stopped serving.
func (s *Server) FlushRefusals() {
	w := &s.guards.refusals
	w.mu.Lock()
	open := w.open
	w.open = nil
	w.mu.Unlock()
	for key, o := range open {
		o.timer.Stop()
		s.recordCounted(key, o)
	}
}
