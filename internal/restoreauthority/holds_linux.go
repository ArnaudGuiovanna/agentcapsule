//go:build linux && cgo

package restoreauthority

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
)

// Holds per store (docs/adr/006-authority-service.md, "Changes after the
// v0.1.0 audit"). Until then a hold kept the catalogue's single SQLite write
// transaction while its callback ran: a key hold of one agent, up to
// max_key_hold, stopped every operation of every other agent. Now a hold
// checks its preconditions in a short transaction, and keeps only locks of
// its own store in this process's memory while its callback runs. The
// SQLite connection is free for other stores' operations.
//
// Each store has two locks:
//
//   - identity: its binding. Every hold that uses the binding takes it
//     shared; a reservation and a seal take it exclusively, so neither
//     happens while a hold runs, as before. An activation takes it
//     exclusively too: no outcome is recorded for the store while its
//     restored image is checked and published.
//   - subjects: its revocation scope. A fences hold and an activation take
//     it shared; a new revocation subject, or a new store in a subject's
//     scope, takes it exclusively for each store it adds. The wildcard
//     store "" stands for every store: a subject begun without a scope takes
//     its lock exclusively, and every fences hold takes it shared.
//
// An operation takes all its locks before anything else, in one order (by
// kind, then store), so no two operations wait for each other. A wait ends
// with the operation's context, as an outage.
//
// The locks live in memory, so they exclude holds within one process only.
// One process owns a catalogue (the authority service, ADR 006 §1). Handles
// opened in one process on the same file share one table, so the package's
// tests, which stand for two processes with two handles, keep their meaning.

type lockKind int

const (
	identityLock lockKind = iota
	subjectsLock
)

// wildcard is the store of a subject whose scope is every store. No store
// has this name: validName refuses an empty one.
const wildcard = ""

type lockRequest struct {
	kind      lockKind
	store     string
	exclusive bool
}

type lockKey struct {
	kind  lockKind
	store string
}

type lockState struct {
	readers int
	writer  bool
}

// lockTable is the locks of one catalogue file, shared by its handles in
// this process.
type lockTable struct {
	mu      sync.Mutex
	locks   map[lockKey]*lockState
	changed chan struct{}
	refs    int
	file    fileID
}

type fileID struct{ device, inode uint64 }

var lockTables = struct {
	sync.Mutex
	byFile map[fileID]*lockTable
}{byFile: map[fileID]*lockTable{}}

// openLocks returns the lock table of a catalogue file.
func openLocks(device, inode uint64) *lockTable {
	id := fileID{device, inode}
	lockTables.Lock()
	defer lockTables.Unlock()
	t := lockTables.byFile[id]
	if t == nil {
		t = &lockTable{locks: map[lockKey]*lockState{}, changed: make(chan struct{}), file: id}
		lockTables.byFile[id] = t
	}
	t.refs++
	return t
}

func (t *lockTable) close() {
	if t == nil {
		return
	}
	lockTables.Lock()
	defer lockTables.Unlock()
	if t.refs--; t.refs == 0 {
		delete(lockTables.byFile, t.file)
	}
}

// acquire takes every lock of reqs, in order, and returns their release.
func (t *lockTable) acquire(ctx context.Context, reqs []lockRequest) (func(), error) {
	reqs = normalize(reqs)
	held := 0
	release := func() {
		t.mu.Lock()
		for _, r := range reqs[:held] {
			k := lockKey{r.kind, r.store}
			l := t.locks[k]
			if r.exclusive {
				l.writer = false
			} else {
				l.readers--
			}
			if !l.writer && l.readers == 0 {
				delete(t.locks, k)
			}
		}
		close(t.changed)
		t.changed = make(chan struct{})
		t.mu.Unlock()
	}
	for _, r := range reqs {
		for {
			t.mu.Lock()
			k := lockKey{r.kind, r.store}
			l := t.locks[k]
			if l == nil {
				l = &lockState{}
				t.locks[k] = l
			}
			free := !l.writer && (!r.exclusive || l.readers == 0)
			if free {
				if r.exclusive {
					l.writer = true
				} else {
					l.readers++
				}
				held++
				t.mu.Unlock()
				break
			}
			changed := t.changed
			t.mu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
				release()
				return nil, errors.Join(ErrUnavailable, context.Cause(ctx))
			}
		}
	}
	return release, nil
}

// normalize sorts reqs and merges those of one lock: exclusive wins.
func normalize(reqs []lockRequest) []lockRequest {
	out := slices.Clone(reqs)
	slices.SortFunc(out, func(a, b lockRequest) int {
		return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.store, b.store))
	})
	merged := out[:0]
	for _, r := range out {
		if n := len(merged); n > 0 && merged[n-1].kind == r.kind && merged[n-1].store == r.store {
			merged[n-1].exclusive = merged[n-1].exclusive || r.exclusive
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// holding runs fn with the locks of reqs.
func (c *Catalog) holding(ctx context.Context, reqs []lockRequest, fn func() error) error {
	release, err := c.locks.acquire(ctx, reqs)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// usesBinding is the lock of a hold that uses store's binding.
func usesBinding(store string) lockRequest { return lockRequest{kind: identityLock, store: store} }

// changesBinding is the lock of a reservation or a seal of store.
func changesBinding(store string) lockRequest {
	return lockRequest{kind: identityLock, store: store, exclusive: true}
}

// readsScope are the locks of a hold that must see no new revocation subject
// in store's scope while it runs.
func readsScope(store string) []lockRequest {
	return []lockRequest{{kind: subjectsLock, store: store}, {kind: subjectsLock, store: wildcard}}
}

// widensScope is the lock of a write that adds a subject to store's scope,
// or to every store's for the wildcard.
func widensScope(store string) lockRequest {
	return lockRequest{kind: subjectsLock, store: store, exclusive: true}
}
