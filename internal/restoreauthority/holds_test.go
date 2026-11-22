//go:build linux && cgo

package restoreauthority

import (
	"context"
	"errors"
	"testing"
	"time"
)

// proceeds fails unless op returns within d.
func proceeds(t *testing.T, d time.Duration, what string, op func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s waited for another store's hold", what)
	}
}

// blocked fails if op returns within d; it returns op's result channel.
func blocked(t *testing.T, d time.Duration, what string, op func() error) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		t.Fatalf("%s overtook the store's own hold: %v", what, err)
	case <-time.After(d):
	}
	return done
}

// A hold of one store's binding, as a key hold during a boot, keeps only that
// store: every operation of another store proceeds, and the identity gate of
// the held store still excludes its reservation and its seal (S-15).
func TestHoldOnOneStoreLeavesOtherStoresFree(t *testing.T) {
	c, a := fixture(t)
	other := reopen(t, c)
	b, err := c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() { held <- c.WithBinding(t.Context(), a, func() error { close(entered); <-release; return nil }) }()
	<-entered
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	const d = 5 * time.Second
	proceeds(t, d, "check of store-b", func() error { return other.WithBinding(t.Context(), b, func() error { return nil }) })
	proceeds(t, d, "outcome of store-b", func() error {
		return other.RecordOutcome(t.Context(), b, Outcome{ID: "outcome-b", Digest: [32]byte{1}})
	})
	proceeds(t, d, "revocation in store-b's scope", func() error {
		return other.BeginRevocations(t.Context(), []Scope{{Subject: "event/b", Stores: []string{"store-b"}}})
	})
	proceeds(t, d, "fences of store-b", func() error {
		r, err := other.Scan(t.Context(), b)
		if err == nil {
			err = other.RecordVerifiedFence(t.Context(), r)
		}
		if err == nil {
			err = other.WithCurrentFences(t.Context(), r, func() error { return nil })
		}
		return err
	})
	proceeds(t, d, "registration of store-c", func() error { _, err := other.Register(t.Context(), "store-c", "volume-c"); return err })
	proceeds(t, d, "reservation of store-b", func() error { _, err := other.ReserveIncarnation(t.Context(), b, "restore-b"); return err })
	reserved := blocked(t, 50*time.Millisecond, "reservation of store-a", func() error {
		_, err := other.ReserveIncarnation(t.Context(), a, "restore-a")
		return err
	})
	close(release)
	if err = <-held; err != nil {
		t.Fatal(err)
	}
	if err = <-reserved; err != nil {
		t.Fatal(err)
	}
}

// A fences hold excludes a new subject in its store's scope, and a subject of
// unknown scope, but no revocation of another store (holds per store keep
// TestPublicationSerializesConcurrentRevocation's guarantee).
func TestFencesHoldExcludesOnlyItsOwnScope(t *testing.T) {
	c, a := fixture(t)
	other := reopen(t, c)
	if _, err := c.Register(t.Context(), "store-b", "volume-b"); err != nil {
		t.Fatal(err)
	}
	r := receipt(t, c, a)
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- c.WithCurrentFences(t.Context(), r, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	proceeds(t, 5*time.Second, "revocation of store-b", func() error {
		return other.BeginRevocations(t.Context(), []Scope{{Subject: "event/b", Stores: []string{"store-b"}}})
	})
	own := blocked(t, 50*time.Millisecond, "revocation of store-a", func() error {
		return other.BeginRevocations(t.Context(), []Scope{{Subject: "event/a", Stores: []string{"store-a"}}})
	})
	everywhere := blocked(t, 50*time.Millisecond, "revocation of unknown scope", func() error {
		_, err := other.BeginRevocation(t.Context(), "agent/everywhere")
		return err
	})
	close(release)
	for _, done := range []chan error{held, own, everywhere} {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := c.WithCurrentFences(t.Context(), r, func() error { t.Error("published past a new revocation"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
}

// A wait for a store's lock ends with the caller's context, as an outage.
func TestHoldWaitEndsWithTheContext(t *testing.T) {
	c, a := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() { held <- c.WithBinding(t.Context(), a, func() error { close(entered); <-release; return nil }) }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.ReserveIncarnation(ctx, a, "restore"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	// Nothing stays locked once both are done.
	if _, err := c.ReserveIncarnation(t.Context(), a, "restore"); err != nil {
		t.Fatal(err)
	}
	c.locks.mu.Lock()
	left := len(c.locks.locks)
	c.locks.mu.Unlock()
	if left != 0 {
		t.Fatal("locks left", left)
	}
}
