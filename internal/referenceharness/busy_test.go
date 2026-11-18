package referenceharness

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// holdStore opens a write transaction on s, as a delivery's handler that
// never returns does, until release is called.
func holdStore(t *testing.T, s *harnessstore.Store) (release func()) {
	t.Helper()
	entered, done, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.Apply(context.Background(), harnessstore.Event{ID: "held", Subjects: []string{"agent/a"}, Body: []byte("{}")},
			func(context.Context, harnessstore.SQL) ([]byte, error) {
				close(entered)
				<-stop
				return nil, errors.New("released")
			})
	}()
	<-entered
	return func() { close(stop); <-done }
}

// The harness's background loop waits out a store that a delivery's handler
// holds past the store's busy timeout (5 s): it tries again at its next
// tick. Ending there would end the harness and, since a harness that exits
// ends its guest (ADR 012, question 6), count a crash for a guest that only
// had a slow or stuck handler. A store that fails otherwise still ends it.
func TestRunWaitsOutABusyStore(t *testing.T) {
	s, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("a", s, &ledger{})
	if err != nil {
		t.Fatal(err)
	}
	release := holdStore(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()
	select {
	case err = <-done:
		t.Fatal("the loop ended while a handler held the store", err)
	case <-time.After(7 * time.Second):
	}
	release()
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("the loop's end", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = h.Run(t.Context()); err == nil || harnessstore.Busy(err) {
		t.Fatal("a closed store", err)
	}
}
