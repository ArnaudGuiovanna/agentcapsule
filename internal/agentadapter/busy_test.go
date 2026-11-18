package agentadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// The adapter's background loop waits out a store that a delivery's handler
// holds past the store's busy timeout (5 s), as the reference harness's
// does: ending there would end the adapter and, since a harness that exits
// ends its guest (ADR 012, question 6), count a crash. A store that fails
// otherwise still ends it.
func TestRunWaitsOutABusyStore(t *testing.T) {
	l := newLab(t, nil)
	entered, held, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(held)
		_, _ = l.store.Apply(context.Background(), harnessstore.Event{ID: "held", Subjects: []string{"agent/a"}, Body: []byte("{}")},
			func(context.Context, harnessstore.SQL) ([]byte, error) {
				close(entered)
				<-stop
				return nil, errors.New("released")
			})
	}()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.engine.Run(ctx) }()
	select {
	case err := <-done:
		t.Fatal("the loop ended while a handler held the store", err)
	case <-time.After(7 * time.Second):
	}
	close(stop)
	<-held
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("the loop's end", err)
	}
	if err := l.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.engine.Run(t.Context()); err == nil || harnessstore.Busy(err) {
		t.Fatal("a closed store", err)
	}
}
