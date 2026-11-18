package harnessstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// Hold opens a write transaction on s, as a delivery's handler that never
// returns does, and keeps it until release is called.
func hold(t *testing.T, s *Store) (release func()) {
	t.Helper()
	entered, done := make(chan struct{}), make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.Apply(context.Background(), Event{ID: "held", Subjects: []string{"agent/held"}, Body: []byte("{}")},
			func(context.Context, SQL) ([]byte, error) {
				close(entered)
				<-stop
				return nil, errors.New("released")
			})
	}()
	<-entered
	return func() { close(stop); <-done }
}

// A store that another transaction holds refuses a new one once its busy
// timeout has passed; Busy tells that refusal from the store's other
// failures, so that a harness's background loop can wait it out.
func TestBusyTellsAHeldStore(t *testing.T) {
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release := hold(t, s)
	err = s.Local(t.Context(), []string{"agent/other"}, func(SQL) error { return nil })
	if err == nil || !Busy(err) {
		t.Fatal("a held store", err)
	}
	release()
	if err = s.Local(t.Context(), []string{"agent/other"}, func(SQL) error { return nil }); err != nil {
		t.Fatal("a released store", err)
	}
	for _, other := range []error{nil, ErrFenced, ErrConflict, ErrCommitUnknown, context.Canceled, errors.New("disk I/O error")} {
		if Busy(other) {
			t.Error("busy", other)
		}
	}
}
