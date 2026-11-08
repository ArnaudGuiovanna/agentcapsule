package harnessstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestLocalWorkSerializesWithFenceAndRollsBack(t *testing.T) {
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Local(t.Context(), []string{"request/r"}, func(tx SQL) error {
			if _, err := tx.ExecContext(t.Context(), "CREATE TABLE work(value INTEGER)"); err != nil {
				return err
			}
			close(entered)
			<-release
			_, err := tx.ExecContext(t.Context(), "INSERT INTO work VALUES(1)")
			return err
		})
	}()
	<-entered
	fenced := make(chan error, 1)
	go func() { fenced <- s.Fence(t.Context(), "request/r") }()
	select {
	case err := <-fenced:
		t.Fatal("fence bypassed transaction", err)
	default:
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-fenced; err != nil {
		t.Fatal(err)
	}
	if err = s.Local(t.Context(), []string{"request/r"}, func(SQL) error { t.Error("revoked mutation ran"); return nil }); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	injected := errors.New("rollback")
	if err = s.Local(t.Context(), []string{"agent/a"}, func(tx SQL) error {
		_, err := tx.ExecContext(t.Context(), "INSERT INTO work VALUES(2)")
		if err != nil {
			return err
		}
		return injected
	}); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	var n int
	if err = s.Local(context.Background(), []string{"agent/a"}, func(tx SQL) error { return tx.QueryRowContext(t.Context(), "SELECT count(*) FROM work").Scan(&n) }); err != nil || n != 1 {
		t.Fatal("local rollback lost", n, err)
	}
}
