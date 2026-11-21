package pgnotify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func databaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL test database is missing")
		}
		t.Skip("run scripts/verify-postgres.py for real PostgreSQL integration checks")
	}
	return dsn
}

func woken(c <-chan struct{}, within time.Duration) bool {
	select {
	case <-c:
		return true
	default:
	}
	select {
	case <-c:
		return true
	case <-time.After(within):
		return false
	}
}

func TestChannelNamesAreChecked(t *testing.T) {
	connect := func(context.Context) (*pgx.Conn, error) { return nil, errors.New("no database") }
	for _, bad := range [][]string{nil, {""}, {"Upper"}, {"a;b"}, {"x y"}} {
		if _, err := New(connect, bad...); !errors.Is(err, ErrInput) {
			t.Error("accepted", bad)
		}
	}
	if _, err := New(nil, "agentcapsule_invocation_stream"); !errors.Is(err, ErrInput) {
		t.Error("accepted no connection")
	}
}

// Without a connection, every subscriber is polled every second; a
// canceled subscription is not.
func TestSubscribersArePolledWithoutAConnection(t *testing.T) {
	l, err := New(func(context.Context) (*pgx.Conn, error) { return nil, errors.New("no database") }, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()
	c, stop := l.Subscribe("agentcapsule_invocation_stream", "op_1")
	gone, stopGone := l.Subscribe("agentcapsule_invocation_stream", "op_2")
	stopGone()
	stopGone()
	for range 2 {
		if !woken(c, 3*time.Second) {
			t.Fatal("not polled")
		}
	}
	if woken(gone, 1500*time.Millisecond) {
		t.Fatal("a canceled subscriber was polled")
	}
	stop()
	if l.Connected() {
		t.Fatal("connected without a database")
	}
}

// A notification wakes the subscribers of its channel and payload only. A
// lost connection puts them on the poll; once connected again, each is woken
// and notifications come again.
func TestNotificationsWakeTheirSubscribers(t *testing.T) {
	dsn := databaseURL(t)
	var pid atomic.Uint32
	l, err := New(func(ctx context.Context) (*pgx.Conn, error) {
		conn, err := pgx.Connect(ctx, dsn)
		if err == nil {
			pid.Store(conn.PgConn().PID())
		}
		return conn, err
	}, "agentcapsule_pgnotify_test")
	if err != nil {
		t.Fatal(err)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	payload := "op_" + hex.EncodeToString(b[:])
	mine, stop := l.Subscribe("agentcapsule_pgnotify_test", payload)
	defer stop()
	other, stopOther := l.Subscribe("agentcapsule_pgnotify_test", payload+"_other")
	defer stopOther()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for !l.Connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !l.Connected() {
		t.Fatal("the hub did not connect")
	}
	// Drain the wakes of the connection and of the poll before it.
	time.Sleep(100 * time.Millisecond)
	for woken(mine, 0) || woken(other, 0) {
	}
	sender, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close(context.Background())
	if _, err = sender.Exec(t.Context(), "SELECT pg_notify('agentcapsule_pgnotify_test', $1)", payload); err != nil {
		t.Fatal(err)
	}
	if !woken(mine, 5*time.Second) {
		t.Fatal("the notification did not wake its subscriber")
	}
	if woken(other, 300*time.Millisecond) {
		t.Fatal("another payload's subscriber was woken")
	}
	// The hub's connection is lost: the poll, then the reconnection.
	if _, err = sender.Exec(t.Context(), "SELECT pg_terminate_backend($1)", int32(pid.Load())); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for l.Connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !woken(other, 3*time.Second) {
		t.Fatal("not polled after the connection was lost")
	}
	deadline = time.Now().Add(15 * time.Second)
	for !l.Connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !l.Connected() {
		t.Fatal("the hub did not connect again")
	}
	time.Sleep(100 * time.Millisecond)
	for woken(mine, 0) {
	}
	if _, err = sender.Exec(t.Context(), "SELECT pg_notify('agentcapsule_pgnotify_test', $1)", payload); err != nil {
		t.Fatal(err)
	}
	if !woken(mine, 5*time.Second) {
		t.Fatal("no notification after the reconnection")
	}
}
