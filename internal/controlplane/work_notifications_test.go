package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// workListener listens on agentcapsule_work, where every test of the
// database notifies: it waits for one host's notifications only.
type workListener struct {
	t    *testing.T
	conn *pgx.Conn
}

func listenForWork(t *testing.T, s *Store) *workListener {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), s.pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err = conn.Exec(t.Context(), "LISTEN agentcapsule_work"); err != nil {
		t.Fatal(err)
	}
	return &workListener{t: t, conn: conn}
}

// next waits up to wait for a notification naming host, and reports whether
// one came. Any notification that names something other than a host is a
// failure: the payload is a host's ID, never content.
func (l *workListener) next(host string, wait time.Duration) bool {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(l.t.Context(), wait)
	defer cancel()
	for {
		n, err := l.conn.WaitForNotification(ctx)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false
		}
		if err != nil {
			l.t.Fatal(err)
		}
		if n.Payload == host {
			return true
		}
	}
}

// await fails unless what notifies host.
func (l *workListener) await(host, what string, do func()) {
	l.t.Helper()
	for l.next(host, 100*time.Millisecond) {
	} // what came before
	do()
	if !l.next(host, 10*time.Second) {
		l.t.Fatal("no notification for the host's worker:", what)
	}
}

// New work for a host notifies its worker on agentcapsule_work, with the
// host's ID as the only payload, from the transaction that records it
// (P-01): a delivery queued, the closure of a request, a mailbox head that
// leaves the queue, a wake or sleep recorded and ended, a VM that stops, a
// deletion.
func TestNewWorkNotifiesItsHost(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	sender, recipient := "notify-"+newID("h")[2:14], "notify-"+newID("h")[2:14]
	ctx := t.Context()
	for agent, host := range map[string]string{"a": sender, "b": recipient} {
		if _, err := s.pool.Exec(ctx, "INSERT INTO worker_hosts(host_id) VALUES($1)", host); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, "INSERT INTO agent_placements(agent_id,host_id) VALUES($1,$2)", agent, host); err != nil {
			t.Fatal(err)
		}
	}
	l := listenForWork(t, s)
	var request Receipt
	l.await(recipient, "a request queued for its recipient", func() {
		var err error
		if request, err = s.Submit(ctx, "a", "notified", submission()); err != nil {
			t.Fatal(err)
		}
	})
	l.await(sender, "a request's closure, for its sender's host", func() {
		if err := s.RequestCancellation(ctx, "user-a", request.RequestID); err != nil {
			t.Fatal(err)
		}
	})
	l.await(recipient, "a mailbox head that leaves the queue", func() {
		if _, err := s.pool.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='CANCELED' WHERE ref_id=$1 AND kind='request'", request.RequestID); err != nil {
			t.Fatal(err)
		}
	})
	op := newID("op")
	l.await(recipient, "a wake recorded", func() {
		if _, err := s.pool.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
            VALUES($1,'someone','b',$2,1,'wake')`, op, recipient); err != nil {
			t.Fatal(err)
		}
	})
	l.await(recipient, "a wake ended", func() {
		if _, err := s.pool.Exec(ctx, "UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1", op); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := s.pool.Exec(ctx, "UPDATE agent_placements SET state='RUNNING',generation=1,vm_id='vm-1',worker_id='w' WHERE agent_id='b'"); err != nil {
		t.Fatal(err)
	}
	l.await(recipient, "a VM stopped", func() {
		if _, err := s.pool.Exec(ctx, "UPDATE agent_placements SET state='STOPPED',vm_id='',worker_id='' WHERE agent_id='b'"); err != nil {
			t.Fatal(err)
		}
	})
	l.await(sender, "a deletion", func() {
		if err := s.RequestDeletion(ctx, "user-a", "a"); err != nil {
			t.Fatal(err)
		}
	})
	// A change that brings no work notifies no one.
	for l.next(recipient, 100*time.Millisecond) {
	}
	if _, err := s.pool.Exec(ctx, "UPDATE agent_placements SET state='RUNNING',generation=2,vm_id='vm-2',worker_id='w' WHERE agent_id='b'"); err != nil {
		t.Fatal(err)
	}
	if l.next(recipient, 300*time.Millisecond) {
		t.Fatal("a boot notified the worker")
	}
}
