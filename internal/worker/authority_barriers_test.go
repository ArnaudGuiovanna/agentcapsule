//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

func assertLocalBarrier(t *testing.T, local *harnessstore.Store, subject string) {
	t.Helper()
	_, err := local.Apply(t.Context(), harnessstore.Event{ID: "blocked-" + subject, Subjects: []string{subject}}, func(context.Context, harnessstore.SQL) ([]byte, error) {
		t.Error("revoked work reached local mutation")
		return nil, nil
	})
	if !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("durable guest fence missing", subject, err)
	}
}

func TestBootSynchronizesIndependentAndSQLRevocationsBeforeConfirmation(t *testing.T) {
	b := newBootLab(t)
	a := b.withAuthority(t, true)
	// Independent history remains present even if the SQL snapshot omits it.
	if _, err := a.BeginRevocation(t.Context(), "agent/old-decision"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(t.Context(), "INSERT INTO revocation_catalogue(subject) VALUES($1)", "request/current-intent"); err != nil {
		t.Fatal(err)
	}
	run := b.claim(t)
	client, local := bootClientHarness(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { return nil }, false, nil, nil)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"agent/old-decision", "request/current-intent"} {
		assertLocalBarrier(t, local, subject)
		ack, sealed, err := a.SubjectBarrier(t.Context(), enrollmentBinding(b.e), subject)
		if err != nil || !ack || sealed {
			t.Fatal("authenticated guest receipt missing", ack, sealed, err)
		}
	}
	if _, err := a.BeginRevocation(t.Context(), "agent/concurrent"); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("stale catalogue confirmed", err)
	}
	if b.initialized(t) {
		t.Fatal("unconfirmed initialization published")
	}
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal("snapshot retry", err)
	}
	assertLocalBarrier(t, local, "agent/concurrent")
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); err != nil {
		t.Fatal("current catalogue cannot confirm", err)
	}
}

func TestLostGuestFenceACKDoesNotBecomeIndependentReceipt(t *testing.T) {
	b := newBootLab(t)
	a := b.withAuthority(t, true)
	subject := "agent/revoked"
	if _, err := a.BeginRevocation(t.Context(), subject); err != nil {
		t.Fatal(err)
	}
	run := b.claim(t)
	var drop atomic.Bool
	drop.Store(true)
	client, local := bootClientHarness(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { return nil }, false, nil, &drop)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("lost fence ACK treated as success", err)
	}
	assertLocalBarrier(t, local, subject)
	ack, _, err := a.SubjectBarrier(t.Context(), enrollmentBinding(b.e), subject)
	if err != nil || ack {
		t.Fatal("unknown guest response became durable root ACK", ack, err)
	}
	if err = b.opts.Confirm(t.Context(), b.e.AgentID, run); err == nil {
		t.Fatal("missing ACK confirmed")
	}
	if b.initialized(t) {
		t.Fatal("unknown fence initialized SQL")
	}
	if err = b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal("idempotent fence retry", err)
	}
	if err = b.opts.Confirm(t.Context(), b.e.AgentID, run); err != nil {
		t.Fatal(err)
	}
	ack, _, err = a.SubjectBarrier(t.Context(), enrollmentBinding(b.e), subject)
	if err != nil || !ack {
		t.Fatal("successful retry not recorded", ack, err)
	}
}
