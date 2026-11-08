package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type admissionRuntime struct {
	*vmruntime.MockRuntime
	blocked, held bool
}

type preparedRuntime struct {
	*admissionRuntime
	target string
}

func (r *preparedRuntime) WithPreparedDelivery(ctx context.Context, target string, fn func(context.Context) error) error {
	r.target = target
	return r.WithDeliveryAdmission(ctx, fn)
}

func TestPreparedDeliveryFailureDoesNotConsumeAttempt(t *testing.T) {
	s, _ := freshStore(t, "auto", 1)
	r := &preparedRuntime{admissionRuntime: &admissionRuntime{MockRuntime: mockStores(t, t.TempDir(), "a", "b", "c"), blocked: true}}
	if _, err := s.Submit(t.Context(), "a", "one", submission()); err != nil {
		t.Fatal(err)
	}
	id, err := s.HeadDelivery(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DispatchMailbox(t.Context(), id, time.Minute, r); !errors.Is(err, ErrUnavailable) || r.target != "b" {
		t.Fatal(r.target, err)
	}
	var attempts int
	if err = s.pool.QueryRow(t.Context(), "SELECT m.attempts+o.attempts FROM agent_mailboxes m JOIN outbox o ON o.mailbox_id=m.id WHERE m.id=$1", id).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal(attempts, err)
	}
}

func (r *admissionRuntime) WithDeliveryAdmission(ctx context.Context, fn func(context.Context) error) error {
	if r.blocked {
		return ErrUnavailable
	}
	r.held = true
	defer func() { r.held = false }()
	return fn(ctx)
}
func (r *admissionRuntime) Fence(ctx context.Context, target, subject string) error {
	if r.held {
		return errors.New("barrier attempted while application admission was held")
	}
	return r.MockRuntime.Fence(ctx, target, subject)
}

func TestDeliveryBackpressureDoesNotConsumeAttempt(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	r := &admissionRuntime{MockRuntime: mockStores(t, t.TempDir(), "a", "b", "c"), blocked: true}
	r.SetHandler(func(ctx context.Context, _ string, _ harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		return localEffect(ctx, tx)
	})
	if _, err := s.Submit(t.Context(), "a", "one", submission()); err != nil {
		t.Fatal(err)
	}
	if err := s.DispatchOne(t.Context(), "b", time.Minute, r); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	var attempts, outboxAttempts int
	var authorized bool
	if err := s.pool.QueryRow(t.Context(), `SELECT m.attempts,o.attempts,m.dispatch_authorized FROM agent_mailboxes m JOIN outbox o ON o.mailbox_id=m.id WHERE m.dest_agent_id='b'`).Scan(&attempts, &outboxAttempts, &authorized); err != nil || attempts != 0 || outboxAttempts != 0 || authorized {
		t.Fatal(attempts, outboxAttempts, authorized, err)
	}
	r.blocked = false
	if err := s.DispatchOne(t.Context(), "b", time.Minute, r); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryRetirementReleasesAdmissionBeforeFences(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	r := &admissionRuntime{MockRuntime: mockStores(t, t.TempDir(), "a", "b", "c")}
	request, err := s.Submit(t.Context(), "a", "one", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(t.Context(), "user-a", request.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.DispatchOne(t.Context(), "b", time.Minute, r); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = s.pool.QueryRow(t.Context(), "SELECT state FROM agent_requests WHERE id=$1", request.RequestID).Scan(&state); err != nil || state != "CANCELED" {
		t.Fatal(state, err)
	}
}
