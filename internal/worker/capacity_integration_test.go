//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
)

func TestBarrierCapacityOneSlotThreeStoresAndReplay(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	for i, id := range []string{"b", "c"} {
		provisionAgent(t, w, options.Root, id, uint32(61212+i))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := w.host.Retire(ctx, id, 1000); err != nil {
				t.Error(err)
			}
		})
	}
	event := harnessstore.Event{ID: "before-preemption", Subjects: []string{"agent/a", "event/before-preemption"}, Body: []byte("local effect")}
	first, err := w.Send(t.Context(), "a", event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Start(t.Context(), "b"); !errors.Is(err, runtime.ErrCapacity) {
		t.Fatal("ordinary capacity exceeded:", err)
	}
	if err = w.Fence(t.Context(), "b", "request/unrelated"); err != nil {
		t.Fatal(err)
	}
	placements, err := w.store.Placements(t.Context(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if placements[0].State != "STOPPED" || !placements[0].UncleanStop || placements[1].State != "STOPPED" || !placements[1].FenceOnly {
		t.Fatal("eviction/temporary scope not recorded:", placements)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || len(runs) != 0 {
		t.Fatal("temporary guest kept its slot:", runs, err)
	}
	if err = w.Fence(t.Context(), "c", "request/unrelated"); err != nil {
		t.Fatal(err)
	}
	replayed, err := w.Send(t.Context(), "a", event)
	if err != nil || !replayed.Replayed || !bytes.Equal(first.Result, replayed.Result) {
		t.Fatal("preemption lost idempotency:", replayed, err)
	}
	second, err := w.Send(t.Context(), "a", harnessstore.Event{ID: "after-preemption", Subjects: []string{"agent/a", "event/after-preemption"}, Body: []byte("second effect")})
	if err != nil || !bytes.Contains(second.Result, []byte(`"effects":2`)) {
		t.Fatal("duplicate/missing effect:", string(second.Result), err)
	}
	// Three complete manifests with one physical slot. Every temporary LIVE or
	// QUIESCING boot is barrier-only and releases its slot before the next target.
	for _, id := range []string{"c", "b", "a"} {
		if err = w.store.RequestDeletion(t.Context(), "user-"+id, id); err != nil {
			t.Fatal(err)
		}
		if err = w.store.ReconcileRevocation(t.Context(), id, w); err != nil {
			t.Fatal(err)
		}
		if err = w.SealDeletedStore(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	var ack, sealed int
	if err = db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "deletion_targets"}.Sanitize()+" WHERE acknowledged").Scan(&ack); err != nil || ack != 9 {
		t.Fatal(ack, err)
	}
	if err = db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "store_seals"}.Sanitize()).Scan(&sealed); err != nil || sealed != 3 {
		t.Fatal(sealed, err)
	}
	if runs, err = w.Reconcile(t.Context()); err != nil || len(runs) != 0 {
		t.Fatal(runs, err)
	}
}
