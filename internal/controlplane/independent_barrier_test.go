//go:build linux && cgo

package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// This adapter exercises SQL final publication against the real independent
// catalogue and MockRuntime SQLite fences. It explicitly supplies trusted ACKs;
// authenticated worker receipts and physical retirement are separate tests.
type independentBarrierRuntime struct {
	local               *vmruntime.MockRuntime
	root                *restoreauthority.Catalog
	bindings            map[string]restoreauthority.Binding
	calls, publications int
	reserveAfterThird   bool
}

func (r *independentBarrierRuntime) Fence(ctx context.Context, target, subject string) error {
	if _, err := r.root.BeginRevocation(ctx, subject); err != nil {
		return err
	}
	snapshot, err := r.root.Scan(ctx, r.bindings[target])
	if err != nil {
		return err
	}
	for _, s := range snapshot.Subjects {
		if err = r.local.Fence(ctx, target, s); err != nil {
			return err
		}
	}
	if err = r.root.RecordVerifiedFence(ctx, snapshot); err != nil {
		return err
	}
	r.calls++
	if r.reserveAfterThird && r.calls == 3 {
		_, err = r.root.ReserveIncarnation(ctx, r.bindings["b"], "restore-b")
	}
	return err
}
func (r *independentBarrierRuntime) CommitBarrier(ctx context.Context, subject string, targets []string, publish func() error) error {
	r.publications++
	bindings := make([]restoreauthority.Binding, 0, len(targets))
	for _, target := range targets {
		bindings = append(bindings, r.bindings[target])
	}
	return r.root.WithRevocation(ctx, subject, bindings, publish)
}

func TestRevocationRechecksIndependentReceiptsAfterSQLAcknowledgment(t *testing.T) {
	for _, kind := range []string{"agent", "request"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := freshStore(t, "auto", 5)
			root, err := restoreauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), "keyauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			r := &independentBarrierRuntime{root: root, local: mockStores(t, t.TempDir(), "a", "b", "c"), bindings: map[string]restoreauthority.Binding{}, reserveAfterThird: true}
			for _, id := range []string{"a", "b", "c"} {
				b, err := root.Register(t.Context(), id, "volume-"+id)
				if err != nil {
					t.Fatal(err)
				}
				r.bindings[id] = b
			}
			var reconcile func() error
			var pending func() bool
			if kind == "agent" {
				if err = s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
					t.Fatal(err)
				}
				reconcile = func() error { return s.ReconcileRevocation(t.Context(), "a", r) }
				pending = func() bool {
					var phase string
					if err := s.pool.QueryRow(t.Context(), "SELECT phase FROM deletion_operations WHERE agent_id='a'").Scan(&phase); err != nil {
						t.Fatal(err)
					}
					return phase == "FENCING"
				}
			} else {
				req, err := s.Submit(t.Context(), "a", "request", submission())
				if err != nil {
					t.Fatal(err)
				}
				if err = s.RequestCancellation(t.Context(), "user-a", req.RequestID); err != nil {
					t.Fatal(err)
				}
				reconcile = func() error { return s.ReconcileRequestClosure(t.Context(), req.RequestID, r) }
				pending = func() bool {
					var phase string
					if err := s.pool.QueryRow(t.Context(), "SELECT phase FROM request_closures WHERE request_id=$1", req.RequestID).Scan(&phase); err != nil {
						t.Fatal(err)
					}
					return phase == "FENCING"
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err = reconcile(); !errors.Is(err, restoreauthority.ErrStale) {
					t.Fatal("obsolete SQL acknowledgments completed revocation", err)
				}
				if !pending() {
					t.Fatal("terminal state published without current independent ACK")
				}
			}
			if r.calls != 3 || r.publications != 2 {
				t.Fatal("replay failed to verify already-acknowledged SQL manifest", r.calls, r.publications)
			}
		})
	}
}
