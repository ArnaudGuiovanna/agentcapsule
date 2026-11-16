//go:build linux && cgo

package authorityclient

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

type implementation interface {
	restoreauthority.Authority
	keyauthority.Provider
}

// The same life of an agent through both implementations of the worker's
// interface: in process, and through the service. The worker's tests will
// run against both the same way (ADR 006 §5, wave 2).
func TestBothImplementationsAgree(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) implementation{
		"in process": func(t *testing.T) implementation {
			keys, catalog := authorities(t, t.TempDir())
			return restoreauthority.Local{Catalog: catalog, Keys: keys}
		},
		"through the service": func(t *testing.T) implementation {
			keys, catalog := authorities(t, t.TempDir())
			return serve(t, keys, catalog).client(t)
		},
	} {
		t.Run(name, func(t *testing.T) { life(t, open(t)) })
	}
}

func life(t *testing.T, a implementation) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !strings.HasPrefix(a.Identity(), "restoreauth_") || !strings.HasPrefix(a.KeyAuthorityIdentity(), "keyauth_") {
		t.Fatal(a.Identity(), a.KeyAuthorityIdentity())
	}
	// Provisioning: the store, its key, the format of its volume, its first
	// boot's fence, its activation.
	b, err := a.Register(ctx, agent, volume)
	if err != nil || b != (restoreauthority.Binding{Store: agent, Volume: volume, Incarnation: 1}) {
		t.Fatal(b, err)
	}
	must(a.Ensure(ctx, agent, volume))
	var key []byte
	must(a.HoldKey(ctx, b, func(_ context.Context, k []byte) error { key = bytes.Clone(k); return nil }))
	must(a.WithKey(ctx, agent, volume, func(k []byte) error {
		if !bytes.Equal(k, key) || len(k) != 32 {
			t.Error("another key")
		}
		return nil
	}))
	r, err := a.Scan(ctx, b)
	must(err)
	if err = a.HoldFences(ctx, r, func(context.Context) error { t.Error("published before the fence"); return nil }); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	must(a.RecordVerifiedFence(ctx, r))
	published := false
	must(a.HoldFences(ctx, r, func(context.Context) error { published = true; return nil }))
	if !published {
		t.Fatal("not published")
	}
	// A delivery, and a platform call under the binding.
	must(a.CheckBinding(ctx, b))
	must(a.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-0", Digest: digest("first")}))
	if err = a.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-0", Digest: digest("other")}); !errors.Is(err, restoreauthority.ErrConflict) {
		t.Fatal(err)
	}
	called := errors.New("the callback's own error")
	if err = a.HoldBinding(ctx, b, func(context.Context) error { return called }); !errors.Is(err, called) {
		t.Fatal("the callback's error was not returned", err)
	}
	// A revocation, completed once the store acknowledged it.
	revision, err := a.BeginRevocation(ctx, "agent/x")
	if err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	if ack, sealed, err := a.SubjectBarrier(ctx, b, "agent/x"); err != nil || ack || sealed {
		t.Fatal(ack, sealed, err)
	}
	if err = a.HoldRevocation(ctx, "agent/x", []restoreauthority.Binding{b}, func(context.Context) error {
		t.Error("completed without the acknowledgment")
		return nil
	}); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	r, err = a.Scan(ctx, b)
	must(err)
	must(a.RecordVerifiedFence(ctx, r))
	completed := false
	must(a.HoldRevocation(ctx, "agent/x", []restoreauthority.Binding{b}, func(context.Context) error { completed = true; return nil }))
	if !completed {
		t.Fatal("not completed")
	}
	// An archive, then a restore from it that lacks event-1.
	archive, err := a.SignArchive(ctx, restoreauthority.Archive{ID: "arc_" + strings.Repeat("c", 32), Binding: b,
		HarnessDigest: "sha256:" + strings.Repeat("d", 64), Size: 4096, Digest: digest("bytes")})
	must(err)
	must(a.ValidateArchive(ctx, archive))
	archive.Size++
	if err = a.ValidateArchive(ctx, archive); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	must(a.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-1", Digest: digest("second")}))
	next, err := a.ReserveIncarnation(ctx, b, "restore-1")
	if err != nil || next.Incarnation != 2 {
		t.Fatal(next, err)
	}
	if err = a.CheckBinding(ctx, b); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	r, err = a.Scan(ctx, next)
	must(err)
	must(a.RecordVerifiedFence(ctx, r))
	image := map[string]bool{"event-0": true}
	inspect := func(recorded []restoreauthority.Outcome) ([]string, error) {
		missing := []string{}
		for _, o := range recorded {
			if !image[o.ID] {
				missing = append(missing, o.ID)
			}
		}
		return missing, nil
	}
	activated := false
	losses, err := a.ActivateRestored(ctx, r, restoreauthority.Activation{Inspect: inspect, Repair: func([]restoreauthority.Outcome) error { return nil },
		Publish: func(context.Context) error { activated = true; return nil }})
	lost := restoreauthority.Loss{ID: "event-1", Store: agent, Incarnation: 2}
	if err != nil || !activated || !reflect.DeepEqual(losses, []restoreauthority.Loss{lost}) {
		t.Fatal(losses, activated, err)
	}
	if status, got, err := a.OutcomeStatus(ctx, "event-1"); err != nil || status != restoreauthority.StatusLost || !reflect.DeepEqual(got, []restoreauthority.Loss{lost}) {
		t.Fatal(status, got, err)
	}
	// The rerun of the lost job.
	must(a.RecordOutcome(ctx, next, restoreauthority.Outcome{ID: "event-1", Digest: digest("rerun")}))
	if err = a.RecordRerun(ctx, next, restoreauthority.Outcome{ID: "event-1", Digest: digest("another")}); !errors.Is(err, restoreauthority.ErrConflict) {
		t.Fatal(err)
	}
	if err = a.RecordRerun(ctx, next, restoreauthority.Outcome{ID: "event-0", Digest: digest("first")}); !errors.Is(err, restoreauthority.ErrNotDeclared) {
		t.Fatal(err)
	}
	lost.Rerun, lost.RerunDigest = true, digest("rerun")
	if got, err := a.Losses(ctx, agent); err != nil || !reflect.DeepEqual(got, []restoreauthority.Loss{lost}) {
		t.Fatal(got, err)
	}
	// Deletion: the seal, then the key's destruction.
	must(a.RecordRetiredSeal(ctx, next))
	if _, err = a.Lookup(ctx, agent); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal(err)
	}
	if err = a.HoldKey(ctx, next, func(context.Context, []byte) error { t.Error("a sealed store's key held"); return nil }); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal(err)
	}
	must(a.Revoke(ctx, agent, volume))
	if err = a.WithKey(ctx, agent, volume, func([]byte) error { t.Error("a destroyed key held"); return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal(err)
	}
	if err = a.Ensure(ctx, agent, volume); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed key came back", err)
	}
}
