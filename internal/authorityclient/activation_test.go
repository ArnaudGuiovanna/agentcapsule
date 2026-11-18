//go:build linux && cgo

package authorityclient

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// restored is a store whose outcome event-0 was acknowledged, then restored
// into incarnation 2 from an image without it: the receipt is its current
// fenced scan.
func restored(t *testing.T) (*lab, *Client, restoreauthority.Binding, restoreauthority.Receipt) {
	t.Helper()
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	b, _ := fenced(t, c, "store-a", "volume-a")
	if err := c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-0", Digest: digest("first")}); err != nil {
		t.Fatal(err)
	}
	next, err := c.ReserveIncarnation(ctx, b, "restore-1")
	if err != nil || next.Incarnation != 2 {
		t.Fatal(next, err)
	}
	r, err := c.Scan(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	return l, c, next, r
}

func lostAt(incarnation uint64) restoreauthority.Loss {
	return restoreauthority.Loss{ID: "event-0", Store: "store-a", Incarnation: incarnation}
}

// undeclaredLossPreventsActivationTest, through the client.
func TestUndeclaredLossPreventsActivation(t *testing.T) {
	_, c, _, r := restored(t)
	ctx := t.Context()
	recorded, list, err := c.RecordedOutcomes(ctx, r)
	if err != nil || len(recorded) != 1 || recorded[0].ID != "event-0" {
		t.Fatal(recorded, err)
	}
	if status, _, err := c.OutcomeStatus(ctx, "event-0"); err != nil || status != restoreauthority.StatusConfirmed {
		t.Fatal(status, err)
	}
	err = c.HoldActivation(ctx, r, list, []string{"event-0"}, func(context.Context) error {
		t.Error("activated with an undeclared loss")
		return nil
	})
	if !errors.Is(err, restoreauthority.ErrHistory) {
		t.Fatal(err)
	}
}

// declaredLossAllowsActivationTest, through the client.
func TestDeclaredLossAllowsActivation(t *testing.T) {
	_, c, _, r := restored(t)
	ctx := t.Context()
	_, list, err := c.RecordedOutcomes(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	losses, err := c.DeclareLosses(ctx, r, list, []string{"event-0"})
	if err != nil || !reflect.DeepEqual(losses, []restoreauthority.Loss{lostAt(2)}) {
		t.Fatal(losses, err)
	}
	if status, _, err := c.OutcomeStatus(ctx, "event-0"); err != nil || status != restoreauthority.StatusLost {
		t.Fatal(status, err)
	}
	ready := false
	if err = c.HoldActivation(ctx, r, list, []string{"event-0"}, func(context.Context) error { ready = true; return nil }); err != nil || !ready {
		t.Fatal(err)
	}
	// The declaration names only recorded work.
	if _, err = c.DeclareLosses(ctx, r, list, []string{"never-recorded"}); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal(err)
	}
}

// The inspection runs in the worker, outside any hold: the declaration and
// the activation name the recorded list it inspected, and a list that
// changed since is stale. The activation then starts again.
func TestActivationRefusesAChangedRecordedList(t *testing.T) {
	l, c, b, r := restored(t)
	ctx := t.Context()
	_, list, err := c.RecordedOutcomes(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-1", Digest: digest("second")}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.DeclareLosses(ctx, r, list, []string{"event-0"}); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("a declaration against a changed list", err)
	}
	if losses, err := c.Losses(ctx, "store-a"); err != nil || len(losses) != 0 {
		t.Fatal("a stale declaration declared", losses, err)
	}
	if err = c.HoldActivation(ctx, r, list, nil, func(context.Context) error {
		t.Error("activated against a changed list")
		return nil
	}); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
	// The whole activation: the list changes after the first inspection,
	// so it inspects again the new list.
	other := l.client(t)
	var inspected [][]string
	inspect := func(recorded []restoreauthority.Outcome) ([]string, error) {
		ids := []string{}
		for _, o := range recorded {
			ids = append(ids, o.ID)
		}
		inspected = append(inspected, ids)
		if len(inspected) == 1 {
			if err := other.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-2", Digest: digest("third")}); err != nil {
				return nil, err
			}
		}
		return []string{"event-0"}, nil // the image holds what came after the archive
	}
	published := 0
	losses, err := c.ActivateRestored(ctx, r, restoreauthority.Activation{Inspect: inspect, Publish: func(context.Context) error { published++; return nil }})
	if err != nil || published != 1 || !reflect.DeepEqual(losses, []restoreauthority.Loss{lostAt(2)}) {
		t.Fatal(losses, published, err)
	}
	if !reflect.DeepEqual(inspected, [][]string{{"event-0", "event-1"}, {"event-0", "event-1", "event-2"}}) {
		t.Fatal("the activation did not inspect the changed list", inspected)
	}
}

// The repair runs before the declaration, with the recorded outcomes the
// image lacks, then the image is inspected again.
func TestActivationRepairsBeforeItDeclares(t *testing.T) {
	_, c, _, r := restored(t)
	image := map[string]bool{}
	inspect := func(recorded []restoreauthority.Outcome) ([]string, error) {
		missing := []string{}
		for _, o := range recorded {
			if !image[o.ID] {
				missing = append(missing, o.ID)
			}
		}
		return missing, nil
	}
	repair := func(missing []restoreauthority.Outcome) error {
		if len(missing) != 1 || missing[0].ID != "event-0" || missing[0].Digest != digest("first") {
			t.Error("the repair got", missing)
		}
		image["event-0"] = true // a newer archive held it
		return nil
	}
	losses, err := c.ActivateRestored(t.Context(), r, restoreauthority.Activation{Inspect: inspect, Repair: repair,
		Publish: func(context.Context) error { return nil }})
	if err != nil || len(losses) != 0 {
		t.Fatal("a repaired image declared losses", losses, err)
	}
	if status, _, err := c.OutcomeStatus(t.Context(), "event-0"); err != nil || status != restoreauthority.StatusConfirmed {
		t.Fatal(status, err)
	}
}
