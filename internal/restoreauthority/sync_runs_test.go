//go:build linux && cgo

package restoreauthority

import (
	"errors"
	"reflect"
	"testing"
)

// syncOutcomeIsDeclaredOneByOneTest (spec/restore_authority_test.qnt,
// module restoreAuthorityReplicaTests), the counterpart of
// TestDegradedOutcomeIsLostWithThePrimary: in sync mode the outcome is on the
// replica, so the promoted authority knows it. A restored image that lacks it
// cannot activate until its loss is declared, one outcome at a time, for the
// new incarnation; no time window is announced.
func TestSyncOutcomeIsDeclaredOneByOne(t *testing.T) {
	p := replicated(t)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	// applied.then(recordOutcome(0)).then(failover).
	if err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: "event-0", Digest: digest("job")}); err != nil {
		t.Fatal(err)
	}
	_, promoted := promote(t, p)
	if status, _, err := promoted.OutcomeStatus(ctx, "event-0"); err != nil || status != StatusConfirmed {
		t.Fatal("the failover lost a replicated outcome", status, err)
	}
	// restoreImage(1), reconcile(1): the image lacks event-0.
	restored, err := promoted.ReserveIncarnation(ctx, b, "restore-after-failover")
	if err != nil {
		t.Fatal(err)
	}
	r := receipt(t, promoted, restored)
	missing := func(recorded []Outcome) ([]string, error) {
		var ids []string
		for _, o := range recorded {
			ids = append(ids, o.ID)
		}
		return ids, nil
	}
	// expect not(canActivate(root, s, 1)).
	if err = promoted.WithActivation(ctx, r, missing, func() error { t.Fatal("published with an undeclared loss"); return nil }); !errors.Is(err, ErrHistory) {
		t.Fatal("activated with an undeclared loss", err)
	}
	// declareLoss(1), activate(1).
	ready := false
	losses, err := promoted.Activate(ctx, r, Restoration{Inspect: missing, Publish: func() error { ready = true; return nil }})
	want := []Loss{{ID: "event-0", Store: b.Store, Incarnation: restored.Incarnation}}
	if err != nil || !ready || !reflect.DeepEqual(losses, want) {
		t.Fatal("the loss was not declared for the new incarnation", losses, err)
	}
	// expect root.lost == Set(lossAt(0, 2)) and outcomeStatus == LostRescheduled.
	status, declared, err := promoted.OutcomeStatus(ctx, "event-0")
	if err != nil || status != StatusLost || !reflect.DeepEqual(declared, want) {
		t.Fatal("the declared loss is not the outcome's status", status, declared, err)
	}
	if restored.Incarnation != b.Incarnation+1 {
		t.Fatal("the restore did not take the next incarnation", restored.Incarnation, b.Incarnation)
	}
}
