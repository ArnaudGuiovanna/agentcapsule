//go:build linux && cgo

package restoreauthority

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"
)

// These tests project the runs of spec/restore_authority_test.qnt for D-03
// option B onto the catalogue. Each one names its Quint run. They are written
// by hand from the runs: no Go test reads the model's traces. The model's
// store 1 is "store-a" and its event 0 is "event-0". An image is simulated: it
// maps an outcome ID to the digest of the result it holds. Real application
// data is inspected in TestActivationRequiresActualRecoveredData.

type image map[string][32]byte

func (m image) clone() image { return maps.Clone(m) }

func digest(result string) [32]byte { return sha256.Sum256([]byte(result)) }

// lab is one store with its live image, as in the model's runs.
type lab struct {
	t    *testing.T
	c    *Catalog
	b    Binding
	disk image
}

func newLab(t *testing.T) *lab {
	c, b := fixture(t)
	return &lab{t: t, c: c, b: b, disk: image{}}
}

// inspect reports the recorded outcomes that the current image lacks, or
// holds with another result.
func (l *lab) inspect(recorded []Outcome) ([]string, error) {
	missing := []string{}
	for _, o := range recorded {
		if d, ok := l.disk[o.ID]; !ok || d != o.Digest {
			missing = append(missing, o.ID)
		}
	}
	return missing, nil
}

// acknowledge is applied then recordOutcome in the model.
func (l *lab) acknowledge(id, result string) {
	l.t.Helper()
	l.disk[id] = digest(result)
	if err := l.c.RecordOutcome(l.t.Context(), l.b, Outcome{ID: id, Digest: digest(result)}); err != nil {
		l.t.Fatal(err)
	}
}

// restore is restoreImage then reconcile: a new incarnation holds a copy of
// backup, and its fences are current.
func (l *lab) restore(backup image) Receipt {
	l.t.Helper()
	next, err := l.c.ReserveIncarnation(l.t.Context(), l.b, fmt.Sprintf("restore-%d", l.b.Incarnation))
	if err != nil {
		l.t.Fatal(err)
	}
	l.b, l.disk = next, backup.clone()
	return receipt(l.t, l.c, next)
}

// activate is the restore path when no archive is available.
func (l *lab) activate(r Receipt) []Loss {
	l.t.Helper()
	ready := false
	losses, err := l.c.Activate(l.t.Context(), r, Restoration{Inspect: l.inspect, Publish: func() error { ready = true; return nil }})
	if err != nil || !ready {
		l.t.Fatal("activation", err)
	}
	return losses
}

// rerun runs the job again in the current image, then records it through the
// delivery path, which is RecordOutcome.
func (l *lab) rerun(id, result string) error {
	l.disk[id] = digest(result)
	return l.c.RecordOutcome(l.t.Context(), l.b, Outcome{ID: id, Digest: digest(result)})
}

func (l *lab) status(id string) Status {
	l.t.Helper()
	s, _, err := l.c.OutcomeStatus(l.t.Context(), id)
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}

func (l *lab) losses() []Loss {
	l.t.Helper()
	losses, err := l.c.Losses(l.t.Context(), "store-a")
	if err != nil {
		l.t.Fatal(err)
	}
	return losses
}

func (l *lab) neverPublish() error {
	l.t.Error("published")
	return nil
}

// restoredWithoutOutcome in the model: the image predates the acknowledgment
// and no archive holds the outcome.
func restoredWithoutOutcome(t *testing.T) (*lab, Receipt) {
	l := newLab(t)
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	return l, l.restore(backup)
}

func lostAt(incarnation uint64) Loss {
	return Loss{ID: "event-0", Store: "store-a", Incarnation: incarnation}
}

func rerunAt(incarnation uint64, result string) Loss {
	l := lostAt(incarnation)
	l.Rerun, l.RerunDigest = true, digest(result)
	return l
}

// undeclaredLossPreventsActivationTest
func TestUndeclaredLossPreventsActivation(t *testing.T) {
	l, r := restoredWithoutOutcome(t)
	if s := l.status("event-0"); s != StatusConfirmed {
		t.Fatal(s)
	}
	if err := l.c.WithActivation(t.Context(), r, l.inspect, l.neverPublish); !errors.Is(err, ErrHistory) {
		t.Fatal("activated with an undeclared loss", err)
	}
}

// declaredLossAllowsActivationTest
func TestDeclaredLossAllowsActivation(t *testing.T) {
	l, r := restoredWithoutOutcome(t)
	losses, err := l.c.declareLosses(t.Context(), r, l.inspect)
	if err != nil || !reflect.DeepEqual(losses, []Loss{lostAt(2)}) {
		t.Fatal(losses, err)
	}
	if s := l.status("event-0"); s != StatusLost {
		t.Fatal(s)
	}
	ready := false
	if err = l.c.WithActivation(t.Context(), r, l.inspect, func() error { ready = true; return nil }); err != nil || !ready {
		t.Fatal(err)
	}
	if _, ok := l.disk["event-0"]; ok {
		t.Fatal("the image gained the outcome")
	}
}

// declaredLossBreaksFormerGuaranteeTest: a negative witness.
func TestDeclaredLossBreaksFormerGuarantee(t *testing.T) {
	l, r := restoredWithoutOutcome(t)
	losses := l.activate(r)
	// noLostAcknowledgedOutcome fails: the active image lacks an acknowledged outcome.
	if _, ok := l.disk["event-0"]; ok {
		t.Fatal("the image holds the outcome")
	}
	// noUndeclaredLoss holds: its loss is declared for this very incarnation.
	if !reflect.DeepEqual(losses, []Loss{lostAt(l.b.Incarnation)}) {
		t.Fatal(losses)
	}
}

// declaredLossIsRerunOnceTest
func TestDeclaredLossIsRerunOnce(t *testing.T) {
	l, r := restoredWithoutOutcome(t)
	l.activate(r)
	// The delivery path records the rerun: RecordOutcome sees the declared loss.
	if err := l.rerun("event-0", "second"); err != nil {
		t.Fatal(err)
	}
	status, losses, err := l.c.OutcomeStatus(t.Context(), "event-0")
	want := []Loss{rerunAt(2, "second")}
	if err != nil || status != StatusRerunConfirmed || !reflect.DeepEqual(losses, want) {
		t.Fatal(status, losses, err)
	}
	// A duplicate delivery returns the same result: a no-op. Another result is refused.
	for _, record := range []func(Binding, Outcome) error{
		func(b Binding, o Outcome) error { return l.c.RecordRerun(t.Context(), b, o) },
		func(b Binding, o Outcome) error { return l.c.RecordOutcome(t.Context(), b, o) },
	} {
		if err = record(l.b, Outcome{ID: "event-0", Digest: digest("second")}); err != nil {
			t.Fatal("retry of the same rerun", err)
		}
		if err = record(l.b, Outcome{ID: "event-0", Digest: digest("third")}); !errors.Is(err, ErrConflict) {
			t.Fatal("second rerun recorded", err)
		}
	}
	if got := l.losses(); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

// rerunNeedsDeclaredLossTest
func TestRerunNeedsDeclaredLoss(t *testing.T) {
	l := newLab(t)
	l.acknowledge("event-0", "first")
	if s := l.status("event-0"); s != StatusConfirmed {
		t.Fatal(s)
	}
	if err := l.c.RecordRerun(t.Context(), l.b, Outcome{ID: "event-0", Digest: digest("second")}); !errors.Is(err, ErrNotDeclared) {
		t.Fatal("rerun without a declared loss", err)
	}
	// Without a declared loss, the delivery path keeps the first result.
	if err := l.c.RecordOutcome(t.Context(), l.b, Outcome{ID: "event-0", Digest: digest("second")}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if got := l.losses(); len(got) != 0 {
		t.Fatal(got)
	}
}

// noDeclarationWithoutLossTest, and lossesNameAcknowledgedWork.
func TestNoDeclarationWithoutLoss(t *testing.T) {
	l := newLab(t)
	l.acknowledge("event-0", "first")
	r := l.restore(l.disk.clone())
	losses, err := l.c.declareLosses(t.Context(), r, l.inspect)
	if err != nil || len(losses) != 0 {
		t.Fatal("declared without a loss", losses, err)
	}
	unrecorded := func([]Outcome) ([]string, error) { return []string{"never-recorded"}, nil }
	if _, err = l.c.declareLosses(t.Context(), r, unrecorded); !errors.Is(err, ErrInput) {
		t.Fatal("declared an outcome never recorded", err)
	}
	if got := l.losses(); len(got) != 0 {
		t.Fatal(got)
	}
	ready := false
	if err = l.c.WithActivation(t.Context(), r, l.inspect, func() error { ready = true; return nil }); err != nil || !ready {
		t.Fatal(err)
	}
}

// repairComesBeforeDeclarationTest
func TestRepairComesBeforeDeclaration(t *testing.T) {
	l := newLab(t)
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	archive := l.disk.clone()
	r := l.restore(backup)
	failed := errors.New("archive read failed")
	if _, err := l.c.Activate(t.Context(), r, Restoration{Inspect: l.inspect, Publish: l.neverPublish,
		Repair: func([]Outcome) error { return failed }}); !errors.Is(err, failed) {
		t.Fatal("a failed repair did not abort", err)
	}
	repaired, ready := false, false
	repair := func(missing []Outcome) error {
		// It runs outside the catalogue transaction, before any declaration.
		if got, err := l.c.Losses(t.Context(), "store-a"); err != nil || len(got) != 0 {
			t.Error("declared before the repair", got, err)
		}
		if len(missing) != 1 || missing[0] != (Outcome{ID: "event-0", Digest: digest("first")}) {
			t.Error(missing)
		}
		for _, o := range missing {
			if d, ok := archive[o.ID]; ok {
				l.disk[o.ID] = d
			}
		}
		repaired = true
		return nil
	}
	losses, err := l.c.Activate(t.Context(), r, Restoration{Inspect: l.inspect, Repair: repair, Publish: func() error { ready = true; return nil }})
	if err != nil || !repaired || !ready || len(losses) != 0 {
		t.Fatal(losses, err)
	}
	if got := l.losses(); len(got) != 0 {
		t.Fatal(got)
	}
	if s := l.status("event-0"); s != StatusConfirmed {
		t.Fatal(s)
	}
}

// lostArchiveLeadsToDeclaredLossTest, and unavailableArchivePreventsRepairTest.
func TestLostArchiveLeadsToDeclaredLoss(t *testing.T) {
	l := newLab(t)
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	archive := l.disk.clone()
	r := l.restore(backup)
	archive = nil // loseArchive
	ready := false
	repair := func(missing []Outcome) error {
		for _, o := range missing {
			if d, ok := archive[o.ID]; ok {
				l.disk[o.ID] = d
			}
		}
		return nil
	}
	losses, err := l.c.Activate(t.Context(), r, Restoration{Inspect: l.inspect, Repair: repair, Publish: func() error { ready = true; return nil }})
	if err != nil || !ready || !reflect.DeepEqual(losses, []Loss{lostAt(2)}) {
		t.Fatal(losses, err)
	}
	if s := l.status("event-0"); s != StatusLost {
		t.Fatal(s)
	}
}

// declaredLossSurvivesControlBackupRestoreTest
func TestDeclaredLossSurvivesControlBackupRestore(t *testing.T) {
	l, r := restoredWithoutOutcome(t)
	other, err := l.c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	l.activate(r)
	// Another store is restored, then a new process opens the authority.
	next, err := l.c.ReserveIncarnation(t.Context(), other, "restore-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.c.Activate(t.Context(), receipt(t, l.c, next), Restoration{Inspect: nothingMissing, Publish: func() error { return nil }}); err != nil {
		t.Fatal(err)
	}
	status, losses, err := reopen(t, l.c).OutcomeStatus(t.Context(), "event-0")
	if err != nil || status != StatusLost || !reflect.DeepEqual(losses, []Loss{lostAt(2)}) {
		t.Fatal(status, losses, err)
	}
}

// oldImageDoesNotReviveOffboardedJobTest. The model's store 0 is "store-b",
// whose subject "agent/b" owns event-0.
func TestOldImageDoesNotReviveOffboardedJob(t *testing.T) {
	l := newLab(t)
	sealed, err := l.c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	if _, err = l.c.BeginRevocation(t.Context(), "agent/b"); err != nil {
		t.Fatal(err)
	}
	if err = l.c.RecordRetiredSeal(t.Context(), sealed); err != nil {
		t.Fatal(err)
	}
	r := l.restore(backup)
	if !slices.Contains(r.Subjects, "agent/b") {
		t.Fatal("the old image is not fenced", r.Subjects)
	}
	if losses := l.activate(r); !reflect.DeepEqual(losses, []Loss{lostAt(2)}) {
		t.Fatal(losses)
	}
	if s := l.status("event-0"); s != StatusLost {
		t.Fatal(s)
	}
	// Not due: the subject is revoked, so its job gets no key and does not run again.
	if err = l.c.WithSubjectKey(t.Context(), "agent/b", func() error { t.Error("revoked job got a key"); return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if _, err = l.c.ReserveIncarnation(t.Context(), sealed, "revive"); !errors.Is(err, ErrSealed) {
		t.Fatal("the sealed store was revived", err)
	}
}

// freshBackupKeepsAcknowledgedOutcomeTest
func TestFreshBackupKeepsAcknowledgedOutcome(t *testing.T) {
	l := newLab(t)
	l.acknowledge("event-0", "first")
	if losses := l.activate(l.restore(l.disk.clone())); len(losses) != 0 {
		t.Fatal(losses)
	}
	if s := l.status("event-0"); s != StatusConfirmed || l.disk["event-0"] != digest("first") {
		t.Fatal(s)
	}
}

// unacknowledgedOutcomeCanBeRecomputedTest
func TestUnacknowledgedOutcomeCanBeRecomputed(t *testing.T) {
	l := newLab(t)
	backup := l.disk.clone()
	l.disk["event-0"] = digest("first") // applied, never recorded
	if losses := l.activate(l.restore(backup)); len(losses) != 0 {
		t.Fatal(losses)
	}
	if s := l.status("event-0"); s != StatusUnrecorded {
		t.Fatal(s)
	}
	// Its work runs again as an ordinary first outcome.
	l.acknowledge("event-0", "second")
	if s := l.status("event-0"); s != StatusConfirmed {
		t.Fatal(s)
	}
}

// oldImageReconcilesRevocationsAndOutcomesTest
func TestOldImageReconcilesRevocationsAndOutcomes(t *testing.T) {
	l := newLab(t)
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	archive := l.disk.clone()
	if _, err := l.c.BeginRevocation(t.Context(), "agent/b"); err != nil {
		t.Fatal(err)
	}
	r := l.restore(backup)
	repair := func(missing []Outcome) error {
		for _, o := range missing {
			l.disk[o.ID] = archive[o.ID]
		}
		return nil
	}
	losses, err := l.c.Activate(t.Context(), r, Restoration{Inspect: l.inspect, Repair: repair, Publish: func() error { return nil }})
	if err != nil || len(losses) != 0 || l.b.Incarnation != 2 || l.disk["event-0"] != digest("first") {
		t.Fatal(losses, err)
	}
	if !slices.Contains(r.Subjects, "agent/b") {
		t.Fatal("the old image is not fenced", r.Subjects)
	}
}

// lostAndRerun in the model: lost under incarnation 2, then rerun. It returns
// the old backup, which still lacks the outcome.
func lostAndRerun(t *testing.T) (*lab, image) {
	t.Helper()
	l := newLab(t)
	backup := l.disk.clone()
	l.acknowledge("event-0", "first")
	l.activate(l.restore(backup))
	if err := l.rerun("event-0", "second"); err != nil {
		t.Fatal(err)
	}
	return l, backup
}

// earlierDeclarationDoesNotCoverLaterLossTest
func TestEarlierDeclarationDoesNotCoverLaterLoss(t *testing.T) {
	l, backup := lostAndRerun(t)
	r := l.restore(backup)
	if got := l.losses(); l.b.Incarnation != 3 || !reflect.DeepEqual(got, []Loss{rerunAt(2, "second")}) {
		t.Fatal(got)
	}
	if err := l.c.WithActivation(t.Context(), r, l.inspect, l.neverPublish); !errors.Is(err, ErrHistory) {
		t.Fatal("an earlier declaration covered a later loss", err)
	}
	if err := l.c.RecordRerun(t.Context(), l.b, Outcome{ID: "event-0", Digest: digest("third")}); !errors.Is(err, ErrNotDeclared) {
		t.Fatal("an earlier declaration allowed a later rerun", err)
	}
}

// eachRestoreDeclaresItsOwnLossTest
func TestEachRestoreDeclaresItsOwnLoss(t *testing.T) {
	l, backup := lostAndRerun(t)
	if losses := l.activate(l.restore(backup)); !reflect.DeepEqual(losses, []Loss{lostAt(3)}) {
		t.Fatal(losses)
	}
	if got := l.losses(); !reflect.DeepEqual(got, []Loss{rerunAt(2, "second"), lostAt(3)}) {
		t.Fatal(got)
	}
	if s := l.status("event-0"); s != StatusLost {
		t.Fatal(s)
	}
	if err := l.rerun("event-0", "third"); err != nil {
		t.Fatal(err)
	}
	if s := l.status("event-0"); s != StatusRerunConfirmed {
		t.Fatal(s)
	}
}

// backupAfterRerunNeedsNoDeclarationTest
func TestBackupAfterRerunNeedsNoDeclaration(t *testing.T) {
	l, _ := lostAndRerun(t)
	r := l.restore(l.disk.clone())
	// The inspection compares with the rerun's result, the current one.
	ready := false
	if err := l.c.WithActivation(t.Context(), r, l.inspect, func() error { ready = true; return nil }); err != nil || !ready {
		t.Fatal(err)
	}
	if got := l.losses(); !reflect.DeepEqual(got, []Loss{rerunAt(2, "second")}) {
		t.Fatal(got)
	}
	if s := l.status("event-0"); s != StatusConfirmed {
		t.Fatal(s)
	}
	// A duplicate delivery returns the rerun's result; the first one is obsolete.
	if err := l.c.RecordOutcome(t.Context(), l.b, Outcome{ID: "event-0", Digest: digest("second")}); err != nil {
		t.Fatal(err)
	}
	if err := l.c.RecordOutcome(t.Context(), l.b, Outcome{ID: "event-0", Digest: digest("first")}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

// forgottenLossTest and declaredLossesSurvive: the catalogue refuses to
// withdraw a declared loss or its rerun. Restoring the catalogue itself from a
// backup is not detected here: it must stay outside the restored domain (D-05).
func TestDeclaredLossIsNeverWithdrawn(t *testing.T) {
	l, backup := lostAndRerun(t)
	l.activate(l.restore(backup)) // a second loss, without a rerun
	want := []Loss{rerunAt(2, "second"), lostAt(3)}
	for _, statement := range []string{"DELETE FROM losses WHERE incarnation=3", "UPDATE losses SET incarnation=9 WHERE incarnation=3",
		"DELETE FROM reruns", "UPDATE reruns SET digest=zeroblob(32)", "DELETE FROM outcomes"} {
		if _, err := l.c.db.Exec(statement); err == nil {
			t.Error("withdrawn:", statement)
		}
	}
	if losses, err := reopen(t, l.c).Losses(t.Context(), "store-a"); err != nil || !reflect.DeepEqual(losses, want) {
		t.Fatal(losses, err)
	}
}

// A catalogue created by an older release (schema version 1) keeps working
// and keeps the old guarantee. Loss operations fail closed until Initialize
// upgrades it in place.
func TestVersionOneCatalogueUpgradesOnInitialize(t *testing.T) {
	c, b := fixture(t)
	if err := c.RecordOutcome(t.Context(), b, Outcome{ID: "event-0", Digest: digest("first")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec("DROP TABLE replication_log; DROP TABLE replication; DROP TABLE reruns; DROP TABLE losses; DROP INDEX outcomes_by_identity; PRAGMA user_version=0"); err != nil {
		t.Fatal(err)
	}
	old := reopen(t, c)
	if err := old.RecordOutcome(t.Context(), b, Outcome{ID: "event-0", Digest: digest("first")}); err != nil {
		t.Fatal(err)
	}
	next, err := old.ReserveIncarnation(t.Context(), b, "restore")
	if err != nil {
		t.Fatal(err)
	}
	r := receipt(t, old, next)
	never := func() error { t.Error("published"); return nil }
	if err = old.WithActivation(t.Context(), r, everythingMissing, never); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error {
			_, err := old.Activate(t.Context(), r, Restoration{Inspect: everythingMissing, Publish: never})
			return err
		},
		func() error { _, err := old.Losses(t.Context(), b.Store); return err },
		func() error { _, _, err := old.OutcomeStatus(t.Context(), "event-0"); return err },
		func() error {
			return old.RecordRerun(t.Context(), next, Outcome{ID: "event-0", Digest: digest("second")})
		},
	} {
		if err = operation(); !errors.Is(err, ErrUnavailable) {
			t.Fatal("loss operation on a version 1 catalogue", err)
		}
	}
	upgraded, err := Initialize(t.Context(), c.root, testKeyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if upgraded.Identity() != c.identity {
		t.Fatal("the upgrade replaced the identity")
	}
	// A catalogue already open sees the new version.
	ready := false
	losses, err := old.Activate(t.Context(), r, Restoration{Inspect: everythingMissing, Publish: func() error { ready = true; return nil }})
	if err != nil || !ready || len(losses) != 1 || losses[0].ID != "event-0" {
		t.Fatal(losses, err)
	}
	if _, err = c.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Lookup(t.Context(), b.Store); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown schema version accepted", err)
	}
	if newer, err := Open(t.Context(), c.root, c.identity, testKeyIdentity); !errors.Is(err, ErrUnavailable) {
		if newer != nil {
			newer.Close()
		}
		t.Fatal("unknown schema version opened", err)
	}
}
