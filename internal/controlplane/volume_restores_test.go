package controlplane

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func restoreID(n int) string { return fmt.Sprintf("rst_%032x", n) }

func enrollmentState(t *testing.T, s *Store, agentID string) (string, uint64) {
	t.Helper()
	var stage string
	var incarnation int64
	if err := s.pool.QueryRow(t.Context(), "SELECT stage,incarnation FROM store_enrollments WHERE agent_id=$1", agentID).Scan(&stage, &incarnation); err != nil {
		t.Fatal(err)
	}
	return stage, uint64(incarnation)
}

// restrictedRestoreBoot stands for the worker's restricted boot of the
// installed image: a fence-only claim, its boot plan and its initialization.
// No VM runs here.
func restrictedRestoreBoot(t *testing.T, s *Store, e Enrollment) Placement {
	t.Helper()
	p, err := s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "restorer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p.VMID = fmt.Sprintf("%016x", p.Generation)
	plan, err := s.PrepareVolumeBoot(t.Context(), VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}, "restorer")
	if err != nil || !plan.Restore || plan.Initialize || !plan.AcknowledgeInitialization || plan.Enrollment.Incarnation < 2 {
		t.Fatal("restricted boot plan of a restored image", plan, err)
	}
	if err = s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "restorer", p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentInitialized(t.Context(), EnrollmentBoot{Incarnation: plan.Enrollment.Incarnation, AgentID: e.AgentID, VolumeID: e.VolumeID,
		HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}); err != nil {
		t.Fatal(err)
	}
	return p
}

// The incarnation of a store enrollment changes only through a restore: one
// step up, to the incarnation that an unfinished restore reserved, as the
// volume leaves READY. A restoring volume is READY again only once its
// restore is activated. The rest of the guard stands, and a restore's row
// only moves forward.
func TestRestoreIsTheOnlyChangeOfIncarnation(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	refused := func(name, query string, args ...any) {
		t.Helper()
		if _, err := s.pool.Exec(t.Context(), query, args...); err == nil {
			t.Fatal("guard accepted", name)
		}
	}
	refused("incarnation alone", "UPDATE store_enrollments SET incarnation=2 WHERE agent_id=$1", e.AgentID)
	refused("restoring without a restore", "UPDATE store_enrollments SET stage='RESTORING',incarnation=2 WHERE agent_id=$1", e.AgentID)
	refused("ready to restoring", "UPDATE store_enrollments SET stage='RESTORING' WHERE agent_id=$1", e.AgentID)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO volume_restores(restore_id,agent_id,host_id,volume_id,archive_id,from_incarnation,incarnation)
        VALUES($1,$2,'local',$3,$4,1,2)`, restoreID(1), e.AgentID, e.VolumeID, archiveID(1)); err != nil {
		t.Fatal(err)
	}
	refused("skipped incarnation", "UPDATE store_enrollments SET stage='RESTORING',incarnation=3 WHERE agent_id=$1", e.AgentID)
	refused("ready at a new incarnation", "UPDATE store_enrollments SET incarnation=2 WHERE agent_id=$1", e.AgentID)
	refused("another volume", "UPDATE store_enrollments SET stage='RESTORING',incarnation=2,volume_id='vol_'||repeat('9',32) WHERE agent_id=$1", e.AgentID)
	refused("device", "UPDATE store_enrollments SET stage='RESTORING',incarnation=2,volume_inode='0000000000000999' WHERE agent_id=$1", e.AgentID)
	if _, err := s.pool.Exec(t.Context(), "UPDATE store_enrollments SET stage='RESTORING',incarnation=2 WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal("the restore's incarnation refused", err)
	}
	refused("back to the old incarnation", "UPDATE store_enrollments SET incarnation=1 WHERE agent_id=$1", e.AgentID)
	refused("ready before activation", "UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1", e.AgentID)
	refused("second step from a reserved row", "UPDATE store_enrollments SET incarnation=3 WHERE agent_id=$1", e.AgentID)
	for _, step := range []string{RestoreInstalling, RestoreReconciling} {
		if _, err := s.pool.Exec(t.Context(), "UPDATE volume_restores SET step=$2 WHERE restore_id=$1", restoreID(1), step); err != nil {
			t.Fatal(err)
		}
	}
	refused("step backwards", "UPDATE volume_restores SET step='DRAINING' WHERE restore_id=$1", restoreID(1))
	refused("activated without a time", "UPDATE volume_restores SET step='ACTIVATED' WHERE restore_id=$1", restoreID(1))
	refused("another archive", "UPDATE volume_restores SET archive_id=$2 WHERE restore_id=$1", restoreID(1), archiveID(2))
	refused("deleted", "DELETE FROM volume_restores WHERE restore_id=$1", restoreID(1))
	refused("ready while reconciling", "UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1", e.AgentID)
	if _, err := s.pool.Exec(t.Context(), "UPDATE volume_restores SET step='ACTIVATED',activated_at=clock_timestamp() WHERE restore_id=$1", restoreID(1)); err != nil {
		t.Fatal(err)
	}
	refused("installing again", "UPDATE store_enrollments SET stage='INSTALLING' WHERE agent_id=$1", e.AgentID)
	if _, err := s.pool.Exec(t.Context(), "UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal("an activated restore cannot end", err)
	}
	if stage, incarnation := enrollmentState(t, s, e.AgentID); stage != "READY" || incarnation != 2 {
		t.Fatal("enrollment after the restore", stage, incarnation)
	}
	refused("an old restore row reused", "UPDATE store_enrollments SET stage='RESTORING',incarnation=3 WHERE agent_id=$1", e.AgentID)
}

// The restore operation, step by step: the volume leaves service as the
// restore is recorded, only an installed image boots and only restricted,
// activation needs that boot, and the losses are copied in the transaction
// that makes the volume READY again. Each loss is mapped to its delivery,
// or recorded as unmatched. Every step can be repeated.
func TestVolumeRestoreOperationAndLossMapping(t *testing.T) {
	s, c, _, _, owner, e := instructionLab(t)
	first, firstOp := queueInstruction(t, c, owner, e.AgentID, "lost-one")
	second, _ := queueInstruction(t, c, owner, e.AgentID, "kept-one")
	host := e.HostID
	if _, err := s.BeginVolumeRestore(t.Context(), "rst_bad", e.AgentID, host, archiveID(1)); !errors.Is(err, ErrInput) {
		t.Fatal("invalid restore ID", err)
	}
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "other-host", archiveID(1)); !errors.Is(err, ErrPlacement) {
		t.Fatal("restore on another host", err)
	}
	plan, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(1))
	if err != nil {
		t.Fatal(err)
	}
	r := plan.Restore
	if r.Step != RestoreDraining || r.FromIncarnation != 1 || r.Incarnation != 2 || plan.Enrollment.Stage != "RESTORING" || plan.Enrollment.Incarnation != 2 ||
		plan.Inode != 100 || r.VolumeID != e.VolumeID || r.ArchiveID != archiveID(1) {
		t.Fatal("begun restore", plan)
	}
	if again, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(1)); err != nil || again.Restore != r {
		t.Fatal("a repeated begin is not the same restore", again, err)
	}
	if _, err = s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(2)); !errors.Is(err, ErrConflict) {
		t.Fatal("the restore ID reused for another archive", err)
	}
	// Out of service: no ordinary boot, and no boot at all before the install.
	if _, err = s.ClaimPlacement(t.Context(), e.AgentID, host, "worker", time.Minute); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("ordinary boot of a restoring volume", err)
	}
	p, err := s.ClaimFencePlacement(t.Context(), e.AgentID, host, "restorer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareVolumeBoot(t.Context(), VMCaller{AgentID: e.AgentID, HostID: host, Generation: p.Generation, VMID: "x"}, "restorer"); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("boot of a volume not yet installed", err)
	}
	if err = s.AdvanceVolumeRestore(t.Context(), r.ID, host, RestoreDraining, RestoreInstalling); !errors.Is(err, ErrRestore) {
		t.Fatal("advanced while a boot is claimed", err)
	}
	retireEnrollmentBoot(t, s, p)
	if err = s.AdvanceVolumeRestore(t.Context(), r.ID, host, RestoreInstalling, RestoreReconciling); !errors.Is(err, ErrRestore) {
		t.Fatal("skipped the retirement", err)
	}
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err = s.AdvanceVolumeRestore(t.Context(), r.ID, host, step[0], step[1]); err != nil {
			t.Fatal(step, err)
		}
	}
	boot := restrictedRestoreBoot(t, s, e)
	if _, err = s.ClaimPlacement(t.Context(), e.AgentID, host, "worker", time.Minute); !errors.Is(err, ErrPlacementBusy) && !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("ordinary boot beside the restricted one", err)
	}
	if err = s.ActivateVolumeRestore(t.Context(), r.ID, host, boot.Generation+1, boot.VMID); !errors.Is(err, ErrPlacement) {
		t.Fatal("activated without the inspected boot", err)
	}
	if _, err = s.CompleteVolumeRestore(t.Context(), r.ID, host, nil); !errors.Is(err, ErrRestore) {
		t.Fatal("completed before activation", err)
	}
	for range 2 {
		if err = s.ActivateVolumeRestore(t.Context(), r.ID, host, boot.Generation, boot.VMID); err != nil {
			t.Fatal(err)
		}
	}
	if stage, _ := enrollmentState(t, s, e.AgentID); stage != "RESTORING" {
		t.Fatal("activation alone put the volume in service", stage)
	}
	if _, err = s.CompleteVolumeRestore(t.Context(), r.ID, host, nil); !errors.Is(err, ErrRestore) {
		t.Fatal("completed while the restricted boot runs", err)
	}
	retireEnrollmentBoot(t, s, boot)
	lost, err := outcomeID(e.AgentID, first)
	if err != nil {
		t.Fatal(err)
	}
	unmatched, err := outcomeID(e.AgentID, "event-this-database-lost")
	if err != nil {
		t.Fatal(err)
	}
	losses, err := s.CompleteVolumeRestore(t.Context(), r.ID, host, []string{lost, unmatched})
	if err != nil || len(losses) != 2 {
		t.Fatal("losses", losses, err)
	}
	byOutcome := map[string]RestoreLoss{}
	for _, l := range losses {
		byOutcome[l.OutcomeID] = l
		if l.Incarnation != 2 || l.DeclaredAt.IsZero() {
			t.Fatal("loss incarnation or time", l)
		}
	}
	if l := byOutcome[lost]; l.MailboxID != first || l.InvocationID != firstOp {
		t.Fatal("loss not mapped to its invocation", l)
	}
	if l := byOutcome[unmatched]; l.MailboxID != "" || l.InvocationID != "" {
		t.Fatal("unmatched loss mapped", l)
	}
	if kept, _ := outcomeID(e.AgentID, second); byOutcome[kept].OutcomeID != "" {
		t.Fatal("an outcome not declared lost was copied")
	}
	if stage, incarnation := enrollmentState(t, s, e.AgentID); stage != "READY" || incarnation != 2 {
		t.Fatal("volume after the restore", stage, incarnation)
	}
	again, err := s.CompleteVolumeRestore(t.Context(), r.ID, host, []string{unmatched})
	if err != nil || len(again) != 2 {
		t.Fatal("a repeated completion changed the losses", again, err)
	}
	for name, query := range map[string]string{"deleted": "DELETE FROM volume_restore_losses", "changed": "UPDATE volume_restore_losses SET mailbox_id=NULL"} {
		if _, err = s.pool.Exec(t.Context(), query); err == nil {
			t.Fatal("a copied loss was", name)
		}
	}
	if plan, err = s.BeginVolumeRestore(t.Context(), r.ID, e.AgentID, host, archiveID(1)); err != nil || plan.Restore.Step != RestoreSucceeded || plan.Restore.CompletedAt == nil {
		t.Fatal("a finished restore replayed", plan.Restore, err)
	}
	if open, err := s.OpenVolumeRestore(t.Context(), e.AgentID); err != nil || open != nil {
		t.Fatal("a finished restore is still open", open, err)
	}
	// The agent serves again, at its new incarnation.
	run, err := s.ClaimPlacement(t.Context(), e.AgentID, host, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := s.PrepareVolumeBoot(t.Context(), VMCaller{AgentID: e.AgentID, HostID: host, Generation: run.Generation, VMID: "y"}, "worker")
	if err != nil || ordinary.Restore || ordinary.Enrollment.Incarnation != 2 {
		t.Fatal("ordinary boot after the restore", ordinary, err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, host, "worker", run.Generation, "vm-after-restore"); err != nil {
		t.Fatal(err)
	}
	// A later restore starts from the new incarnation.
	if plan, err = s.BeginVolumeRestore(t.Context(), restoreID(2), e.AgentID, host, archiveID(3)); err != nil || plan.Restore.FromIncarnation != 2 || plan.Restore.Incarnation != 3 {
		t.Fatal("second restore", plan.Restore, err)
	}
	if err = s.ValidatePlacement(t.Context(), e.AgentID, host, run.Generation, "vm-after-restore"); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("the running VM of the old incarnation was adopted", err)
	}
}

// A new restore replaces an unfinished one that has not activated: one
// incarnation further, the old row SUPERSEDED. An activated restore is
// finished instead. A restore needs a LIVE agent.
func TestVolumeRestoreSupersedesOnlyBeforeActivation(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	host := e.HostID
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(1)); err != nil {
		t.Fatal(err)
	}
	plan, err := s.BeginVolumeRestore(t.Context(), restoreID(2), e.AgentID, host, archiveID(2))
	if err != nil || plan.Restore.FromIncarnation != 2 || plan.Restore.Incarnation != 3 {
		t.Fatal("superseding restore", plan.Restore, err)
	}
	old, err := s.VolumeRestoreTarget(t.Context(), restoreID(1), host)
	if err != nil || old.Restore.Step != RestoreSuperseded || old.Restore.CompletedAt == nil {
		t.Fatal("superseded restore", old.Restore, err)
	}
	if err = s.AdvanceVolumeRestore(t.Context(), restoreID(1), host, RestoreDraining, RestoreInstalling); !errors.Is(err, ErrRestore) {
		t.Fatal("a superseded restore advanced", err)
	}
	if open, err := s.OpenVolumeRestore(t.Context(), e.AgentID); err != nil || open == nil || open.ID != restoreID(2) {
		t.Fatal("open restore", open, err)
	}
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err = s.AdvanceVolumeRestore(t.Context(), restoreID(2), host, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	boot := restrictedRestoreBoot(t, s, e)
	if err = s.ActivateVolumeRestore(t.Context(), restoreID(2), host, boot.Generation, boot.VMID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BeginVolumeRestore(t.Context(), restoreID(3), e.AgentID, host, archiveID(3)); !errors.Is(err, ErrRestore) {
		t.Fatal("an activated restore was replaced", err)
	}
	if stage, incarnation := enrollmentState(t, s, e.AgentID); stage != "RESTORING" || incarnation != 3 {
		t.Fatal("enrollment", stage, incarnation)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE agents SET phase='QUIESCING' WHERE id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, boot)
	if _, err = s.CompleteVolumeRestore(t.Context(), restoreID(2), host, nil); err != nil {
		t.Fatal("a restore activated before a deletion request cannot end", err)
	}
	if _, err = s.BeginVolumeRestore(t.Context(), restoreID(4), e.AgentID, host, archiveID(4)); !errors.Is(err, ErrRestore) {
		t.Fatal("restore of an agent being deleted", err)
	}
}

// Taking the volume out of service and recording the restore commit
// together, and so do the copy of the losses and the return to READY: a
// failure leaves neither half.
func TestVolumeRestoreStepsAreAtomic(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	host := e.HostID
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION fail_restore() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected failure'; END $$;
        CREATE TRIGGER fail_enrollment BEFORE UPDATE ON store_enrollments FOR EACH ROW EXECUTE FUNCTION fail_restore()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(1)); err == nil {
		t.Fatal("injected failure ignored")
	}
	if open, err := s.OpenVolumeRestore(t.Context(), e.AgentID); err != nil || open != nil {
		t.Fatal("a restore recorded without leaving service", open, err)
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER fail_enrollment ON store_enrollments"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, host, archiveID(1)); err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err := s.AdvanceVolumeRestore(t.Context(), restoreID(1), host, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	boot := restrictedRestoreBoot(t, s, e)
	if err := s.ActivateVolumeRestore(t.Context(), restoreID(1), host, boot.Generation, boot.VMID); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, boot)
	if _, err := s.pool.Exec(t.Context(), "CREATE TRIGGER fail_loss BEFORE INSERT ON volume_restore_losses FOR EACH ROW EXECUTE FUNCTION fail_restore()"); err != nil {
		t.Fatal(err)
	}
	unmatched, err := outcomeID(e.AgentID, "lost-event")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompleteVolumeRestore(t.Context(), restoreID(1), host, []string{unmatched}); err == nil {
		t.Fatal("injected failure ignored")
	}
	if stage, _ := enrollmentState(t, s, e.AgentID); stage != "RESTORING" {
		t.Fatal("the volume served without its losses", stage)
	}
	if plan, err := s.VolumeRestoreTarget(t.Context(), restoreID(1), host); err != nil || plan.Restore.Step != RestoreActivated {
		t.Fatal("the restore moved without its losses", plan.Restore, err)
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER fail_loss ON volume_restore_losses"); err != nil {
		t.Fatal(err)
	}
	if losses, err := s.CompleteVolumeRestore(t.Context(), restoreID(1), host, []string{unmatched}); err != nil || len(losses) != 1 {
		t.Fatal("completion after the failure", losses, err)
	}
}

// The archives newer than a restored one are those PostgreSQL records as
// kept, published and captured later, for the same agent and host.
func TestNewerVolumeArchives(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	for n, row := range []string{"now()-interval '2 days'", "now()-interval '1 day'", "now()", "NULL"} {
		size := "4096"
		if row == "NULL" {
			size = "NULL"
		}
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,size)
            VALUES($1,$2,'local',$3,1,now()-interval '3 days',`+row+`,`+size+`)`, archiveID(n), e.AgentID, e.VolumeID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE volume_archives SET removed_at=now() WHERE archive_id=$1", archiveID(2)); err != nil {
		t.Fatal(err)
	}
	newer, err := s.NewerVolumeArchives(t.Context(), e.AgentID, "local", archiveID(0))
	if err != nil || len(newer) != 1 || newer[0] != archiveID(1) {
		t.Fatal("newer archives", newer, err)
	}
	for _, id := range []string{archiveID(1), archiveID(3), archiveID(9)} {
		if newer, err = s.NewerVolumeArchives(t.Context(), e.AgentID, "local", id); err != nil || len(newer) != 0 {
			t.Fatal("no newer archive expected", id, newer, err)
		}
	}
}
