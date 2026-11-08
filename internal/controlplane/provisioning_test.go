package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func reserveEnrollment(t *testing.T, s *Store, c *AgentCatalog, owner Principal, autoStart bool) Enrollment {
	t.Helper()
	in := catalogInput(owner.ID)
	in.AutoStart = autoStart
	if _, err := c.Reserve(t.Context(), owner, "provision", in); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.PendingProvisioning(t.Context(), "local", 20)
	if err != nil || len(jobs) != 1 || jobs[0].Stage != "INSTALLING" {
		t.Fatal("reservation not discoverable", jobs, err)
	}
	return jobs[0]
}

// These helpers stand for physical worker observations to exercise SQL commit
// boundaries. They do NOT test volume encryption, formatting or a real VM.
func observeTestVolume(t *testing.T, s *Store, e Enrollment) ProvisionedVolume {
	t.Helper()
	proof := ProvisionedVolume{AgentID: e.AgentID, OperationID: e.OperationID, VolumeID: e.VolumeID, HostID: e.HostID, Device: 1, Inode: 100}
	if err := s.RecordProvisionedVolume(t.Context(), proof); err != nil {
		t.Fatal(err)
	}
	return proof
}
func enrollmentBoot(t *testing.T, s *Store, e Enrollment) Placement {
	t.Helper()
	p := uninitializedEnrollmentBoot(t, s, e)
	if err := s.RecordEnrollmentInitialized(t.Context(), EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}); err != nil {
		t.Fatal(err)
	}
	return p
}

func uninitializedEnrollmentBoot(t *testing.T, s *Store, e Enrollment) Placement {
	t.Helper()
	p, err := s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
	if err != nil || !p.FenceOnly {
		t.Fatal("restricted claim", err)
	}
	p.VMID = fmt.Sprintf("%016x", p.Generation)
	if err = s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	return p
}
func retireEnrollmentBoot(t *testing.T, s *Store, p Placement) {
	t.Helper()
	if err := s.BeginPlacementStop(t.Context(), p.AgentID, p.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.ObservePlacementStopped(t.Context(), p.AgentID, p.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentHistoricalAndConcurrentRevocations(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRevocation(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}
	e := reserveEnrollment(t, s, c, owner, false)
	proof := observeTestVolume(t, s, e)
	if err := s.RecordProvisionedVolume(t.Context(), proof); err != nil {
		t.Fatal("lost registration ACK cannot be retried", err)
	}
	proof.Inode++
	if err := s.RecordProvisionedVolume(t.Context(), proof); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("replacement inode accepted", err)
	}
	if err := s.ActivateProvisionedAgent(t.Context(), e); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("filesystem readiness inferred from encrypted header", err)
	}
	if _, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uninitialized store gained ordinary authority", err)
	}
	p := enrollmentBoot(t, s, e)
	caller := VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}
	if err := s.ValidateVMCaller(t.Context(), caller); !errors.Is(err, ErrPlacement) {
		t.Fatal("restricted boot can issue platform work", err)
	}
	local, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	pending, err := s.EnrollmentPendingFences(t.Context(), e.AgentID, e.HostID, e.VolumeID)
	if err != nil || !slices.Equal(pending, []string{"agent/a"}) {
		t.Fatal("historical catalogue scan", pending, err)
	}
	ack := EnrollmentFence{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID, Subject: "agent/a"}
	if err = local.Fence(t.Context(), ack.Subject); err != nil {
		t.Fatal(err)
	}
	// A lost response is replayed against the durable local fence before ACK.
	if err = local.Fence(t.Context(), ack.Subject); err != nil {
		t.Fatal(err)
	}
	wrongIncarnation := ack
	wrongIncarnation.Incarnation++
	if err = s.RecordEnrollmentFence(t.Context(), wrongIncarnation); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("fence ACK rebound to a different storage incarnation", err)
	}
	if err = s.RecordEnrollmentFence(t.Context(), ack); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(t.Context(), e); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("restricted VM still running during activation", err)
	}
	retireEnrollmentBoot(t, s, p)
	if err = s.RecordEnrollmentFence(t.Context(), ack); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("old boot ACK accepted", err)
	}
	if err = s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRevocation(t.Context(), "b", m); err != nil {
		t.Fatal("unavailable provisioning store blocked existing deletion", err)
	}
	if err = s.ActivateProvisionedAgent(t.Context(), e); !errors.Is(err, ErrPendingFences) {
		t.Fatal("cached catalogue scan authorized activation", err)
	}
	p = enrollmentBoot(t, s, e)
	ack.Subject, ack.Generation, ack.VMID = "agent/b", p.Generation, p.VMID
	if err = local.Fence(t.Context(), ack.Subject); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentFence(t.Context(), ack); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, p)
	if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	view, err := c.Get(t.Context(), owner, e.AgentID)
	if err != nil || view.State != "STOPPED" {
		t.Fatal("activation state", view, err)
	}
	for _, subject := range []string{"agent/a", "agent/b"} {
		_, err := local.Apply(t.Context(), harnessstore.Event{ID: "late-" + subject, Subjects: []string{subject}}, localEffect)
		if !errors.Is(err, harnessstore.ErrFenced) {
			t.Fatal("new store accepts revoked work", subject, err)
		}
	}
	// A deletion starting AFTER activation must include the new store instead.
	if err = s.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	var included bool
	if err = s.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM deletion_targets WHERE agent_id='c' AND store_agent_id=$1)`, e.AgentID).Scan(&included); err != nil || !included {
		t.Fatal("activated store omitted from future census", err)
	}
}

func TestEnrollmentActivationWaitsForConcurrentIntentCommit(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(gate)
	if _, err = lockAgents(ctx, gate, "a"); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err = gate.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	deleted, activated := make(chan error, 1), make(chan error, 1)
	go func() { deleted <- s.RequestDeletion(ctx, "user-a", "a") }()
	waitUntil(t, func() bool {
		var held bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%FROM agents WHERE id = ANY%')`, pid).Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	})
	go func() { activated <- s.ActivateProvisionedAgent(ctx, e) }()
	waitUntil(t, func() bool {
		var held bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock(hashtextextended%')`, pid).Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	})
	if err = commit(ctx, gate); err != nil {
		t.Fatal(err)
	}
	if err = <-deleted; err != nil {
		t.Fatal("concurrent intent failed", err)
	}
	if err = <-activated; !errors.Is(err, ErrPendingFences) {
		t.Fatal("activation bypassed concurrent intent", err)
	}
	assertPhase(t, s, e.AgentID, "PROVISIONING")
}

func TestEnrollmentPublicationAtomicReplayAndAutoStart(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, true)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_activation_result() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.status='SUCCEEDED' THEN RAISE EXCEPTION 'injected publication failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_activation BEFORE UPDATE ON platform_operations FOR EACH ROW EXECUTE FUNCTION reject_activation_result()`); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateProvisionedAgent(t.Context(), e); err == nil {
		t.Fatal("publication failure ignored")
	}
	assertPhase(t, s, e.AgentID, "PROVISIONING")
	op, err := c.Operation(t.Context(), owner, e.OperationID)
	if err != nil || op.Status != "RUNNING" || count(t, s, "platform_operations") != 1 {
		t.Fatal("partial activation", op, err)
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_activation ON platform_operations"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal("activation retry", err)
		}
	}
	op, err = c.Operation(t.Context(), owner, e.OperationID)
	if err != nil || op.Status != "SUCCEEDED" || op.CompletedAt == nil || count(t, s, "platform_operations") != 2 {
		t.Fatal("success or unique auto-start missing", op, err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal("old completed callback", err)
	}
	assertPhase(t, s, e.AgentID, "QUIESCING")
	if _, err = s.pool.Exec(t.Context(), "UPDATE store_enrollments SET volume_id=$2 WHERE agent_id=$1", e.AgentID, newID("vol")); err == nil {
		t.Fatal("volume identity rebound")
	}
}

func TestRevocationCatalogueCoversClosuresAndRetiredNotifications(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	r, err := s.Submit(t.Context(), "a", "cancel", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(t.Context(), "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRequestClosure(t.Context(), r.RequestID, m); err != nil {
		t.Fatal(err)
	}
	id := mailboxFor(t, s, r.RequestID, "status")
	if _, err = s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if err = s.RetireDelivery(t.Context(), id, m); err != nil {
		t.Fatal(err)
	}
	// Construct the pre-catalogue schema's historical state in this isolated
	// fixture. Migration must recover both already completed kinds of intent.
	simulatePreLedgerSchema(t, s)
	if _, err = s.pool.Exec(t.Context(), `DROP TRIGGER revocation_catalogue_guard ON revocation_catalogue;
        DELETE FROM revocation_catalogue`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("catalogue migration cannot be repeated", err)
	}
	for _, subject := range []string{"request/" + r.RequestID, "event/" + id} {
		var exists bool
		if err = s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM revocation_catalogue WHERE subject=$1)", subject).Scan(&exists); err != nil || !exists {
			t.Fatal("completed revocation absent from catalogue", subject, err)
		}
		if _, err = s.pool.Exec(t.Context(), "DELETE FROM revocation_catalogue WHERE subject=$1", subject); err == nil {
			t.Fatal("revocation history can disappear", subject)
		}
	}
}

func TestEnrollmentMigrationPreservesPendingReservation(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	// Previous catalogue version had the reservation but no volume identity.
	// It also predates the versioned migration ledger. Reconstruct that legacy
	// installation explicitly rather than deleting data from a current schema.
	simulatePreLedgerSchema(t, s)
	if _, err := s.pool.Exec(t.Context(), "DELETE FROM store_enrollments WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.PendingProvisioning(t.Context(), e.HostID, 20)
	if err != nil || len(jobs) != 1 || jobs[0].AgentID != e.AgentID || jobs[0].OperationID != e.OperationID || jobs[0].VolumeID == "" {
		t.Fatal("legacy reservation stranded", jobs, err)
	}
	identity := jobs[0].VolumeID
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs, err = s.PendingProvisioning(t.Context(), e.HostID, 20)
	if err != nil || len(jobs) != 1 || jobs[0].VolumeID != identity {
		t.Fatal("migration replaced assigned volume", jobs, err)
	}
}

func TestEnrollmentInitializationRequiresCurrentBootBeforeFence(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	observeTestVolume(t, s, e)
	if count(t, s, "revocation_catalogue") != 0 {
		t.Fatal("fixture must start without fences")
	}
	if err := s.ActivateProvisionedAgent(t.Context(), e); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("empty catalogue bypassed filesystem initialization", err)
	}
	p := uninitializedEnrollmentBoot(t, s, e)
	proof := EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}
	for _, change := range []func(*EnrollmentBoot){
		func(x *EnrollmentBoot) { x.Incarnation++ },
		func(x *EnrollmentBoot) { x.Incarnation = 0 },
		func(x *EnrollmentBoot) { x.VolumeID = newID("vol") },
		func(x *EnrollmentBoot) { x.Generation++ },
		func(x *EnrollmentBoot) { x.VMID = "another-boot" },
		func(x *EnrollmentBoot) { x.HostID = "another-host" },
	} {
		wrong := proof
		change(&wrong)
		if err := s.RecordEnrollmentInitialized(t.Context(), wrong); err == nil {
			t.Fatal("foreign initialization ACK accepted")
		}
	}
	if count(t, s, "store_initializations") != 0 {
		t.Fatal("rejected ACK persisted")
	}
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	fence := EnrollmentFence{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID, Subject: "agent/a"}
	if err := s.RecordEnrollmentFence(t.Context(), fence); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("fence recorded before filesystem initialization", err)
	}
	for range 2 {
		if err := s.RecordEnrollmentInitialized(t.Context(), proof); err != nil {
			t.Fatal("initialization ACK retry", err)
		}
	}
	jobs, err := s.PendingProvisioning(t.Context(), e.HostID, 20)
	if err != nil || len(jobs) != 1 || !jobs[0].Initialized {
		t.Fatal("worker cannot observe initialization", err)
	}
	for _, sql := range []string{
		"DELETE FROM store_initializations WHERE agent_id=$1",
		"UPDATE store_initializations SET boot_generation=boot_generation+1 WHERE agent_id=$1",
	} {
		if _, err := s.pool.Exec(t.Context(), sql, e.AgentID); err == nil {
			t.Fatal("initialization receipt is mutable")
		}
	}
	if err = s.RecordEnrollmentFence(t.Context(), fence); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, p)
	if err = s.RecordEnrollmentInitialized(t.Context(), proof); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("stopped boot ACK accepted", err)
	}
	newBoot := uninitializedEnrollmentBoot(t, s, e)
	if err = s.RecordEnrollmentInitialized(t.Context(), proof); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("obsolete boot ACK accepted despite existing receipt", err)
	}
	proof.Generation, proof.VMID = newBoot.Generation, newBoot.VMID
	if err = s.RecordEnrollmentInitialized(t.Context(), proof); err != nil {
		t.Fatal(err)
	}
	var firstGeneration uint64
	if err = s.pool.QueryRow(t.Context(), "SELECT boot_generation FROM store_initializations WHERE agent_id=$1", e.AgentID).Scan(&firstGeneration); err != nil || firstGeneration != p.Generation {
		t.Fatal("later validation replaced initialization identity", err)
	}
	retireEnrollmentBoot(t, s, newBoot)
	if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyEnrollmentNeedsObservedInitialization(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce a READY enrollment from before initialization receipts existed.
	// This is isolated test setup, not a migration that invents an observation.
	simulatePreLedgerSchema(t, s)
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER store_initialization_guard ON store_initializations; DELETE FROM store_initializations"); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "store_initializations") != 0 {
		t.Fatal("migration fabricated guest readiness")
	}
	if _, err = s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", time.Minute); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("ordinary claim bypassed readiness", err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", p.Generation, "legacy-boot"); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("ordinary confirmation bypassed readiness", err)
	}
	if err = s.ActivateProvisionedAgent(t.Context(), e); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("READY replay bypassed readiness", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE agent_placements SET state='RUNNING',vm_id='legacy-boot',lease_until=NULL WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	caller := VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: "legacy-boot"}
	if err = s.ValidateVMCaller(t.Context(), caller); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("legacy running boot has ordinary authority", err)
	}
	retireEnrollmentBoot(t, s, p)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	p, err = s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", time.Minute)
	if err != nil {
		t.Fatal("observed validation cannot recover legacy enrollment", err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", p.Generation, "validated-boot"); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeBootPlanUsesCurrentAuthorityAndInitialization(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, false)
	observeTestVolume(t, s, e)
	p, err := s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proof := VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: "0123456789abcdef"}
	plan, err := s.PrepareVolumeBoot(t.Context(), proof, "installer")
	if err != nil || !plan.Initialize || !plan.AcknowledgeInitialization || plan.Enrollment.VolumeID != e.VolumeID || plan.UncleanStop {
		t.Fatal("new restricted boot plan", err)
	}
	if _, err = s.PrepareVolumeBoot(t.Context(), proof, "obsolete-worker"); !errors.Is(err, ErrPlacement) {
		t.Fatal("foreign worker can request key", err)
	}
	old := proof
	old.Generation++
	if _, err = s.PrepareVolumeBoot(t.Context(), old, "installer"); !errors.Is(err, ErrPlacement) {
		t.Fatal("foreign generation can request key", err)
	}
	if err = s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", p.Generation, proof.VMID); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentInitialized(t.Context(), EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: proof.VMID}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareVolumeBoot(t.Context(), proof, "installer"); !errors.Is(err, ErrPlacement) {
		t.Fatal("RUNNING placement gained new bootstrap capability", err)
	}
	retireEnrollmentBoot(t, s, p)
	p, err = s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proof.Generation = p.Generation
	proof.VMID = "0123456789abcdee"
	plan, err = s.PrepareVolumeBoot(t.Context(), proof, "installer")
	if err != nil || plan.Initialize || plan.AcknowledgeInitialization || !plan.UncleanStop {
		t.Fatal("initialized filesystem can be reformatted", err)
	}
	if err = s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", p.Generation, proof.VMID); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, s, p)
	if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	p, err = s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proof.Generation = p.Generation
	proof.VMID = "0123456789abcded"
	plan, err = s.PrepareVolumeBoot(t.Context(), proof, "ordinary")
	if err != nil || plan.Initialize || plan.AcknowledgeInitialization || !plan.UncleanStop {
		t.Fatal("ordinary boot plan", err)
	}
	// A decision before an RPC is not a durable grant of business authority.
	// Deletion can win before the post-readiness confirmation, which must fail.
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareVolumeBoot(t.Context(), proof, "ordinary"); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("deleting agent obtained ordinary bootstrap", err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "ordinary", p.Generation, proof.VMID); !errors.Is(err, ErrPlacement) {
		t.Fatal("old bootstrap plan overrode deletion", err)
	}
}

func TestVolumeBootPlanRechecksLeaseAfterLockWait(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, false)
	observeTestVolume(t, s, e)
	p, err := s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, e.AgentID); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err = tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.PrepareVolumeBoot(ctx, VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: "0123456789abcdef"}, "installer")
		done <- err
	}()
	waitUntil(t, func() bool {
		var waiting bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting
	})
	waitUntil(t, func() bool {
		var expired bool
		if err := s.pool.QueryRow(ctx, "SELECT lease_until<clock_timestamp() FROM agent_placements WHERE agent_id=$1", e.AgentID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		return expired
	})
	if err = commit(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrPlacement) {
		t.Fatal("lease elapsed during wait still allowed key delivery", err)
	}
}

func TestAbandonProvisioningFreesAnUnstartedReservationOnly(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	if err := s.AbandonProvisioning(t.Context(), "agent_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown agent not reported", err)
	}
	// A live job lease means a worker may be creating a volume right now.
	if err := s.DiscoverWork(t.Context(), e.HostID, 10); err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimWork(t.Context(), e.HostID, time.Minute)
	if err != nil || job.Kind != "provision" {
		t.Fatal("expected a provisioning job", job, err)
	}
	if err = s.AbandonProvisioning(t.Context(), e.AgentID); !errors.Is(err, ErrTransition) {
		t.Fatal("abandoned while a worker holds the job", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE worker_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = s.AbandonProvisioning(t.Context(), e.AgentID); err != nil {
		t.Fatal("stuck reservation could not be abandoned:", err)
	}
	if n := agentRows(t, s, e.AgentID); n != 0 {
		t.Fatal("rows remain after abandoning", n)
	}
	// The owner can reserve again.
	in := catalogInput(owner.ID)
	if _, err = c.Reserve(t.Context(), owner, "provision-again", in); err != nil {
		t.Fatal("owner is still blocked after abandoning:", err)
	}
}

func TestAbandonProvisioningRefusesOnceAVolumeIsRecorded(t *testing.T) {
	s, _, c, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, c, owner, false)
	observeTestVolume(t, s, e)
	if err := s.AbandonProvisioning(t.Context(), e.AgentID); !errors.Is(err, ErrTransition) {
		t.Fatal("abandoned a reservation that owns a volume", err)
	}
	if n := agentRows(t, s, e.AgentID); n < 4 {
		t.Fatal("refused abandon still changed rows", n)
	}
}

// agentRows counts the reservation rows of one agent across the tables that
// AbandonProvisioning removes.
func agentRows(t *testing.T, s *Store, id string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), `SELECT
        (SELECT count(*) FROM agents WHERE id=$1)+(SELECT count(*) FROM agent_specs WHERE agent_id=$1)
        +(SELECT count(*) FROM store_enrollments WHERE agent_id=$1)+(SELECT count(*) FROM platform_operations WHERE agent_id=$1)
        +(SELECT count(*) FROM worker_jobs WHERE agent_id=$1)`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
