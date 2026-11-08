package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func acceptedOperation(t *testing.T, r APIReceipt, err error) AgentCreation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var op AgentCreation
	if r.Status != 202 {
		t.Fatal(r.Status)
	}
	if err = json.Unmarshal(r.Body, &op); err != nil {
		t.Fatal(err)
	}
	return op
}
func requestOperation(t *testing.T, c *AgentCatalog, p Principal, id, key, kind string) AgentCreation {
	t.Helper()
	r, err := c.RequestLifecycle(t.Context(), p, id, key, kind)
	return acceptedOperation(t, r, err)
}

func TestLifecycleOperationsOrderAndCurrentObservations(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	wake := requestOperation(t, catalog, owner, e.AgentID, "wake", "wake")
	sleep := requestOperation(t, catalog, owner, e.AgentID, "sleep", "sleep")
	if _, err := s.BeginLifecycleOperation(t.Context(), sleep.OperationID, e.AgentID, e.HostID); !errors.Is(err, ErrOperationPending) {
		t.Fatal("sleep overtook wake", err)
	}
	op, err := s.BeginLifecycleOperation(t.Context(), wake.OperationID, e.AgentID, e.HostID)
	if err != nil || op.Status != "RUNNING" {
		t.Fatal(op, err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, op.Placement.Generation, ""); !errors.Is(err, ErrPlacement) {
		t.Fatal("unstarted wake completed", err)
	}
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "worker", p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation-1, "0123456789abcdef"); !errors.Is(err, ErrPlacement) {
		t.Fatal("old boot completed operation", err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation, "0123456789abcdef"); !errors.Is(err, ErrPlacement) {
		t.Fatal("physical RUNNING completed wake without negotiated contract", err)
	}
	if err = s.ObservePlacementControl(t.Context(), PlacementControlObservation{AgentID: e.AgentID, HostID: e.HostID,
		Generation: p.Generation, VMID: "0123456789abcdef", Incarnation: e.Incarnation, Compatible: true}); err != nil {
		t.Fatal(err)
	}
	// SQL fixture: real host publication must precede this observation in Go.
	if _, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_lifecycle_success() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='wake' AND NEW.status='SUCCEEDED' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_lifecycle BEFORE UPDATE ON platform_operations FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_success()`); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation, "0123456789abcdef"); err == nil {
		t.Fatal("failed result publication ignored")
	}
	if got, err := catalog.Operation(t.Context(), owner, op.ID); err != nil || got.Status != "RUNNING" {
		t.Fatal("partial completion", got, err)
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_lifecycle ON platform_operations"); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if old, err := s.BeginLifecycleOperation(t.Context(), op.ID, e.AgentID, e.HostID); err != nil || old.Status != "SUCCEEDED" {
		t.Fatal("completed wake reopened", old, err)
	}
	op, err = s.BeginLifecycleOperation(t.Context(), sleep.OperationID, e.AgentID, e.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation, ""); !errors.Is(err, ErrPlacement) {
		t.Fatal("sleep completed before retirement", err)
	}
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, p.Generation, ""); err != nil {
		t.Fatal(err)
	}
	finished, err := catalog.Operation(t.Context(), owner, op.ID)
	if err != nil || finished.Status != "SUCCEEDED" || finished.UncleanStop == nil || !*finished.UncleanStop {
		t.Fatal("forced stop advertised as clean", finished, err)
	}
}

func TestLifecycleCommandsReplayAndDeletionCancellation(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, false)
	if _, err := catalog.RequestLifecycle(t.Context(), owner, e.AgentID, "too-early", "wake"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wake before activation", err)
	}
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	wake := requestOperation(t, catalog, owner, e.AgentID, "wake", "wake")
	sleep := requestOperation(t, catalog, owner, e.AgentID, "sleep", "sleep")
	op, err := s.BeginLifecycleOperation(t.Context(), wake.OperationID, e.AgentID, e.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if again := requestOperation(t, catalog, owner, e.AgentID, "wake", "wake"); again != wake {
		t.Fatal("historical receipt changed")
	}
	if _, err = catalog.RequestLifecycle(t.Context(), owner, e.AgentID, "new-wake", "wake"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("new command after deletion", err)
	}
	if err = s.CompleteLifecycleOperation(t.Context(), op, 1, "stale-boot"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{wake.OperationID, sleep.OperationID} {
		got, err := catalog.Operation(t.Context(), owner, id)
		if err != nil || got.Status != "CANCELED" || got.ErrorCode != "agent_unavailable" {
			t.Fatal("canceled command revived", got, err)
		}
		current, err := s.BeginLifecycleOperation(t.Context(), id, e.AgentID, e.HostID)
		if err != nil || current.Status != "CANCELED" {
			t.Fatal(current, err)
		}
	}
}

func TestLifecycleCommandsRollbackAndConcurrentSequence(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, false)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_lifecycle_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='wake' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_lifecycle BEFORE INSERT ON platform_operations FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_insert()`); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.RequestLifecycle(t.Context(), owner, e.AgentID, "retry", "wake"); err == nil {
		t.Fatal("failed command accepted")
	}
	if count(t, s, "platform_operations") != 1 {
		t.Fatal("partial operation")
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_lifecycle ON platform_operations"); err != nil {
		t.Fatal(err)
	}
	requestOperation(t, catalog, owner, e.AgentID, "retry", "wake")
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := range 6 {
		wg.Go(func() {
			_, err := catalog.RequestLifecycle(t.Context(), owner, e.AgentID, fmt.Sprint(i), "sleep")
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var total, minimum, maximum int
	if err := s.pool.QueryRow(t.Context(), "SELECT count(*),min(seq),max(seq) FROM platform_operations WHERE agent_id=$1", e.AgentID).Scan(&total, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if total != 8 || minimum != 1 || maximum != 8 {
		t.Fatal("sequence lost or consumed on rollback", total, minimum, maximum)
	}
	if err := s.DiscoverWork(t.Context(), e.HostID, 100); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "worker_jobs") != 1 {
		t.Fatal("more than head lifecycle operation scheduled")
	}
}

func TestLifecycleAutoStartSurvivesActivationAndDiscovery(t *testing.T) {
	s, _, catalog, _, _, owner := catalogLab(t)
	e := reserveEnrollment(t, s, catalog, owner, true)
	observeTestVolume(t, s, e)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
	if err := s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscoverWork(t.Context(), e.HostID, 10); err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimWork(t.Context(), e.HostID, time.Minute)
	if err != nil || job.Kind != "lifecycle" || job.AgentID != e.AgentID {
		t.Fatal("auto-start lost", job, err)
	}
	op, err := s.BeginLifecycleOperation(t.Context(), job.ID, job.AgentID, job.HostID)
	if err != nil || op.Kind != "wake" || op.Status != "RUNNING" {
		t.Fatal(op, err)
	}
}
