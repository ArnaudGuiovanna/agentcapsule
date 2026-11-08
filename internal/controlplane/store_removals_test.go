package controlplane

import (
	"errors"
	"strings"
	"testing"
)

func TestStoreRemovalPublishesCompletionAtomically(t *testing.T) {
	s, c, _, _, owner, e := instructionLab(t)
	r, err := c.Delete(t.Context(), owner, e.AgentID, "remove")
	op := acceptedOperation(t, r, err)
	if _, err = s.StoreRemovalTarget(t.Context(), e.AgentID, e.HostID); !errors.Is(err, ErrPlacement) {
		t.Fatal("premature cleanup", err)
	}
	m := mockStores(t, t.TempDir(), "a", "b", "c", e.AgentID)
	if err = s.ReconcileRevocation(t.Context(), e.AgentID, m); err != nil {
		t.Fatal(err)
	}
	p, _, err := s.StoreSealTarget(t.Context(), e.AgentID, e.HostID)
	if err != nil {
		t.Fatal(err)
	}
	proof := StoreSeal{AgentID: e.AgentID, HostID: e.HostID, ID: strings.Repeat("2", 32), Generation: p.Generation, Device: 1, Inode: 100}
	if err = s.RecordStoreRemoval(t.Context(), proof, e.VolumeID); !errors.Is(err, ErrNotFound) {
		t.Fatal("completion without execution seal", err)
	}
	// These are explicit trusted-observation fixtures; this test proves SQL
	// publication and job discovery, not physical key/container destruction.
	if err = s.RecordStoreSeal(t.Context(), proof); err != nil {
		t.Fatal(err)
	}
	plan, err := s.StoreRemovalTarget(t.Context(), e.AgentID, e.HostID)
	if err != nil || plan.Seal != proof || plan.Enrollment.VolumeID != e.VolumeID {
		t.Fatal(plan, err)
	}
	if err = s.DiscoverWork(t.Context(), e.HostID, 200); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM worker_jobs WHERE kind='deletion' AND agent_id=$1", e.AgentID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("sealed cleanup not discovered", jobs, err)
	}
	wrong := proof
	wrong.Inode++
	if err = s.RecordStoreRemoval(t.Context(), wrong, e.VolumeID); !errors.Is(err, ErrPlacement) {
		t.Fatal("different inode", err)
	}
	if err = s.RecordStoreRemoval(t.Context(), proof, "vol_"+strings.Repeat("f", 32)); !errors.Is(err, ErrPlacement) {
		t.Fatal("different volume", err)
	}
	if _, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_delete_success() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='delete' AND NEW.status='SUCCEEDED' THEN RAISE EXCEPTION 'injected final publication failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_delete_success BEFORE UPDATE ON platform_operations FOR EACH ROW EXECUTE FUNCTION reject_delete_success()`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordStoreRemoval(t.Context(), proof, e.VolumeID); err == nil {
		t.Fatal("failed publication acknowledged")
	}
	if count(t, s, "store_removals") != 0 {
		t.Fatal("partial receipt")
	}
	assertPhase(t, s, e.AgentID, "DELETING")
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_delete_success ON platform_operations"); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordStoreRemoval(t.Context(), proof, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	first, err := c.Operation(t.Context(), owner, op.OperationID)
	if err != nil || first.Status != "SUCCEEDED" || first.DeletionPhase != "COMPLETE" || first.CompletedAt == nil {
		t.Fatal(first, err)
	}
	if err = s.RecordStoreRemoval(t.Context(), proof, e.VolumeID); err != nil {
		t.Fatal("replay", err)
	}
	again, err := c.Operation(t.Context(), owner, op.OperationID)
	if err != nil || again.CompletedAt == nil || !again.CompletedAt.Equal(*first.CompletedAt) {
		t.Fatal("unstable completion", err)
	}
	assertPhase(t, s, e.AgentID, "DELETED")
	for _, q := range []string{"UPDATE store_removals SET seal_id=repeat('f',32)", "DELETE FROM store_removals", "UPDATE agents SET phase='DELETING' WHERE phase='DELETED'"} {
		if _, err = s.pool.Exec(t.Context(), q); err == nil {
			t.Fatal("permanent removal changed", q)
		}
	}
	if _, err = s.pool.Exec(t.Context(), "DELETE FROM worker_jobs WHERE kind='deletion' AND agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = s.DiscoverWork(t.Context(), e.HostID, 200); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(t.Context(), "SELECT count(*) FROM worker_jobs WHERE kind='deletion' AND agent_id=$1", e.AgentID).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("completed cleanup rediscovered", jobs, err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "store_removals") != 1 {
		t.Fatal("migration lost receipt")
	}
}
