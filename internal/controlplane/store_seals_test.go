package controlplane

import (
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func sealProof() StoreSeal {
	return StoreSeal{AgentID: "a", HostID: "host", ID: "0123456789abcdef0123456789abcdef", Device: 9, Inode: 17}
}

func prepareSealSQL(t *testing.T, s *Store) {
	t.Helper()
	if err := s.RegisterPlacement(t.Context(), "a", "host"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	if err := s.ReconcileRevocation(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}
}

func TestStoreSealRequiresCompletedBarrierAndImmutableReceipt(t *testing.T) {
	s, dsn := freshStore(t, "auto", 3)
	if err := s.RegisterPlacement(t.Context(), "a", "host"); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := s.StoreSealTarget(t.Context(), "a", "host"); err != nil || ready {
		t.Fatal(ready, err)
	}
	if err := s.RecordStoreSeal(t.Context(), sealProof()); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	if err := s.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := s.StoreSealTarget(t.Context(), "a", "host"); err != nil || ready {
		t.Fatal(ready, err)
	}
	if err := s.RecordStoreSeal(t.Context(), sealProof()); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	// A phase flag alone is not a completed distributed barrier.
	if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET phase='DELETING' WHERE id='a'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.StoreSealTarget(t.Context(), "a", "host"); !errors.Is(err, ErrPendingFences) {
		t.Fatal(err)
	}
	if err := s.RecordStoreSeal(t.Context(), sealProof()); !errors.Is(err, ErrPendingFences) {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET phase='QUIESCING' WHERE id='a'"); err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), "a", "b", "c")
	if err := s.ReconcileRevocation(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}
	// This unit test trusts a synthetic host observation. Actual physical
	// retirement and refusal to ACK without it are checked by the KVM tests.
	if err := s.RecordStoreSeal(t.Context(), sealProof()); err != nil {
		t.Fatal(err)
	}
	peer, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.RecordStoreSeal(t.Context(), sealProof()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*StoreSeal){
		func(p *StoreSeal) { p.ID = "ffffffffffffffffffffffffffffffff" },
		func(p *StoreSeal) { p.HostID = "foreign" },
		func(p *StoreSeal) { p.Generation++ },
		func(p *StoreSeal) { p.Inode++ },
		func(p *StoreSeal) { p.Device++ },
	} {
		p := sealProof()
		mutate(&p)
		if err = s.RecordStoreSeal(t.Context(), p); !errors.Is(err, ErrPlacement) {
			t.Fatal("different receipt accepted:", err)
		}
	}
	for _, statement := range []string{
		"UPDATE store_seals SET generation=1", "DELETE FROM store_seals",
		"UPDATE agents SET phase='LIVE' WHERE id='a'",
		"UPDATE agent_placements SET generation=1 WHERE agent_id='a'",
		"UPDATE agent_placements SET host_id='other' WHERE agent_id='a'",
	} {
		if _, err = s.pool.Exec(t.Context(), statement); err == nil {
			t.Fatal("permanent seal changed:", statement)
		}
	}
	assertPhase(t, s, "a", "DELETING")
	if _, err = s.pool.Exec(t.Context(), "ALTER TABLE store_removals DROP CONSTRAINT store_removals_agent_id_fkey; ALTER TABLE store_seals SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(t.Context(), dsn); !errors.Is(err, ErrUnsafeDatabase) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("volatile seal table accepted:", err)
	}
}

func TestStoreSealPublicationRollsBackWithPlacementFailure(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	prepareSealSQL(t, s)
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION fail_seal_stop() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected placement failure'; END $$;
        CREATE TRIGGER fail_seal_stop BEFORE UPDATE ON agent_placements FOR EACH ROW EXECUTE FUNCTION fail_seal_stop()`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStoreSeal(t.Context(), sealProof()); err == nil {
		t.Fatal("placement failure acknowledged")
	}
	if count(t, s, "store_seals") != 0 {
		t.Fatal("partial receipt committed")
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER fail_seal_stop ON agent_placements"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStoreSeal(t.Context(), sealProof()); err != nil {
		t.Fatal(err)
	}
}

// Executed in distinct processes around the runner's actual PostgreSQL immediate
// shutdown and WAL recovery. This tests receipt durability, not a physical host.
func TestStoreSealDatabaseRecovery(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_PG_RECOVERY")
	if phase == "" {
		return
	}
	root := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if phase == "prepare" {
		if _, err = admin.Exec(t.Context(), "CREATE SCHEMA restart_seal"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(t.Context(), scopedURL(t, root, "restart_seal"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if phase == "prepare" {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		seed(t, s, "auto", 3)
		prepareSealSQL(t, s)
	} else if phase != "verify" {
		t.Fatal("invalid recovery phase")
	}
	if phase == "verify" && count(t, s, "store_seals") != 1 {
		t.Fatal("durable receipt lost before replay")
	}
	if err = s.RecordStoreSeal(t.Context(), sealProof()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "store_seals") != 1 {
		t.Fatal("receipt missing")
	}
	p, ready, err := s.StoreSealTarget(t.Context(), "a", "host")
	if err != nil || !ready || p.State != "STOPPED" {
		t.Fatal(p, ready, err)
	}
	assertPhase(t, s, "a", "DELETING")
}
