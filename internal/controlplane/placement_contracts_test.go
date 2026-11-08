package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestPlacementContractMigrationDoesNotBlessRunningBoot(t *testing.T) {
	s := migrationStore(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Test-only downgrade to the deployed v6 state. Running a prefix through
	// migrate would fail the current binary's complete durable-table census.
	// Never remove a ledger row to repair or retry a production migration.
	revertTenantAgents(t, s)
	if _, err := s.pool.Exec(t.Context(), `DROP TABLE placement_control_contracts;
	  ALTER TABLE api_tokens DROP COLUMN issued_by_token_id;
	  DELETE FROM schema_migrations WHERE version>=7`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO agents(id,owner_user_id) VALUES('legacy','owner');
	  INSERT INTO agent_placements(agent_id,host_id,generation,state,worker_id,vm_id)
	  VALUES('legacy','host',9,'RUNNING','worker','legacy-vm')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "placement_control_contracts") != 0 {
		t.Fatal("migration invented compatibility")
	}
	if err := s.ValidatePlacement(t.Context(), "legacy", "host", 9, "legacy-vm"); err != nil {
		t.Fatal("migration disturbed physical adoption", err)
	}
	if _, err := s.pool.Exec(t.Context(), "ALTER TABLE placement_control_contracts SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Placements(t.Context(), "host"); !errors.Is(err, ErrUnsafeDatabase) {
		t.Fatal("compatibility observations lost durability guard", err)
	}
}

// SQL fixture observations below do not execute a VMM or negotiate a channel.
// Separate runtime/worker tests exercise those caller boundaries.
func TestPlacementContractSeparatesPhysicalCensusAndApplicationReadiness(t *testing.T) {
	s, catalog, _, _, owner, e := instructionLab(t)
	claim := func(vm string) PlacementControlObservation {
		t.Helper()
		p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "worker", p.Generation, vm); err != nil {
			t.Fatal(err)
		}
		return PlacementControlObservation{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: vm, Incarnation: e.Incarnation, Compatible: true}
	}
	state := func(want string) {
		t.Helper()
		v, err := catalog.Get(t.Context(), owner, e.AgentID)
		if err != nil || v.State != want {
			t.Fatal("application projection", v.State, want, err)
		}
	}
	first := claim("0123456789abcdef")
	state("STARTING")
	if err := s.ValidatePlacement(t.Context(), first.AgentID, first.HostID, first.Generation, first.VMID); err != nil {
		t.Fatal("physical adoption refused", err)
	}
	state("STARTING")
	for _, edit := range []func(*PlacementControlObservation){
		func(o *PlacementControlObservation) { o.HostID = "other" },
		func(o *PlacementControlObservation) { o.Generation++ },
		func(o *PlacementControlObservation) { o.VMID = "foreign" },
		func(o *PlacementControlObservation) { o.Incarnation++ },
	} {
		wrong := first
		edit(&wrong)
		if err := s.ObservePlacementControl(t.Context(), wrong); !errors.Is(err, ErrPlacement) {
			t.Fatal("foreign observation accepted", wrong, err)
		}
		state("STARTING")
	}
	if err := s.ObservePlacementControl(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	state("READY")
	failed := first
	failed.Compatible = false
	if err := s.ObservePlacementControl(t.Context(), failed); err != nil {
		t.Fatal(err)
	}
	state("STARTING")
	if err := s.ValidatePlacement(t.Context(), first.AgentID, first.HostID, first.Generation, first.VMID); err != nil {
		t.Fatal("incompatibility became physical absence", err)
	}
	if err := s.ObservePlacementControl(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginPlacementStop(t.Context(), first.AgentID, first.HostID, first.Generation); err != nil {
		t.Fatal(err)
	}
	state("STOPPING")
	if err := s.ObservePlacementStopped(t.Context(), first.AgentID, first.HostID, first.Generation, true); err != nil {
		t.Fatal(err)
	}
	second := claim("fedcba9876543210")
	state("STARTING")
	if err := s.ObservePlacementControl(t.Context(), first); !errors.Is(err, ErrPlacement) {
		t.Fatal("late success blessed replacement", err)
	}
	state("STARTING")
	if err := s.ObservePlacementControl(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	state("READY")
	if err := s.ObservePlacementControl(t.Context(), failed); !errors.Is(err, ErrPlacement) {
		t.Fatal("late failure accepted for replacement", err)
	}
	state("READY")
	wrongIncarnation := second
	wrongIncarnation.Incarnation++
	wrongIncarnation.Compatible = false
	if err := s.ObservePlacementControl(t.Context(), wrongIncarnation); err != nil {
		t.Fatal(err)
	}
	state("READY")
}

func TestPlacementContractSQLFailurePreservesPhysicalPlacement(t *testing.T) {
	s, catalog, _, _, owner, e := instructionLab(t)
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "worker", p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `CREATE FUNCTION reject_contract() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected contract observation failure'; END $$;
	  CREATE TRIGGER reject_contract BEFORE INSERT OR UPDATE ON placement_control_contracts FOR EACH ROW EXECUTE FUNCTION reject_contract()`); err != nil {
		t.Fatal(err)
	}
	err = s.ObservePlacementControl(t.Context(), PlacementControlObservation{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: "0123456789abcdef", Incarnation: e.Incarnation, Compatible: true})
	if err == nil {
		t.Fatal("failed SQL observation acknowledged")
	}
	if err = s.ValidatePlacement(t.Context(), e.AgentID, e.HostID, p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal("observation failure changed placement", err)
	}
	v, err := catalog.Get(t.Context(), owner, e.AgentID)
	if err != nil || v.State != "STARTING" {
		t.Fatal("failed observation published READY", v.State, err)
	}
}
