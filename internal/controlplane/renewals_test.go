package controlplane

import (
	"errors"
	"os"
	"testing"
	"time"
)

func renewalBoot(t *testing.T, s *Store, id string) Placement {
	t.Helper()
	if err := s.RegisterPlacement(t.Context(), id, "host"); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimPlacement(t.Context(), id, "host", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(t.Context(), id, "host", "worker", p.Generation, "vm-"+id); err != nil {
		t.Fatal(err)
	}
	p.State, p.VMID = "RUNNING", "vm-"+id
	return p
}

func TestRenewalIntentAtomicityAndObservation(t *testing.T) {
	s, _ := freshStore(t, "auto", 1)
	p := renewalBoot(t, s, "a")
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION fail_renewal_stop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$;
        CREATE TRIGGER fail_renewal_stop BEFORE UPDATE ON agent_placements FOR EACH ROW EXECUTE FUNCTION fail_renewal_stop()`); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginCredentialRenewal(t.Context(), "a", "host", p.Generation, p.VMID); err == nil {
		t.Fatal("injected update succeeded")
	}
	if count(t, s, "placement_renewals") != 0 {
		t.Fatal("intent escaped failed STOPPING transaction")
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER fail_renewal_stop ON agent_placements"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.BeginCredentialRenewal(t.Context(), "a", "host", p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.PendingCredentialRenewals(t.Context(), "host")
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	job := jobs[0]
	if _, err = s.ClaimRenewalPlacement(t.Context(), job, "next", time.Minute); !errors.Is(err, ErrPlacementBusy) {
		t.Fatal("claimed before retirement:", err)
	}
	if err = s.ObserveRenewalSatisfied(t.Context(), "a", "host", p.Generation, p.VMID); !errors.Is(err, ErrPlacement) {
		t.Fatal("acknowledged old generation:", err)
	}
	if err = s.ObservePlacementStopped(t.Context(), "a", "host", p.Generation, true); err != nil {
		t.Fatal(err)
	}
	next, err := s.ClaimRenewalPlacement(t.Context(), job, "next", time.Minute)
	if err != nil || next.Generation != p.Generation+1 {
		t.Fatal(next, err)
	}
	if err = s.ConfirmPlacement(t.Context(), "a", "host", "next", next.Generation, "replacement"); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "placement_renewals") != 1 {
		t.Fatal("SQL confirmation prematurely completed job")
	}
	if err = s.ObserveRenewalSatisfied(t.Context(), "a", "host", next.Generation, "wrong"); !errors.Is(err, ErrPlacement) {
		t.Fatal(err)
	}
	if err = s.ObserveRenewalSatisfied(t.Context(), "a", "host", next.Generation, "replacement"); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "placement_renewals") != 0 {
		t.Fatal("verified replacement not observed")
	}
	if err = s.BeginCredentialRenewal(t.Context(), "a", "host", next.Generation, "replacement"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimRenewalPlacement(t.Context(), job, "stale", time.Minute); !errors.Is(err, ErrNoRenewal) {
		t.Fatal("old snapshot accepted:", err)
	}
	if err = s.ObserveRenewalSatisfied(t.Context(), "a", "host", next.Generation, "replacement"); !errors.Is(err, ErrPlacement) {
		t.Fatal("new renewal erased:", err)
	}
	if count(t, s, "placement_renewals") != 1 {
		t.Fatal("new intent lost")
	}
}

func TestRenewalCancellationAndDurability(t *testing.T) {
	s, dsn := freshStore(t, "auto", 1)
	for _, id := range []string{"a", "b"} {
		p := renewalBoot(t, s, id)
		if err := s.BeginCredentialRenewal(t.Context(), id, "host", p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.PendingCredentialRenewals(t.Context(), "host")
	if err != nil || len(jobs) != 2 {
		t.Fatal(jobs, err)
	}
	if err = s.BeginPlacementStop(t.Context(), "a", "host", 1); err != nil {
		t.Fatal(err)
	}
	if err = s.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if count(t, s, "placement_renewals") != 0 {
		t.Fatal("canceled intent retained")
	}
	for _, job := range jobs {
		if err = s.ObservePlacementStopped(t.Context(), job.AgentID, "host", 1, true); err != nil {
			t.Fatal(err)
		}
		if _, err = s.ClaimRenewalPlacement(t.Context(), job, "delayed", time.Minute); !errors.Is(err, ErrNoRenewal) {
			t.Fatal("canceled restart revived:", err)
		}
	}
	if _, err = s.pool.Exec(t.Context(), "ALTER TABLE placement_renewals SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(t.Context(), dsn); !errors.Is(err, ErrUnsafeDatabase) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("unlogged restart jobs accepted:", err)
	}
}

func TestRenewalDatabaseRecovery(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_PG_RECOVERY")
	if phase == "" {
		return
	}
	dsn := databaseURL(t)
	admin, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const schema = "renewal_recovery"
	if phase == "prepare" {
		if _, err = admin.pool.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(t.Context(), scopedURL(t, dsn, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if phase == "prepare" {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "INSERT INTO agents(id,owner_user_id) VALUES ('a','user-a')"); err != nil {
			t.Fatal(err)
		}
		p := renewalBoot(t, s, "a")
		if err = s.BeginCredentialRenewal(t.Context(), "a", "host", p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
		return
	}
	jobs, err := s.PendingCredentialRenewals(t.Context(), "host")
	if err != nil || len(jobs) != 1 || jobs[0].Generation != 1 {
		t.Fatal("WAL lost restart intent:", jobs, err)
	}
	p, err := s.Placements(t.Context(), "host")
	if err != nil || len(p) != 1 || p[0].State != "STOPPING" {
		t.Fatal("WAL split intent/stop:", p, err)
	}
	if _, err = admin.pool.Exec(t.Context(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
		t.Fatal(err)
	}
}
