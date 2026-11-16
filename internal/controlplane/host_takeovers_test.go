package controlplane

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

// A takeover is recorded once and for good, and stops the lost host: its
// worker discovers and claims no work, and no agent is reserved on it. It
// moves nothing by itself. A host that is lost cannot take another over,
// and the chain of takeovers ends at the live host.
func TestHostTakeoverIsFinalAndStopsTheLostHost(t *testing.T) {
	s, c, _, admin, owner, e := instructionLab(t)
	queueInstruction(t, c, owner, e.AgentID, "before-the-loss")
	if err := s.DiscoverWork(t.Context(), "local", 10); err != nil {
		t.Fatal(err)
	}
	owners := []User{}
	principals := []Principal{}
	for _, name := range []string{"second", "third"} {
		u := createAccount(t, c.accounts, admin, name+"-owner", name)
		p, err := s.Authenticate(t.Context(), issueAccountToken(t, c.accounts, admin, u, name+"-token").Token)
		if err != nil {
			t.Fatal(err)
		}
		owners, principals = append(owners, u), append(principals, p)
	}
	// An agent still provisioning when the host is lost.
	r, err := c.Reserve(t.Context(), principals[0], "before-the-loss", catalogInput(owners[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	var provisioning AgentCreation
	if err = json.Unmarshal(r.Body, &provisioning); err != nil {
		t.Fatal(err)
	}
	for name, hosts := range map[string][2]string{"empty": {"", "standby"}, "same": {"local", "local"}, "invalid": {"local", "a b"}} {
		if _, err := s.TakeOverHost(t.Context(), hosts[0], hosts[1]); !errors.Is(err, ErrInput) {
			t.Fatal("takeover input", name, err)
		}
	}
	if _, err = s.TakeOverHost(t.Context(), "never-seen", "standby"); !errors.Is(err, ErrNotFound) {
		t.Fatal("takeover of an unknown host", err)
	}
	taken, err := s.TakeOverHost(t.Context(), "local", "standby")
	if err != nil || taken.LostHostID != "local" || taken.HostID != "standby" || taken.TakenOverAt.IsZero() {
		t.Fatal("takeover", taken, err)
	}
	if again, err := s.TakeOverHost(t.Context(), "local", "standby"); err != nil || again != taken {
		t.Fatal("a repeated takeover is not the same record", again, err)
	}
	if _, err = s.TakeOverHost(t.Context(), "local", "other"); !errors.Is(err, ErrConflict) {
		t.Fatal("a second successor", err)
	}
	if _, err = s.TakeOverHost(t.Context(), "standby", "local"); !errors.Is(err, ErrHostLost) {
		t.Fatal("a lost host took another over", err)
	}
	for _, q := range []string{"UPDATE host_takeovers SET host_id='other'", "DELETE FROM host_takeovers"} {
		if _, err = s.pool.Exec(t.Context(), q); err == nil {
			t.Fatal("a takeover changed", q)
		}
	}

	// The lost host's worker gets no work, not even the job discovered
	// before; no agent is reserved there.
	if err = s.DiscoverWork(t.Context(), "local", 10); !errors.Is(err, ErrHostLost) {
		t.Fatal("discovery on a lost host", err)
	}
	if _, err = s.ClaimWork(t.Context(), "local", time.Minute); !errors.Is(err, ErrHostLost) {
		t.Fatal("claim on a lost host", err)
	}
	if _, err = c.Reserve(t.Context(), principals[1], "after-the-loss", catalogInput(owners[1].ID)); !errors.Is(err, ErrHostLost) {
		t.Fatal("reservation on a lost host", err)
	}
	agents, err := s.LostHostAgents(t.Context(), "local")
	if err != nil || len(agents) != 2 || !slices.ContainsFunc(agents, func(a LostHostAgent) bool {
		return a.AgentID == provisioning.AgentID && a.Phase == "PROVISIONING" && a.HostID == "local"
	}) {
		t.Fatal("agents of the lost host, one still provisioning", agents, err)
	}
	// A reservation that obtained nothing on the lost host can be abandoned.
	if err = s.AbandonProvisioning(t.Context(), provisioning.AgentID); err != nil {
		t.Fatal("abandon a reservation of the lost host", err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 1024); !errors.Is(err, ErrHostLost) {
		t.Fatal("storage of a lost host configured", err)
	}

	// Nothing moved: the agent is still on the lost host.
	var placement, spec string
	if err = s.pool.QueryRow(t.Context(), `SELECT p.host_id,x.host_id FROM agent_placements p JOIN agent_specs x ON x.agent_id=p.agent_id
        WHERE p.agent_id=$1`, e.AgentID).Scan(&placement, &spec); err != nil || placement != "local" || spec != "local" {
		t.Fatal("the takeover moved the agent", placement, spec, err)
	}
	agents, err = s.LostHostAgents(t.Context(), "local")
	if err != nil || len(agents) != 1 || agents[0].AgentID != e.AgentID || agents[0].HostID != "local" || agents[0].Phase != "LIVE" ||
		agents[0].Stage != "READY" || agents[0].Incarnation != 1 || agents[0].Restore != nil || len(agents[0].Archives) != 0 {
		t.Fatal("agents of the lost host", agents, err)
	}

	// The standby is lost in turn: the chain ends at the third host.
	if _, err = s.TakeOverHost(t.Context(), "standby", "third"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.HostTakeoverOf(t.Context(), "local"); err != nil || got.LostHostID != "local" || got.HostID != "third" || !got.TakenOverAt.Equal(taken.TakenOverAt) {
		t.Fatal("the end of the chain", got, err)
	}
	if _, err = s.HostTakeoverOf(t.Context(), "third"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a live host is not lost", err)
	}
	if _, err = s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "standby", archiveID(1)); !errors.Is(err, ErrPlacement) {
		t.Fatal("a restore on a lost host of the chain", err)
	}
}

// A restore that begins on the host that took the agent's lost host over
// moves the agent there, in the transaction that takes its volume out of
// service: its placement (stopped), its specification, its unfinished
// operations and its jobs, in their order. The new volume file's identity is
// recorded once, before the install, and the restore then ends on the new
// host like any other. A host that did not take the agent's host over cannot
// restore it.
func TestRestoreRelocatesAnAgentOfALostHost(t *testing.T) {
	s, c, _, _, owner, e := instructionLab(t)
	_, first := queueInstruction(t, c, owner, e.AgentID, "first")
	_, second := queueInstruction(t, c, owner, e.AgentID, "second")
	if err := s.DiscoverWork(t.Context(), "local", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,size)
        VALUES($1,$2,'local',$3,1,now()-interval '2 hours',now()-interval '1 hour',4096)`, archiveID(1), e.AgentID, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE worker_jobs SET failures=3 WHERE host_id='local'"); err != nil {
		t.Fatal(err)
	}
	jobs := func(host string) []string {
		t.Helper()
		rows, err := s.pool.Query(t.Context(), `SELECT kind||':'||object_id||':'||failures||':'||(lease_until IS NULL)
            FROM worker_jobs WHERE host_id=$1 AND agent_id=$2 ORDER BY ticket`, host, e.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := []string{}
		for rows.Next() {
			var j string
			if err = rows.Scan(&j); err != nil {
				t.Fatal(err)
			}
			got = append(got, j)
		}
		return got
	}
	before := jobs("local")
	if len(before) == 0 {
		t.Fatal("no job to move")
	}
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "standby", archiveID(1)); !errors.Is(err, ErrPlacement) {
		t.Fatal("a restore on a host that took nothing over", err)
	}
	if _, err := s.TakeOverHost(t.Context(), "local", "standby"); err != nil {
		t.Fatal(err)
	}
	plan, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "standby", archiveID(1))
	if err != nil {
		t.Fatal(err)
	}
	if plan.RelocatedFrom != "local" || plan.Placement.HostID != "standby" || plan.Placement.State != "STOPPED" || plan.Enrollment.HostID != "standby" ||
		plan.Enrollment.Stage != "RESTORING" || plan.Enrollment.Incarnation != 2 || plan.Restore.HostID != "standby" || plan.Device != 1 || plan.Inode != 100 {
		t.Fatal("relocated restore", plan)
	}
	if again, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "standby", archiveID(1)); err != nil || again.Restore != plan.Restore {
		t.Fatal("a repeated begin is not the same restore", again, err)
	}
	if got := jobs("standby"); !slices.Equal(got, before) || len(jobs("local")) != 0 {
		t.Fatal("the jobs did not move in their order", got, before)
	}
	var operations int
	if err = s.pool.QueryRow(t.Context(), `SELECT count(*) FROM platform_operations WHERE id IN ($1,$2) AND host_id='standby'`, first, second).Scan(&operations); err != nil || operations != 2 {
		t.Fatal("the unfinished operations did not move", operations, err)
	}
	var from, to, device string
	if err = s.pool.QueryRow(t.Context(), "SELECT from_host_id,host_id,from_volume_device FROM volume_relocations WHERE restore_id=$1", restoreID(1)).Scan(&from, &to, &device); err != nil ||
		from != "local" || to != "standby" || device != "0000000000000001" {
		t.Fatal("relocation record", from, to, device, err)
	}
	// The lost host's archive is still the newest one of the agent.
	if newer, err := s.NewerVolumeArchives(t.Context(), e.AgentID, "standby", archiveID(1)); err != nil || len(newer) != 0 {
		t.Fatal("newer archives", newer, err)
	}

	// The new volume file: recorded once, before the install, on its host.
	if err = s.RecordRelocatedVolume(t.Context(), restoreID(1), "local", 2, 200); !errors.Is(err, ErrPlacement) {
		t.Fatal("recorded from the lost host", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE store_enrollments SET volume_inode='0000000000000999' WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal("the guard refused a pending relocation's volume", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE store_enrollments SET volume_inode='0000000000000064' WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordRelocatedVolume(t.Context(), restoreID(1), "standby", 2, 200); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordRelocatedVolume(t.Context(), restoreID(1), "standby", 2, 200); err != nil {
		t.Fatal("a repeated record", err)
	}
	if err = s.RecordRelocatedVolume(t.Context(), restoreID(1), "standby", 3, 300); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("a second volume recorded", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE store_enrollments SET volume_inode='0000000000000999' WHERE agent_id=$1", e.AgentID); err == nil {
		t.Fatal("the volume changed after its relocation was recorded")
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE volume_relocations SET volume_inode='0000000000000999' WHERE restore_id=$1", restoreID(1)); err == nil {
		t.Fatal("a recorded relocation changed")
	}
	if plan, err = s.VolumeRestoreTarget(t.Context(), restoreID(1), "standby"); err != nil || plan.RelocatedFrom != "" || plan.Device != 2 || plan.Inode != 200 {
		t.Fatal("plan after the record", plan, err)
	}

	// The restore ends on the new host like any other.
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err = s.AdvanceVolumeRestore(t.Context(), restoreID(1), "standby", step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	p := restrictedRestoreBoot(t, s, plan.Enrollment)
	if err = s.ActivateVolumeRestore(t.Context(), restoreID(1), "standby", p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, "standby", p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, "standby", p.Generation, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompleteVolumeRestore(t.Context(), restoreID(1), "standby", nil); err != nil {
		t.Fatal(err)
	}
	if stage, incarnation := enrollmentState(t, s, e.AgentID); stage != "READY" || incarnation != 2 {
		t.Fatal("volume after the relocated restore", stage, incarnation)
	}
	if err = s.DiscoverWork(t.Context(), "standby", 10); err != nil {
		t.Fatal(err)
	}
	if j, err := s.ClaimWork(t.Context(), "standby", time.Minute); err != nil || j.AgentID != e.AgentID {
		t.Fatal("the new host's work", j, err)
	}
	agents, err := s.LostHostAgents(t.Context(), "local")
	if err != nil || len(agents) != 1 || agents[0].HostID != "standby" || agents[0].Restore == nil || agents[0].Restore.Step != RestoreSucceeded ||
		agents[0].Incarnation != 2 || len(agents[0].Archives) != 1 || agents[0].Archives[0].ID != archiveID(1) {
		t.Fatal("agents of the lost host after the restore", agents, err)
	}
	// A later restore on the new host is an ordinary one.
	if plan, err = s.BeginVolumeRestore(t.Context(), restoreID(2), e.AgentID, "standby", archiveID(1)); err != nil || plan.RelocatedFrom != "" || plan.Device != 2 {
		t.Fatal("a later restore", plan, err)
	}
}

// A relocation's volume is recorded only before the install: once the
// archive is installed, or after a superseding restore of the agent
// installed nothing yet, the rule follows the agent, not the restore.
func TestRelocatedVolumeIsRecordedBeforeTheInstall(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	if _, err := s.TakeOverHost(t.Context(), "local", "standby"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginVolumeRestore(t.Context(), restoreID(1), e.AgentID, "standby", archiveID(1)); err != nil {
		t.Fatal(err)
	}
	// Another archive replaces the first before anything was created: the
	// relocation is still pending for the superseding restore.
	plan, err := s.BeginVolumeRestore(t.Context(), restoreID(2), e.AgentID, "standby", archiveID(2))
	if err != nil || plan.RelocatedFrom != "local" || plan.Enrollment.Incarnation != 3 {
		t.Fatal("superseding restore", plan, err)
	}
	for _, step := range [][2]string{{RestoreDraining, RestoreInstalling}, {RestoreInstalling, RestoreReconciling}} {
		if err = s.AdvanceVolumeRestore(t.Context(), restoreID(2), "standby", step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.RecordRelocatedVolume(t.Context(), restoreID(2), "standby", 2, 200); !errors.Is(err, ErrRestore) {
		t.Fatal("a volume recorded after the install", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE store_enrollments SET volume_inode='0000000000000999' WHERE agent_id=$1", e.AgentID); err == nil {
		t.Fatal("the guard let the volume change after the install")
	}
	if _, err = s.pool.Exec(t.Context(), "DELETE FROM volume_relocations"); err == nil {
		t.Fatal("a relocation deleted")
	}
}
