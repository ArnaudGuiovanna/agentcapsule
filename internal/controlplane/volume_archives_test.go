package controlplane

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// archiveAgents provisions one LIVE agent with an initialized volume per
// state on host "local": "asleep" (cleanly stopped), "running", or "unclean"
// (stopped without the guest's acknowledgment, as provisioning leaves it).
func archiveAgents(t *testing.T, states ...string) (*Store, []Enrollment) {
	t.Helper()
	s, a, c, admin, _, _ := catalogLab(t)
	if err := s.ConfigureHostStorage(t.Context(), "local", 64*1024); err != nil {
		t.Fatal(err)
	}
	var result []Enrollment
	for i, state := range states {
		u := createAccount(t, a, admin, fmt.Sprintf("archive-owner-%d", i), "Owner")
		owner, err := s.Authenticate(t.Context(), issueAccountToken(t, a, admin, u, fmt.Sprintf("archive-token-%d", i)).Token)
		if err != nil {
			t.Fatal(err)
		}
		e := reserveEnrollment(t, s, c, owner, false)
		observeTestVolume(t, s, e)
		retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
		if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		if state != "unclean" {
			p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "archive-test", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "archive-test", p.Generation, fmt.Sprintf("vm-%d", p.Generation)); err != nil {
				t.Fatal(err)
			}
			if state == "asleep" {
				if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
					t.Fatal(err)
				}
				if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, false); err != nil {
					t.Fatal(err)
				}
			}
		}
		result = append(result, e)
	}
	return s, result
}

var dailyArchives = ArchivePolicy{Every: 24 * time.Hour, SleepWindow: 2 * time.Hour}

func archiveID(n int) string { return fmt.Sprintf("arc_%032x", n) }

func due(t *testing.T, s *Store, now *time.Time, limit int) []string {
	t.Helper()
	candidates, err := s.DueVolumeArchives(t.Context(), "local", now, dailyArchives, limit)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.AgentID)
	}
	return ids
}

func archived(t *testing.T, s *Store, agent string, running bool, id string, now *time.Time) {
	t.Helper()
	if err := s.BeginVolumeArchive(t.Context(), "local", agent, id, running, now, dailyArchives); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteVolumeArchive(t.Context(), id, 256<<20, false); err != nil {
		t.Fatal(err)
	}
}

func later(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
}

// A sleeping agent is captured at once when it has no archive, and from
// Every-SleepWindow on; a running agent only once its newest archive (or its
// initialization) is Every old; sleeping agents come first, then the oldest.
// An unclean stop, a deleted agent and another host are never selected.
func TestVolumeArchivesDueSleepingFirstThenOverdueRunning(t *testing.T) {
	s, agents := archiveAgents(t, "asleep", "asleep", "running", "unclean", "running")
	fresh, old, busy, unclean, busier := agents[0].AgentID, agents[1].AgentID, agents[2].AgentID, agents[3].AgentID, agents[4].AgentID
	// Ties (no archive yet) go by agent ID.
	if got := due(t, s, nil, 10); !slices.Equal(got, slices.Sorted(slices.Values([]string{fresh, old}))) {
		t.Fatal("never-archived sleeping agents are due at once, running ones are not", got)
	}
	archived(t, s, fresh, false, archiveID(1), nil)
	if got := due(t, s, nil, 10); !slices.Equal(got, []string{old}) {
		t.Fatal("an agent archived just now is not due", got)
	}
	if got := due(t, s, later(21*time.Hour), 10); !slices.Equal(got, []string{old}) {
		t.Fatal("before the sleep window, the archived agent waits", got)
	}
	archived(t, s, old, false, archiveID(2), nil)
	if got := due(t, s, later(23*time.Hour), 10); !slices.Equal(got, []string{fresh, old}) {
		t.Fatal("in the sleep window, sleeping agents are due, oldest archive first; running ones wait", got)
	}
	if got := due(t, s, later(25*time.Hour), 10); !slices.Equal(got, []string{fresh, old, busy, busier}) {
		t.Fatal("past Every, running agents are due after the sleeping ones, oldest first", got)
	}
	if got := due(t, s, later(25*time.Hour), 1); !slices.Equal(got, []string{fresh}) {
		t.Fatal("the limit bounds the selection", got)
	}
	archived(t, s, busier, true, archiveID(3), later(25*time.Hour))
	if got := due(t, s, later(25*time.Hour), 10); !slices.Equal(got, []string{fresh, old, busy, busier}) {
		t.Fatal("seen 25 hours later, a capture of now is due again, after older ones", got)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE volume_archives SET started_at=started_at+interval '2 hours',captured_at=captured_at+interval '2 hours' WHERE archive_id=$1", archiveID(3)); err != nil {
		t.Fatal(err)
	}
	if got := due(t, s, later(25*time.Hour), 10); !slices.Equal(got, []string{fresh, old, busy}) {
		t.Fatal("a running agent whose archive is 23 hours old is not due", got)
	}
	for _, id := range []string{unclean} {
		if slices.Contains(due(t, s, later(30*24*time.Hour), 10), id) {
			t.Fatal("an unclean stop is never selected: a capture would refuse it")
		}
	}
	candidates, err := s.DueVolumeArchives(t.Context(), "local", later(25*time.Hour), dailyArchives, 10)
	if err != nil || len(candidates) != 3 || candidates[0].Running || candidates[0].Last == nil || !candidates[2].Running || candidates[2].Last != nil {
		t.Fatal("candidates describe the VM and the newest archive", candidates, err)
	}
	if got, err := s.DueVolumeArchives(t.Context(), "elsewhere", later(25*time.Hour), dailyArchives, 10); err != nil || len(got) != 0 {
		t.Fatal("another host's agents are not selected", got, err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET phase='QUIESCING' WHERE id=$1", old); err != nil {
		t.Fatal(err)
	}
	if got := due(t, s, later(25*time.Hour), 10); !slices.Equal(got, []string{fresh, busy}) {
		t.Fatal("an agent leaving LIVE is not archived", got)
	}
	for _, bad := range []ArchivePolicy{{}, {Every: time.Hour, SleepWindow: time.Hour}, {Every: time.Hour, SleepWindow: -time.Second}} {
		if _, err := s.DueVolumeArchives(t.Context(), "local", nil, bad, 10); !errors.Is(err, ErrInput) {
			t.Fatal("invalid policy accepted", bad, err)
		}
	}
	if _, err := s.DueVolumeArchives(t.Context(), "local", nil, dailyArchives, 0); !errors.Is(err, ErrInput) {
		t.Fatal("empty limit accepted", err)
	}
}

// Under the agent's lock, Begin checks again that the agent is due and that
// its VM is in the state seen by the worker, then records the capture. A
// pending capture does not count as an archive until it is completed.
func TestVolumeArchiveBeginRechecksAndRecords(t *testing.T) {
	s, agents := archiveAgents(t, "asleep", "running")
	asleep, running := agents[0], agents[1]
	if err := s.BeginVolumeArchive(t.Context(), "local", asleep.AgentID, archiveID(1), true, nil, dailyArchives); !errors.Is(err, ErrArchiveNotDue) {
		t.Fatal("a VM that disagrees with the database was captured", err)
	}
	if err := s.BeginVolumeArchive(t.Context(), "local", running.AgentID, archiveID(1), true, nil, dailyArchives); !errors.Is(err, ErrArchiveNotDue) {
		t.Fatal("a running agent was stopped before Every", err)
	}
	if err := s.BeginVolumeArchive(t.Context(), "elsewhere", asleep.AgentID, archiveID(1), false, nil, dailyArchives); !errors.Is(err, ErrArchiveNotDue) {
		t.Fatal("another host captured the agent", err)
	}
	if err := s.BeginVolumeArchive(t.Context(), "local", asleep.AgentID, "arc_bad", false, nil, dailyArchives); !errors.Is(err, ErrInput) {
		t.Fatal("invalid archive ID accepted", err)
	}
	if err := s.BeginVolumeArchive(t.Context(), "local", asleep.AgentID, archiveID(1), false, nil, dailyArchives); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.PendingVolumeArchives(t.Context(), asleep.AgentID, "local"); err != nil || !slices.Equal(pending, []string{archiveID(1)}) {
		t.Fatal("begun capture not pending", pending, err)
	}
	if got := due(t, s, nil, 10); !slices.Equal(got, []string{asleep.AgentID}) {
		t.Fatal("a pending capture counted as an archive", got)
	}
	if err := s.CompleteVolumeArchive(t.Context(), archiveID(1), 256<<20, false); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteVolumeArchive(t.Context(), archiveID(1), 256<<20, false); err != nil {
		t.Fatal("a repeated completion failed", err)
	}
	if err := s.CompleteVolumeArchive(t.Context(), archiveID(1), 128<<20, false); !errors.Is(err, ErrArchiveRecord) {
		t.Fatal("a published archive changed size", err)
	}
	if err := s.CompleteVolumeArchive(t.Context(), archiveID(9), 128<<20, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("an unknown capture completed", err)
	}
	if err := s.AbandonVolumeArchive(t.Context(), archiveID(1)); err != nil {
		t.Fatal(err)
	}
	records, err := s.VolumeArchives(t.Context(), asleep.AgentID)
	if err != nil || len(records) != 1 || records[0].CapturedAt == nil || records[0].Size != 256<<20 || records[0].VolumeID != asleep.VolumeID ||
		records[0].Incarnation != 1 || records[0].HostID != "local" || records[0].CapturedAt.Before(records[0].StartedAt) {
		t.Fatal("a published archive was forgotten or misrecorded", records, err)
	}
	if got := due(t, s, nil, 10); len(got) != 0 {
		t.Fatal("an archived agent is still due", got)
	}
	// An overdue running agent, interrupted after publication: the next
	// capture adopts the archive as of the start of its capture.
	if err = s.BeginVolumeArchive(t.Context(), "local", running.AgentID, archiveID(2), true, later(25*time.Hour), dailyArchives); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteVolumeArchive(t.Context(), archiveID(2), 256<<20, true); err != nil {
		t.Fatal(err)
	}
	records, err = s.VolumeArchives(t.Context(), running.AgentID)
	if err != nil || len(records) != 1 || records[0].CapturedAt == nil || !records[0].CapturedAt.Equal(records[0].StartedAt) {
		t.Fatal("an adopted archive is not dated from the start of its capture", records, err)
	}
	// A capture that published nothing is forgotten.
	if err = s.BeginVolumeArchive(t.Context(), "local", asleep.AgentID, archiveID(3), false, later(23*time.Hour), dailyArchives); err != nil {
		t.Fatal(err)
	}
	if err = s.AbandonVolumeArchive(t.Context(), archiveID(3)); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.PendingVolumeArchives(t.Context(), asleep.AgentID, "local"); err != nil || len(pending) != 0 {
		t.Fatal("abandoned capture still pending", pending, err)
	}
	if _, err := s.pool.Exec(t.Context(), "INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,captured_at) VALUES($1,$2,'local',$3,1,clock_timestamp())",
		archiveID(4), asleep.AgentID, asleep.VolumeID); err == nil || !strings.Contains(err.Error(), "check") {
		t.Fatal("a record published without its size", err)
	}
}

// Retention keeps the newest archives of an agent and expires the others,
// oldest last; the newest is never expired, nor a pending capture, nor
// another agent's archive. Freshness reports the oldest newest archive.
func TestVolumeArchiveRetentionAndFreshness(t *testing.T) {
	s, agents := archiveAgents(t, "asleep", "asleep")
	a, b := agents[0].AgentID, agents[1].AgentID
	n, oldest, err := s.VolumeArchiveFreshness(t.Context(), "local")
	if err != nil || n != 2 || oldest <= 0 || oldest > time.Hour {
		t.Fatal("never-archived agents count from their initialization", n, oldest, err)
	}
	for i := 1; i <= 4; i++ {
		archived(t, s, a, false, archiveID(i), later(time.Duration(i)*23*time.Hour))
	}
	archived(t, s, b, false, archiveID(10), nil)
	if err := s.BeginVolumeArchive(t.Context(), "local", a, archiveID(5), false, later(5*23*time.Hour), dailyArchives); err != nil {
		t.Fatal(err)
	}
	for keep, want := range map[int][]string{
		1:  {archiveID(3), archiveID(2), archiveID(1)},
		3:  {archiveID(1)},
		4:  {},
		10: {},
	} {
		got, err := s.ExpiredVolumeArchives(t.Context(), a, "local", keep)
		if err != nil || !slices.Equal(got, want) {
			t.Fatal("retention selection", keep, got, want, err)
		}
	}
	if _, err := s.ExpiredVolumeArchives(t.Context(), a, "local", 0); !errors.Is(err, ErrInput) {
		t.Fatal("retention could expire every archive", err)
	}
	if got, err := s.ExpiredVolumeArchives(t.Context(), b, "local", 1); err != nil || len(got) != 0 {
		t.Fatal("an agent's only archive expired", got, err)
	}
	if got, err := s.ExpiredVolumeArchives(t.Context(), a, "elsewhere", 1); err != nil || len(got) != 0 {
		t.Fatal("another host's archives selected", got, err)
	}
	for _, id := range []string{archiveID(1), archiveID(1)} {
		if err := s.RemovedVolumeArchive(t.Context(), id); err != nil {
			t.Fatal("removal not recorded, or not repeatable", err)
		}
	}
	if err := s.RemovedVolumeArchive(t.Context(), archiveID(5)); !errors.Is(err, ErrNotFound) {
		t.Fatal("a pending capture recorded as removed", err)
	}
	if got, err := s.ExpiredVolumeArchives(t.Context(), a, "local", 1); err != nil || !slices.Equal(got, []string{archiveID(3), archiveID(2)}) {
		t.Fatal("a removed archive selected again", got, err)
	}
	n, oldest, err = s.VolumeArchiveFreshness(t.Context(), "local")
	if err != nil || n != 2 || oldest <= 0 || oldest > time.Hour {
		t.Fatal("freshness after captures", n, oldest, err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE volume_archives SET captured_at=captured_at-interval '30 hours',started_at=started_at-interval '30 hours' WHERE agent_id=$1", b); err != nil {
		t.Fatal(err)
	}
	if n, oldest, err = s.VolumeArchiveFreshness(t.Context(), "local"); err != nil || n != 2 || oldest < 30*time.Hour || oldest > 31*time.Hour {
		t.Fatal("freshness reports the oldest newest archive", n, oldest, err)
	}
	if n, oldest, err = s.VolumeArchiveFreshness(t.Context(), "elsewhere"); err != nil || n != 0 || oldest != 0 {
		t.Fatal("a host without agents", n, oldest, err)
	}
}
