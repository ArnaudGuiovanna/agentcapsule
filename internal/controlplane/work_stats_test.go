package controlplane

import (
	"testing"
	"time"
)

// The host's queue, as metrics read it: jobs by kind, those due and not held,
// those failing, how long the oldest due job has waited past its time, and
// the running VMs. Counts only.
func TestWorkQueueStatisticsForMetrics(t *testing.T) {
	s, _ := freshStore(t, "auto", 5)
	workPlacements(t, s)
	if _, err := s.Submit(t.Context(), "a", "to-b", submission()); err != nil {
		t.Fatal(err)
	}
	c := submission()
	c.RecipientAgentID = "c"
	if _, err := s.Submit(t.Context(), "a", "to-c", c); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscoverWork(t.Context(), "host", 10); err != nil {
		t.Fatal(err)
	}
	stats, err := s.WorkQueue(t.Context(), "host")
	if err != nil || len(stats) != 1 || stats[0].Kind != "delivery" || stats[0].Jobs != 2 || stats[0].Due != 2 || stats[0].Failing != 0 {
		t.Fatal("queue", stats, err)
	}
	// One job is held by a worker; the other has waited 90 s past its time and
	// failed three times.
	held, err := s.ClaimWork(t.Context(), "host", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `UPDATE worker_jobs SET available_at=clock_timestamp()-interval '90 seconds', failures=3
        WHERE host_id='host' AND object_id<>$1`, held.ID); err != nil {
		t.Fatal(err)
	}
	stats, err = s.WorkQueue(t.Context(), "host")
	if err != nil || len(stats) != 1 || stats[0].Jobs != 2 || stats[0].Due != 1 || stats[0].Failing != 1 ||
		stats[0].OldestDue < 89*time.Second || stats[0].OldestDue > 5*time.Minute {
		t.Fatal("queue after a claim", stats, err)
	}
	// A job waiting for its retry is not late.
	if _, err = s.pool.Exec(t.Context(), `UPDATE worker_jobs SET available_at=clock_timestamp()+interval '1 minute' WHERE host_id='host' AND object_id<>$1`, held.ID); err != nil {
		t.Fatal(err)
	}
	if stats, err = s.WorkQueue(t.Context(), "host"); err != nil || stats[0].Due != 0 || stats[0].OldestDue != 0 {
		t.Fatal("a backoff counted as delay", stats, err)
	}
	if foreign, err := s.WorkQueue(t.Context(), "foreign"); err != nil || len(foreign) != 0 {
		t.Fatal("another host's queue", foreign, err)
	}
	if n, err := s.RunningPlacements(t.Context(), "host"); err != nil || n != 0 {
		t.Fatal("running", n, err)
	}
	p, err := s.ClaimPlacement(t.Context(), "b", "host", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(t.Context(), "b", "host", "worker", p.Generation, "0000000000000001"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RunningPlacements(t.Context(), "host"); err != nil || n != 1 {
		t.Fatal("running", n, err)
	}
}
