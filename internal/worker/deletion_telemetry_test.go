//go:build linux && cgo

package worker

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Until an agent's deletion finishes, its volume key exists and its archives
// still open (ADR 018). The worker counts the unfinished deletions of its host
// and gives the age of the oldest, read from PostgreSQL at each scrape. With a
// key authority, a deletion finishes once the key and the volume are destroyed;
// on a host without one, once the execution is sealed.
func TestUnfinishedDeletionsAreMeasured(t *testing.T) {
	l := newArchiveLab(t, "asleep", "asleep")
	gone := l.agents[0] // the other one stays live
	registry := telemetry.NewRegistry()
	if err := l.w.EnableDeletionTelemetry(nil); err == nil {
		t.Fatal("no registry accepted")
	}
	if err := l.w.EnableDeletionTelemetry(registry); err != nil {
		t.Fatal(err)
	}
	scrape := func() string {
		t.Helper()
		r := httptest.NewRecorder()
		registry.Handler(5*time.Second).ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
		return r.Body.String()
	}
	if out := scrape(); !strings.Contains(out, "agentcapsule_worker_deletions_unfinished 0\n") || !strings.Contains(out, "agentcapsule_worker_deletion_oldest_seconds 0\n") {
		t.Fatal("no deletion", out)
	}
	var owner string
	if err := l.db.QueryRow(t.Context(), "SELECT owner_user_id FROM agents WHERE id=$1", gone.AgentID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := l.store.RequestDeletion(t.Context(), owner, gone.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(t.Context(), "UPDATE deletion_operations SET requested_at=clock_timestamp()-interval '7 hours' WHERE agent_id=$1", gone.AgentID); err != nil {
		t.Fatal(err)
	}
	out := scrape()
	if !strings.Contains(out, "agentcapsule_worker_deletions_unfinished 1\n") || !strings.Contains(out, "agentcapsule_worker_deletion_oldest_seconds 252") {
		t.Fatal("a deletion requested 7 hours ago", out)
	}
	// Sealed, the volume and the key are still there.
	seal := l.sealDeletedAgent(t, gone)
	for sealOnly, want := range map[bool]int{false: 1, true: 0} {
		n, age, err := l.store.UnfinishedDeletions(t.Context(), "local", sealOnly)
		if err != nil || n != want || (want == 1) != (age > 7*time.Hour) {
			t.Fatal("a sealed deletion", sealOnly, n, age, err)
		}
	}
	if n, _, err := l.store.UnfinishedDeletions(t.Context(), "elsewhere", false); err != nil || n != 0 {
		t.Fatal("another host's deletion counted", n, err)
	}
	if err := l.store.RecordStoreRemoval(t.Context(), seal, gone.VolumeID); err != nil {
		t.Fatal(err)
	}
	if n, age, err := l.store.UnfinishedDeletions(t.Context(), "local", false); err != nil || n != 0 || age != 0 {
		t.Fatal("a finished deletion", n, age, err)
	}
	if out = scrape(); !strings.Contains(out, "agentcapsule_worker_deletions_unfinished 0\n") {
		t.Fatal("a finished deletion is still counted", out)
	}
}
