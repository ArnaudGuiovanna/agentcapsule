//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// invoke posts bob's text to the agent; whoever runs dispatch delivers it.
func (l *registryLab) invoke(agentID, key, text string) string {
	l.t.Helper()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agentID+"/invocations", key, map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}}}, 202, &inv)
	return inv.ID
}

// answered reports whether the invocation completed, and with text.
func (l *registryLab) answered(id, text string) bool {
	l.t.Helper()
	var v controlplane.Invocation
	l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
	if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
		l.t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
	}
	if v.State != "completed" {
		return false
	}
	if result := string(l.request(l.user(), "GET", "/v1/invocations/"+id+"/result", "", nil, 200, nil)); !strings.Contains(result, text) {
		l.t.Fatal("unexpected answer")
	}
	return true
}

// archived returns the agent's published archives that retention kept.
func (l *registryLab) archived(agentID string) []controlplane.VolumeArchive {
	l.t.Helper()
	records, err := l.store.VolumeArchives(l.t.Context(), agentID)
	if err != nil {
		l.t.Fatal(err)
	}
	kept := []controlplane.VolumeArchive{}
	for _, r := range records {
		if r.CapturedAt != nil && r.RemovedAt == nil {
			kept = append(kept, r)
		}
	}
	return kept
}

// verifyArchive authenticates and hashes the archive with the restore
// authority, and checks it is the agent's encrypted container.
func (l *registryLab) verifyArchive(archives *volumearchive.Store, r controlplane.VolumeArchive, agentID string) {
	l.t.Helper()
	e, err := l.store.VolumeEnrollment(l.t.Context(), agentID, "local")
	if err != nil {
		l.t.Fatal(err)
	}
	file, m, err := archives.Open(l.t.Context(), r.ID, l.worker.authority)
	if err != nil {
		l.t.Fatal("archive authentication/hash", err)
	}
	var magic [6]byte
	_, err = io.ReadFull(file, magic[:])
	file.Close()
	if err != nil || !bytes.Equal(magic[:], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) {
		l.t.Fatal("archive is not the encrypted container", err)
	}
	if m.Binding.Store != agentID || m.Binding.Volume != e.VolumeID || m.Binding.Incarnation != e.Incarnation ||
		r.VolumeID != e.VolumeID || r.Incarnation != e.Incarnation || m.Size != r.Size || m.Size != 128<<20 {
		l.t.Fatal("archive identity does not match the agent's volume", m.Binding, r)
	}
}

// The maintenance worker archives agents' encrypted volumes itself, without
// being stopped (REC-02, ADR 004). A sleeping agent is captured by the
// running maintenance loop while that loop keeps delivering to another
// agent, whose VM is not interrupted; the archive verifies with the restore
// authority and is recorded in PostgreSQL. Seen a day later, a running agent
// that never slept is overdue: the pass stops it for its archive, retention
// keeps one archive per agent, and the agent wakes on its next invocation.
func TestProductWorkerNightlyVolumeArchives(t *testing.T) {
	l := newRegistryLab(t)
	l.publish("1.0.0", "opt/echo")
	sleeper := l.create("archive-asleep", "1.0.0").AgentID
	busy := l.create("archive-busy", "1.0.0").AgentID
	l.answers(sleeper, "before-archive", "written before the archive")
	l.lifecycle(sleeper, "sleep", "sleep-before-archive")
	var unclean bool
	if err := l.db.QueryRow(t.Context(), "SELECT unclean_stop FROM agent_placements WHERE agent_id=$1", sleeper).Scan(&unclean); err != nil || unclean {
		t.Fatal("the sleeping agent did not stop cleanly: a capture would refuse it", err)
	}
	before := l.runs(1)
	busyRun, ok := before[busy]
	if !ok {
		t.Fatal("the busy agent does not run")
	}
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []ArchiveReport
	report := func() []ArchiveReport {
		mu.Lock()
		defer mu.Unlock()
		return append([]ArchiveReport(nil), reports...)
	}
	a := &Archives{Store: archives, Every: 24 * time.Hour, SleepWindow: 2 * time.Hour, Keep: 1, PerPass: 1, Timeout: 5 * time.Minute,
		Report: func(r ArchiveReport) { mu.Lock(); reports = append(reports, r); mu.Unlock() }}

	t.Log("stage: the maintenance loop archives the sleeping agent and keeps delivering to the running one")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- l.worker.RunMaintenance(ctx, MaintenanceOptions{Interval: 200 * time.Millisecond, AttemptTimeout: 90 * time.Second, Archives: a,
			Dispatch: &DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}})
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Error("maintenance stopped", err)
			}
		})
	}
	t.Cleanup(stop)
	first := l.invoke(busy, "during-archive", "delivered while archiving")
	l.await("archive of the sleeping agent and delivery to the running one", false, func() bool {
		return l.answered(first, "delivered while archiving") && len(l.archived(sleeper)) == 1
	})
	second := l.invoke(busy, "after-archive", "delivered after archiving")
	l.await("delivery after the capture", false, func() bool { return l.answered(second, "delivered after archiving") })
	stop()
	got := report()
	if len(got) != 1 || got[0].Err != nil || got[0].Running || got[0].Size != 128<<20 || got[0].Removed != 0 {
		t.Fatal("one capture of the sleeping agent expected", got)
	}
	kept := l.archived(sleeper)
	l.verifyArchive(archives, kept[0], sleeper)
	after := l.runs(1)
	if run, ok := after[busy]; !ok || run.ID != busyRun.ID || run.Generation != busyRun.Generation {
		t.Fatal("the running agent was interrupted")
	}
	if records := l.archived(busy); len(records) != 0 {
		t.Fatal("a running agent was captured before it was due", records)
	}
	if entries, err := os.ReadDir(archives.Root()); err != nil || len(entries) != 1 || entries[0].Name() != kept[0].ID {
		t.Fatal("the archive root holds more than the published archive", err)
	}

	t.Log("stage: a day later, the running agent is overdue: it is stopped for its archive, then wakes on its next invocation")
	a.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	a.PerPass = 2 // the sleeping agent, due again, comes first
	if err = l.worker.ArchivePass(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	got = report()
	if len(got) != 3 || got[1].Err != nil || got[1].Running || got[1].Removed != 1 || got[2].Err != nil || !got[2].Running || got[2].Removed != 0 {
		t.Fatal("the sleeping agent then the overdue running agent expected", got)
	}
	l.runs(0)
	busyKept := l.archived(busy)
	if len(busyKept) != 1 {
		t.Fatal("the overdue running agent was not archived", busyKept)
	}
	l.verifyArchive(archives, busyKept[0], busy)
	if busyKept[0].Incarnation != busyRun.Incarnation {
		t.Fatal("the archive is not of the volume the VM ran")
	}
	sleeperKept := l.archived(sleeper)
	if len(sleeperKept) != 1 || sleeperKept[0].ID == kept[0].ID {
		t.Fatal("retention did not keep exactly the newest archive", sleeperKept)
	}
	if _, err = archives.Manifest(kept[0].ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the older archive is still on disk", err)
	}
	l.verifyArchive(archives, sleeperKept[0], sleeper)
	l.answers(busy, "woken-after-archive", "awake again after the archive")
	if run, ok := l.runs(1)[busy]; !ok || run.Generation <= busyRun.Generation {
		t.Fatal("the archived agent did not wake on its next invocation")
	}
	l.answers(sleeper, "sleeper-after-archive", "the sleeper answers too")
}
