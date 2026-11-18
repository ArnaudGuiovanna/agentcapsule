//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

type fencedAtOnce struct{}

func (fencedAtOnce) Fence(context.Context, string, string) error { return nil }

// deleteAgent plays an agent's deletion up to its final receipt, which the
// worker records only once the agent's volume key is destroyed
// (RemoveDeletedStore): every store fences the agent's subject, the host
// seals it, then its volume and key are gone. No VM runs.
func (l *archiveLab) deleteAgent(t *testing.T, e controlplane.Enrollment) {
	t.Helper()
	seal := l.sealDeletedAgent(t, e)
	if err := l.store.RecordStoreRemoval(t.Context(), seal, e.VolumeID); err != nil {
		t.Fatal(err)
	}
}

// sealDeletedAgent plays a deletion up to the host's seal: the volume and its
// key are still there.
func (l *archiveLab) sealDeletedAgent(t *testing.T, e controlplane.Enrollment) controlplane.StoreSeal {
	t.Helper()
	var owner, device, inode string
	if err := l.db.QueryRow(t.Context(), "SELECT owner_user_id FROM agents WHERE id=$1", e.AgentID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := l.db.QueryRow(t.Context(), "SELECT volume_device,volume_inode FROM store_enrollments WHERE agent_id=$1", e.AgentID).Scan(&device, &inode); err != nil {
		t.Fatal(err)
	}
	if err := l.store.RequestDeletion(t.Context(), owner, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err := l.store.ReconcileRevocation(t.Context(), e.AgentID, fencedAtOnce{}); err != nil {
		t.Fatal(err)
	}
	p, ready, err := l.store.StoreSealTarget(t.Context(), e.AgentID, e.HostID)
	if err != nil || !ready {
		t.Fatal("deletion barrier", ready, err)
	}
	seal := controlplane.StoreSeal{AgentID: e.AgentID, HostID: e.HostID, ID: strings.Repeat("1", 32), Generation: p.Generation}
	if seal.Device, err = strconv.ParseUint(device, 16, 64); err != nil {
		t.Fatal(err)
	}
	if seal.Inode, err = strconv.ParseUint(inode, 16, 64); err != nil {
		t.Fatal(err)
	}
	if err = l.store.RecordStoreSeal(t.Context(), seal); err != nil {
		t.Fatal(err)
	}
	return seal
}

func (l *archiveLab) onDisk(t *testing.T) []string {
	t.Helper()
	ids, err := l.archives.List()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func (l *archiveLab) records(t *testing.T, agentID string) map[string]controlplane.VolumeArchive {
	t.Helper()
	list, err := l.store.VolumeArchives(t.Context(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]controlplane.VolumeArchive{}
	for _, r := range list {
		byID[r.ID] = r
	}
	return byID
}

// Once a deleted agent's volume key is destroyed, its archives no longer open
// anywhere. The worker then deletes those of its host: recorded or taken on
// demand, settled or not. It never touches the archives of a live agent, and
// does nothing before the key is destroyed.
func TestDeletedAgentArchivesArePurged(t *testing.T) {
	l := newArchiveLab(t, "asleep", "asleep")
	gone, kept := l.agents[0], l.agents[1]
	a := l.options(t)
	policy := a.policy()
	id := func(n int) string { return fmt.Sprintf("arc_%032x", n) }
	// The deleted agent: a settled archive (1), a published capture that a
	// crash left unsettled (2), a capture that published nothing (3), an
	// archive taken on demand (4). The live agent: a settled archive (5), one
	// taken on demand (6).
	for _, n := range []int{1, 2, 3} {
		if err := l.store.BeginVolumeArchive(t.Context(), "local", gone.AgentID, id(n), false, nil, policy); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.store.BeginVolumeArchive(t.Context(), "local", kept.AgentID, id(5), false, nil, policy); err != nil {
		t.Fatal(err)
	}
	for n, e := range map[int]controlplane.Enrollment{1: gone, 2: gone, 4: gone, 5: kept, 6: kept} {
		l.publish(t, e, id(n))
	}
	for _, n := range []int{1, 5} {
		if err := l.store.CompleteVolumeArchive(t.Context(), id(n), 4096, false); err != nil {
			t.Fatal(err)
		}
	}
	all := []string{id(1), id(2), id(4), id(5), id(6)}
	if n, err := l.w.purgeDeletedArchives(t.Context(), l.archives); err != nil || n != 0 || !slices.Equal(l.onDisk(t), all) {
		t.Fatal("archives purged before any deletion", n, err, l.onDisk(t))
	}
	// Deletion requested, key not destroyed yet: nothing goes.
	var owner string
	if err := l.db.QueryRow(t.Context(), "SELECT owner_user_id FROM agents WHERE id=$1", gone.AgentID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := l.store.RequestDeletion(t.Context(), owner, gone.AgentID); err != nil {
		t.Fatal(err)
	}
	if n, err := l.w.purgeDeletedArchives(t.Context(), l.archives); err != nil || n != 0 || !slices.Equal(l.onDisk(t), all) {
		t.Fatal("archives purged before the key was destroyed", n, err, l.onDisk(t))
	}
	l.deleteAgent(t, gone)
	n, err := l.w.purgeDeletedArchives(t.Context(), l.archives)
	if err != nil || n != 3 || !slices.Equal(l.onDisk(t), []string{id(5), id(6)}) {
		t.Fatal("purge", n, err, l.onDisk(t))
	}
	records := l.records(t, gone.AgentID)
	if len(records) != 2 {
		t.Fatal("the capture that published nothing is still recorded", records)
	}
	for _, n := range []int{1, 2} {
		r := records[id(n)]
		if r.CapturedAt == nil || r.Size != 4096 || r.RemovedAt == nil {
			t.Fatal("a purged archive is not recorded removed", n, r)
		}
	}
	if r := records[id(2)]; !r.CapturedAt.Equal(r.StartedAt) {
		t.Fatal("an unsettled archive is not adopted as of its start", r)
	}
	if r := l.records(t, kept.AgentID)[id(5)]; r.RemovedAt != nil {
		t.Fatal("a live agent's archive is recorded removed", r)
	}
	// Recording a purge never marks a live agent's archive.
	if err = l.store.PurgedVolumeArchive(t.Context(), id(5), 4096); err != nil {
		t.Fatal(err)
	}
	if r := l.records(t, kept.AgentID)[id(5)]; r.RemovedAt != nil {
		t.Fatal("a purge was recorded for a live agent's archive", r)
	}
	// A crash after a removal on disk, before its record: the next purge
	// records it.
	if _, err = l.db.Exec(t.Context(), `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,captured_at,size)
        VALUES($1,$2,'local',$3,1,clock_timestamp(),4096)`, id(7), gone.AgentID, gone.VolumeID); err != nil {
		t.Fatal(err)
	}
	if n, err = l.w.purgeDeletedArchives(t.Context(), l.archives); err != nil || n != 0 {
		t.Fatal("second purge", n, err)
	}
	if r := l.records(t, gone.AgentID)[id(7)]; r.RemovedAt == nil {
		t.Fatal("a removal left unrecorded by a crash is not recorded", r)
	}
	if !slices.Equal(l.onDisk(t), []string{id(5), id(6)}) {
		t.Fatal("a second purge removed a live agent's archive", l.onDisk(t))
	}
}

// The archive pass purges at its first pass, then once an hour, and reports
// what it removed.
func TestArchivePassPurgesDeletedAgentsHourly(t *testing.T) {
	l := newArchiveLab(t, "asleep")
	gone := l.agents[0]
	a := l.options(t)
	var purged []int
	a.Purged = func(removed int, err error) {
		if err != nil {
			t.Error(err)
		}
		purged = append(purged, removed)
	}
	id := func(n int) string { return fmt.Sprintf("arc_%032x", n) }
	l.publish(t, gone, id(1))
	l.deleteAgent(t, gone)
	if err := l.w.ArchivePass(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(purged, []int{1}) || len(l.onDisk(t)) != 0 {
		t.Fatal("the first pass did not purge", purged, l.onDisk(t))
	}
	l.publish(t, gone, id(2))
	if err := l.w.ArchivePass(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(purged, []int{1}) || !slices.Equal(l.onDisk(t), []string{id(2)}) {
		t.Fatal("a pass within the hour purged again", purged, l.onDisk(t))
	}
	a.purged = time.Now().Add(-time.Hour)
	if err := l.w.ArchivePass(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(purged, []int{1, 1}) || len(l.onDisk(t)) != 0 {
		t.Fatal("the pass an hour later did not purge", purged, l.onDisk(t))
	}
	if _, err := l.archives.Manifest(id(2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
