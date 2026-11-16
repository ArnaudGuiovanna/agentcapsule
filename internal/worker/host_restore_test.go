//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// addAgent creates another agent on the restore lab's host, as the lab
// creates its own: a new owner and a reservation, then, when provisioned, a
// volume (its inode given), an initialized first boot, a LIVE agent, its
// key and its store in the authorities.
func (l *restoreLab) addAgent(name string, provisioned bool, inode uint64) controlplane.Enrollment {
	t := l.t
	t.Helper()
	r, err := l.accounts.CreateUser(t.Context(), l.admin, "owner-"+name, controlplane.CreateUserInput{DisplayName: name})
	if err != nil {
		t.Fatal(err)
	}
	var owner controlplane.User
	if err = json.Unmarshal(r.Body, &owner); err != nil {
		t.Fatal(err)
	}
	if r, err = l.catalog.Reserve(t.Context(), l.admin, "agent-"+name, controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: name,
		Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: restoreVolumeSize >> 20}}); err != nil {
		t.Fatal(err)
	}
	var created controlplane.AgentCreation
	if err = json.Unmarshal(r.Body, &created); err != nil {
		t.Fatal(err)
	}
	jobs, err := l.store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(jobs, func(e controlplane.Enrollment) bool { return e.AgentID == created.AgentID })
	if i < 0 {
		t.Fatal("no provisioning of", name)
	}
	e := jobs[i]
	if !provisioned {
		return e
	}
	if err = l.store.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: inode}); err != nil {
		t.Fatal(err)
	}
	fence, err := l.store.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", fence.Generation)
	if err = l.store.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", fence.Generation, vm); err != nil {
		t.Fatal(err)
	}
	if err = l.store.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: fence.Generation, VMID: vm}); err != nil {
		t.Fatal(err)
	}
	if err = l.store.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, fence.Generation); err != nil {
		t.Fatal(err)
	}
	if err = l.store.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, fence.Generation, false); err != nil {
		t.Fatal(err)
	}
	if err = l.store.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if err = l.keys.Ensure(t.Context(), e.AgentID, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.authority.Register(t.Context(), e.AgentID, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	l.registered["local/"+e.AgentID] = true
	return e
}

// captureOf archives an empty volume of another agent, signed by the
// restore authority, into the lab's archive root.
func (l *restoreLab) captureOf(e controlplane.Enrollment, id string) restoreauthority.Archive {
	l.t.Helper()
	a, err := l.archives.Capture(l.t.Context(), volumearchive.Spec{ID: id, Binding: restoreauthority.Binding{Store: e.AgentID, Volume: e.VolumeID, Incarnation: 1},
		HarnessDigest: "sha256:" + strings.Repeat("a", 64), Size: restoreVolumeSize}, bytes.NewReader(make([]byte, restoreVolumeSize)), l.authority)
	if err != nil {
		l.t.Fatal(err)
	}
	return a
}

// recordArchive records a nightly capture of the agent on the lost host,
// published age ago (a PostgreSQL interval).
func (l *restoreLab) recordArchive(e controlplane.Enrollment, id, age string) {
	l.t.Helper()
	if _, err := l.db.Exec(l.t.Context(), `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,size)
        VALUES($1,$2,'local',$3,1,now()-$4::interval-interval '1 minute',now()-$4::interval,$5)`, id, e.AgentID, e.VolumeID, age, restoreVolumeSize); err != nil {
		l.t.Fatal(err)
	}
}

// offHostStores stands for the standby's disk and S3: a directory each,
// holding archives as the archive root does. fetch copies one into root.
type offHostStores map[string]string

func (s offHostStores) fetch(root string) ArchiveFetcher {
	return func(_ context.Context, store, id string) error {
		src := filepath.Join(s[store], id)
		if _, err := os.Stat(filepath.Join(src, "manifest.json")); err != nil {
			return fmt.Errorf("%s holds no complete copy of %s", store, id)
		}
		dst := filepath.Join(root, id)
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		for _, name := range []string{"volume.luks", "manifest.json"} {
			data, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(dst, name), data, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
}

// The host is lost; the standby took it over and restores its agents from
// the copies of their archives (ADR 020). Each agent moves to the standby as
// its restore begins, from the newest archive a store holds: the standby's
// copy, or S3's when the standby's is missing or does not verify. Its volume
// is created on the new host before the install, and its losses after the
// archive are declared, as on its own host. An agent without an archive, or
// still provisioning, is reported and stays on the lost host. The report
// follows the archives' order; the same command resumes an unfinished
// restore first, with its restore ID, and reports a finished one again
// without restoring it twice.
func TestRestoreHostMovesTheLostHostsAgentsHere(t *testing.T) {
	forEachAuthority(t, testRestoreHostMovesTheLostHostsAgentsHere)
}

func testRestoreHostMovesTheLostHostsAgentsHere(t *testing.T, implementation string) {
	l := newRestoreLab(t, implementation)
	kept := l.deliver("before-archive")
	archiveA := l.capture("arc_" + strings.Repeat("a", 32))
	lost := l.deliver("after-archive-1", "after-archive-2")
	l.recordArchive(l.e, archiveA.ID, "3 hours")
	b := l.addAgent("b", true, 101)
	archiveB := l.captureOf(b, "arc_"+strings.Repeat("b", 32))
	l.recordArchive(b, archiveB.ID, "5 hours")
	c := l.addAgent("c", true, 102)
	l.recordArchive(c, "arc_"+strings.Repeat("c", 32), "1 hour") // shipped nowhere
	d := l.addAgent("d", true, 103)                              // never archived
	p := l.addAgent("p", false, 0)                               // still provisioning

	t.Log("stage: the host is lost; its archives are on the stores only, the standby's copy of A damaged")
	stores := offHostStores{"standby": t.TempDir(), "s3": t.TempDir()}
	for _, id := range []string{archiveA.ID, archiveB.ID} {
		if err := os.Rename(filepath.Join(l.archives.Root(), id), filepath.Join(stores["s3"], id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.CopyFS(filepath.Join(stores["standby"], archiveA.ID), os.DirFS(filepath.Join(stores["s3"], archiveA.ID))); err != nil {
		t.Fatal(err)
	}
	damaged := filepath.Join(stores["standby"], archiveA.ID, "volume.luks")
	data, err := os.ReadFile(damaged)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err = os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "standby-archives"))
	if err != nil {
		t.Fatal(err)
	}
	l.archives = archives
	l.w = &Placements{store: l.store, hostID: "standby", workerID: "standby-restorer", lease: time.Minute, authority: l.w.authority}
	if l.opts, err = l.w.runtimeOptions(runtime.FirecrackerOptions{AuthenticatedControl: true}, l.keys); err != nil {
		t.Fatal(err)
	}
	fetch := stores.fetch(archives.Root())
	var reported []HostRestoreItem
	report := func(item HostRestoreItem) { reported = append(reported, item) }
	if _, err = l.w.RestoreHost(t.Context(), "local", archives, fetch, nil, report); !errors.Is(err, ErrNotTakenOver) {
		t.Fatal("a restore of a host that was not taken over", err)
	}
	if _, _, err = l.store.TakeOverHost(t.Context(), controlplane.OperatorCommand{Actor: "local-uid:0"}, "local", "standby"); err != nil {
		t.Fatal(err)
	}

	// B's restore stops once after it began, like a crash; A's is real.
	var restoreB string
	var order []string
	l.w.hostRestore = func(ctx context.Context, restoreID, agentID, archiveID string, archives *volumearchive.Store, paused func(error)) (VolumeRestoreResult, error) {
		order = append(order, agentID)
		if agentID != b.AgentID {
			return l.w.restorePausing(ctx, l.host(), restoreID, agentID, archiveID, archives, func(err error) { t.Error("paused", err) })
		}
		if restoreB == "" {
			restoreB = restoreID
			if _, err := l.store.BeginVolumeRestore(ctx, restoreID, agentID, "standby", archiveID); err != nil {
				return VolumeRestoreResult{}, err
			}
			return VolumeRestoreResult{}, errors.New("stopped like a crash")
		}
		if restoreID != restoreB || archiveID != archiveB.ID {
			t.Error("B's restore did not resume", restoreID, archiveID)
		}
		return VolumeRestoreResult{RestoreID: restoreID, AgentID: agentID, ArchiveID: archiveID, Incarnation: 2}, nil
	}

	t.Log("stage: the first run")
	items, err := l.w.RestoreHost(t.Context(), "local", archives, fetch, nil, report)
	if err != nil {
		t.Fatal(err)
	}
	byAgent := map[string]HostRestoreItem{}
	ids := []string{}
	for _, item := range items {
		byAgent[item.AgentID] = item
		ids = append(ids, item.AgentID)
	}
	noArchive := []string{d.AgentID, p.AgentID}
	slices.Sort(noArchive)
	if want := append([]string{b.AgentID, l.e.AgentID, c.AgentID}, noArchive...); !slices.Equal(ids, want) || !slices.Equal(reported, items) {
		t.Fatal("the order of the report", ids, want)
	}
	if !slices.Equal(order, []string{b.AgentID, l.e.AgentID}) {
		t.Fatal("restores run", order)
	}
	if got := byAgent[b.AgentID]; got.Result != "failed" || got.Reason != "error" || got.RestoreID != HostRestoreID("local", b.AgentID, archiveB.ID) ||
		got.ArchiveStore != "s3" {
		t.Fatal("B after a crash", got)
	}
	got := byAgent[l.e.AgentID]
	if got.Result != "restored" || got.ArchiveID != archiveA.ID || got.ArchiveStore != "s3" || got.Incarnation != 2 || got.Losses != 2 || got.Unmatched != 2 ||
		got.RestoreID != HostRestoreID("local", l.e.AgentID, archiveA.ID) {
		t.Fatal("A", got)
	}
	if got := byAgent[c.AgentID]; got.Result != "failed" || got.Reason != "archive_unavailable" {
		t.Fatal("C, whose archive no store holds", got)
	}
	if got := byAgent[d.AgentID]; got.Result != "skipped" || got.Reason != "no_archive" {
		t.Fatal("D, never archived", got)
	}
	if got := byAgent[p.AgentID]; got.Result != "skipped" || got.Reason != "provisioning" {
		t.Fatal("P, still provisioning", got)
	}

	t.Log("stage: A is on the standby, in a volume created there, with the losses after its archive declared")
	if l.relocations != 1 || l.installs != 1 || l.installedOn != [2]uint64{2, 200} {
		t.Fatal("the new host's volume", l.relocations, l.installs, l.installedOn)
	}
	e := l.enrollment()
	if e.HostID != "standby" || e.Stage != "READY" || e.Incarnation != 2 || !e.Initialized {
		t.Fatal("A's volume after the restore", e)
	}
	if pl, err := l.w.placement(t.Context(), l.e.AgentID); err != nil || pl.State != "STOPPED" {
		t.Fatal("A's placement", pl, err)
	}
	losses, err := l.authority.Losses(t.Context(), l.e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	declared := []string{}
	for _, loss := range losses {
		if loss.Incarnation == 2 {
			declared = append(declared, loss.ID)
		}
	}
	slices.Sort(declared)
	if want := slices.Sorted(slices.Values(lost)); !slices.Equal(declared, want) {
		t.Fatal("A's declared losses", declared, want)
	}
	if held := l.heldOutcomes(kept); len(held) != 1 {
		t.Fatal("the outcome before the archive is not in the restored volume", held)
	}
	if _, err = os.Stat(filepath.Join(archives.Root(), archiveA.ID)); err != nil {
		t.Fatal("the verified copy is not in the archive root", err)
	}
	agents, err := l.store.LostHostAgents(t.Context(), "local")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		want := "local"
		if a.AgentID == l.e.AgentID || a.AgentID == b.AgentID {
			want = "standby"
		}
		if a.HostID != want {
			t.Fatal("where an agent of the lost host is", a.AgentID, a.HostID, want)
		}
	}

	t.Log("stage: the same command again")
	order, reported = nil, nil
	items, err = l.w.RestoreHost(t.Context(), "local", archives, fetch, nil, report)
	if err != nil {
		t.Fatal(err)
	}
	ids = ids[:0]
	for _, item := range items {
		byAgent[item.AgentID] = item
		ids = append(ids, item.AgentID)
	}
	if want := append([]string{b.AgentID, l.e.AgentID, c.AgentID}, noArchive...); !slices.Equal(ids, want) {
		t.Fatal("the order of the second report", ids, want)
	}
	if !slices.Equal(order, []string{b.AgentID}) || l.installs != 1 || l.relocations != 1 {
		t.Fatal("restored twice", order, l.installs, l.relocations)
	}
	if got := byAgent[b.AgentID]; got.Result != "restored" || got.RestoreID != restoreB || got.ArchiveStore != "local" {
		t.Fatal("B resumed", got)
	}
	if again := byAgent[l.e.AgentID]; again.Result != "restored" || again.RestoreID != got.RestoreID || again.Incarnation != 2 || again.Losses != 2 {
		t.Fatal("A reported again", again)
	}
}

// A fetched copy is used only once the restore authority and its manifest
// verify it: a copy that does not is removed, and the next store is tried.
// An archive of a sealed store (a deleted agent) ends the fetch.
func TestFetchArchiveVerifiesEachCopy(t *testing.T) {
	l := newRestoreLab(t, inProcess)
	archive := l.capture("arc_" + strings.Repeat("e", 32))
	stores := offHostStores{"standby": t.TempDir(), "s3": t.TempDir()}
	if err := os.Rename(filepath.Join(l.archives.Root(), archive.ID), filepath.Join(stores["standby"], archive.ID)); err != nil {
		t.Fatal(err)
	}
	if store, err := l.w.FetchArchive(t.Context(), l.archives, nil, archive.ID, nil); !errors.Is(err, ErrArchiveUnavailable) || store != "" {
		t.Fatal("a fetch without stores", store, err)
	}
	fetch := stores.fetch(l.archives.Root())
	if store, err := l.w.FetchArchive(t.Context(), l.archives, fetch, archive.ID, nil); err != nil || store != "standby" {
		t.Fatal("fetch from the standby", store, err)
	}
	if store, err := l.w.FetchArchive(t.Context(), l.archives, fetch, archive.ID, nil); err != nil || store != "local" {
		t.Fatal("an archive already in the root", store, err)
	}
	// A manifest altered on its way: not signed, removed, and no other copy.
	if err := l.archives.Remove(archive.ID); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(stores["standby"], archive.ID, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var altered restoreauthority.Archive
	if err = json.Unmarshal(raw, &altered); err != nil {
		t.Fatal(err)
	}
	altered.HarnessDigest = "sha256:" + strings.Repeat("b", 64)
	if raw, err = json.Marshal(altered); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = l.w.FetchArchive(t.Context(), l.archives, fetch, archive.ID, nil); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("an altered manifest", err)
	}
	if _, err = l.archives.Manifest(archive.ID); err == nil {
		t.Fatal("a copy that did not verify stayed in the archive root")
	}
}
