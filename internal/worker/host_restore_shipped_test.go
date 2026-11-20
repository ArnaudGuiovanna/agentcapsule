//go:build linux && cgo

package worker

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// shippedStores is what scripts/verify-archive-shipping.py gives this test
// with --restore-from-copies: the archive shipper, rclone, and the host's and
// the standby's rclone configurations of its two stores (SeaweedFS and an
// SFTP server, in Docker).
type shippedStores struct {
	Python        string   `json:"python"`
	Shipper       string   `json:"shipper"`
	Rclone        string   `json:"rclone"`
	HostConfig    string   `json:"host_config"`
	StandbyConfig string   `json:"standby_config"`
	Flags         []string `json:"rclone_flags"`
}

func (s shippedStores) command(config string) []string {
	c := []string{s.Python, "-I", s.Shipper, "--rclone=" + s.Rclone, "--rclone-config=" + config}
	for _, f := range s.Flags {
		c = append(c, "--rclone-flag="+f)
	}
	return c
}

// A host is lost after its archives were shipped. The standby took it
// over, and restores its agent from the stores' copies, through the
// shipper's fetch with the standby's configuration (ADR 020). The standby's
// copy of the newest archive is missing, so it comes from S3, encrypted
// with rclone crypt there; it is verified against the restore authority, its
// volume is created on the new host and the archive installed, and only the
// outcome after it is declared lost. An older archive comes from the
// standby's disk. Run by scripts/verify-archive-shipping.py
// --restore-from-copies; without its stores, it does nothing.
func TestRestoreFromShippedCopies(t *testing.T) {
	path := os.Getenv("AGENTCAPSULE_SHIPPED_STORES")
	if path == "" {
		return // a child of verify-archive-shipping.py only
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stores shippedStores
	if err = json.Unmarshal(raw, &stores); err != nil {
		t.Fatal(err)
	}
	t.Run("reopen_the_LUKS_copy_from_each_store", func(t *testing.T) {
		l := newRestoreLab(t, inProcess)
		runtimeRoot := filepath.Join(t.TempDir(), "runtime")
		volume := l.luksVolume(l.e, runtimeRoot)
		archive := l.captureFile(volume, "arc_"+strings.Repeat("6", 32))
		state := t.TempDir()
		cmd := append(stores.command(stores.HostConfig), "--archive-root="+l.archives.Root(), "ship",
			"--textfile-directory="+state, "--state-directory="+state)
		if log, err := exec.CommandContext(t.Context(), cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("ship: %s: %v", log, err)
		}
		if err := os.RemoveAll(l.archives.Root()); err != nil {
			t.Fatal(err)
		}
		for _, store := range []string{"s3", "standby"} {
			root := filepath.Join(t.TempDir(), "fetched")
			cmd := append(stores.command(stores.StandbyConfig), "--archive-root="+root, "fetch", "--store="+store, "--archive="+archive.ID)
			if log, err := exec.CommandContext(t.Context(), cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("fetch from %s: %s: %v", store, log, err)
			}
			fetched, err := volumearchive.New(root)
			if err != nil {
				t.Fatal(err)
			}
			check := RestoreTest{Store: l.store, HostID: "local", Authority: l.authority, RuntimeRoot: runtimeRoot,
				Archives: fetched, Scratch: t.TempDir()}
			report, err := check.Run(t.Context(), l.e.AgentID, archive.ID)
			if err != nil || report.ArchiveID != archive.ID || report.AgentID != l.e.AgentID ||
				!slices.Equal(report.Checked, []string{"manifest", "digest", "volume", "copy", "key"}) {
				t.Fatalf("reopen copy from %s: %+v, %v", store, report, err)
			}
			t.Logf("%s restored %d verified LUKS bytes", store, report.Size)
		}
	})
	l := newRestoreLab(t, inProcess)
	kept := l.deliver("before-the-archives")
	older := l.capture("arc_" + strings.Repeat("1", 31) + "0")
	l.recordArchive(l.e, older.ID, "2 hours")
	between := l.deliver("between-the-archives")
	newest := l.capture("arc_" + strings.Repeat("2", 31) + "0")
	l.recordArchive(l.e, newest.ID, "1 hour")
	lost := l.deliver("after-the-archives")

	t.Log("stage: ship the archives, then remove the newest from the standby's copy")
	run := func(name string, command []string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), command[0], command[1:]...)
		out, err := cmd.CombinedOutput()
		t.Logf("%s:\n%s", name, out)
		if err != nil {
			t.Fatal(name, err)
		}
	}
	state := t.TempDir()
	run("ship", append(stores.command(stores.HostConfig), "--archive-root="+l.archives.Root(), "ship",
		"--textfile-directory="+state, "--state-directory="+filepath.Join(state, "state")))
	purge := []string{stores.Rclone, "--config=" + stores.StandbyConfig}
	purge = append(append(purge, stores.Flags...), "purge", "standby:"+newest.ID)
	run("purge the standby's copy", purge)

	t.Log("stage: the host is lost; the standby takes it over")
	if err = os.RemoveAll(l.archives.Root()); err != nil {
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
	if _, _, err = l.store.TakeOverHost(t.Context(), controlplane.OperatorCommand{Actor: "local-uid:0"}, "local", "standby"); err != nil {
		t.Fatal(err)
	}
	l.w.hostRestore = func(ctx context.Context, restoreID, agentID, archiveID string, archives *volumearchive.Store, paused func(error)) (VolumeRestoreResult, error) {
		return l.w.restorePausing(ctx, l.host(), restoreID, agentID, archiveID, archives, func(err error) { t.Error("paused", err) })
	}
	fetch := ScriptFetcher(stores.command(stores.StandbyConfig), archives.Root())
	started := time.Now()
	items, err := l.w.RestoreHost(t.Context(), "local", archives, fetch, nil, func(item HostRestoreItem) { t.Logf("report: %+v", item) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restored in %s", time.Since(started).Round(time.Millisecond))
	if len(items) != 1 || items[0].Result != "restored" || items[0].ArchiveID != newest.ID || items[0].ArchiveStore != "s3" ||
		items[0].Incarnation != 2 || items[0].Losses != 1 {
		t.Fatal("the restore from the copies", items)
	}
	if l.relocations != 1 || l.installedOn != [2]uint64{2, 200} {
		t.Fatal("the new host's volume", l.relocations, l.installedOn)
	}
	if held := l.heldOutcomes(append(kept, between...)); len(held) != 2 {
		t.Fatal("the outcomes before the newest archive are not all in the restored volume", held)
	}
	if held := l.heldOutcomes(lost); len(held) != 0 {
		t.Fatal("an outcome after the archive is in the restored volume", held)
	}
	if e := l.enrollment(); e.HostID != "standby" || e.Stage != "READY" || e.Incarnation != 2 {
		t.Fatal("the volume after the restore", e)
	}

	t.Log("stage: the older archive comes from the standby's disk, byte for byte")
	store, err := l.w.FetchArchive(t.Context(), archives, fetch, older.ID, nil)
	if err != nil || store != "standby" {
		t.Fatal("fetch from the standby", store, err)
	}
	f, a, err := archives.Open(t.Context(), older.ID, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if a.ID != older.ID || a.Digest != older.Digest || a.Size != older.Size || a.Binding != older.Binding {
		t.Fatal("the fetched manifest is not the archive's", a, older)
	}
}
