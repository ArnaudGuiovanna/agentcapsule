//go:build linux

package worker

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

var (
	// ErrArchiveUnavailable: no off-host store holds a complete copy of the
	// archive that verifies against the restore authority.
	ErrArchiveUnavailable = errors.New("no store holds a usable copy of the archive")
	// ErrNotTakenOver refuses to restore the agents of a host that this host
	// did not take over (controlplane.TakeOverHost).
	ErrNotTakenOver = errors.New("this host did not take the lost host over")
)

// ArchiveStores are the off-host stores of the volume archives, in the order
// a fetch tries them (docs/recovery.md): the standby's disk, then S3.
var ArchiveStores = []string{"standby", "s3"}

// ArchiveFetcher copies one archive from one off-host store into the archive
// root, complete and checked against its manifest, or fails.
type ArchiveFetcher func(ctx context.Context, store, archiveID string) error

// ScriptFetcher runs the archive shipper's fetch
// (deploy/backup/agentcapsule-archive-ship.py): command, then --archive-root
// root fetch --store STORE --archive ID. The script runs rclone as its own
// unprivileged account; this process never reads the stores' secrets.
func ScriptFetcher(command []string, root string) ArchiveFetcher {
	return func(ctx context.Context, store, archiveID string) error {
		if len(command) == 0 || !volumearchive.ValidID(archiveID) || !slices.Contains(ArchiveStores, store) {
			return controlplane.ErrInput
		}
		args := append(slices.Clone(command[1:]), "--archive-root", root, "fetch", "--store", store, "--archive", archiveID)
		cmd := exec.CommandContext(ctx, command[0], args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			return fmt.Errorf("fetch from %s: %w: %s", store, err, lines[len(lines)-1])
		}
		return nil
	}
}

// FetchArchive makes archiveID available in the archive root and verifies
// it against the restore authority's catalogue (ValidateArchive) and its own
// manifest (size and digest), before anything installs it. An archive
// already in the root is verified the same way. Otherwise each store is
// tried in order: a copy that does not verify is removed again, and the next
// store is tried. It returns where the archive came from: "local" or a
// store. A refusal of the authorities (a deleted agent's sealed store, an
// archive it did not sign) ends it. While the authorities do not answer, it
// waits as a restore does, and tells paused.
func (w *Placements) FetchArchive(ctx context.Context, archives *volumearchive.Store, fetch ArchiveFetcher, archiveID string, paused func(error)) (string, error) {
	if w.authority == nil || archives == nil || !volumearchive.ValidID(archiveID) {
		return "", controlplane.ErrInput
	}
	verify := func() error {
		wait := restorePause.first
		for {
			f, _, err := archives.Open(ctx, archiveID, w.authority)
			if err == nil {
				f.Close()
				return nil
			}
			if !errors.Is(err, restoreauthority.ErrUnavailable) || ctx.Err() != nil {
				return err
			}
			if paused != nil {
				paused(err)
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.Join(err, ctx.Err())
			case <-timer.C:
			}
			wait = min(2*wait, restorePause.max)
		}
	}
	definite := func(err error) bool {
		return err != nil && !errors.Is(err, volumearchive.ErrArchive) && !errors.Is(err, controlplane.ErrInput)
	}
	if _, err := archives.Manifest(archiveID); err == nil {
		err = verify()
		if err == nil {
			return "local", nil
		}
		if definite(err) || fetch == nil {
			return "", err
		}
		// A local copy that does not verify gives way to a store's.
		if err = archives.Remove(archiveID); err != nil {
			return "", err
		}
	}
	if fetch == nil {
		return "", ErrArchiveUnavailable
	}
	var failures []error
	for _, store := range ArchiveStores {
		if err := fetch(ctx, store, archiveID); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			failures = append(failures, err)
			continue
		}
		err := verify()
		if err == nil {
			return store, nil
		}
		removed := archives.Remove(archiveID)
		if definite(err) {
			return "", errors.Join(err, removed)
		}
		if removed != nil {
			return "", errors.Join(err, removed)
		}
		failures = append(failures, fmt.Errorf("%s: %w", store, err))
	}
	return "", errors.Join(append([]error{ErrArchiveUnavailable}, failures...)...)
}

// HostRestoreItem is the outcome for one agent of a lost host, one line of
// the -restore-host report. Result is "restored" (by this run or an earlier
// one), "skipped" (nothing can restore it here: Reason says why) or "failed"
// (the same command may succeed later: Reason says why).
type HostRestoreItem struct {
	AgentID      string `json:"agent_id"`
	Result       string `json:"result"`
	Reason       string `json:"reason,omitempty"`
	RestoreID    string `json:"restore_id,omitempty"`
	ArchiveID    string `json:"archive_id,omitempty"`
	ArchiveStore string `json:"archive_store,omitempty"`
	Incarnation  uint64 `json:"incarnation,omitempty"`
	Losses       int    `json:"losses"`
	Unmatched    int    `json:"unmatched_losses"`
	Queued       int    `json:"reruns_queued"`
	Skipped      int    `json:"reruns_skipped"`
}

// RestoreCounts counts a restore's losses: those without a delivery this
// database knows, and the reruns queued and skipped.
func RestoreCounts(losses []controlplane.RestoreLoss) (unmatched, queued, skipped int) {
	for _, l := range losses {
		if l.MailboxID == "" {
			unmatched++
		}
		switch l.Rerun {
		case controlplane.RerunQueued:
			queued++
		case controlplane.RerunSkipped:
			skipped++
		}
	}
	return unmatched, queued, skipped
}

// HostRestoreID is the restore ID of an agent of a lost host restored from
// one archive: the same command finds it again and resumes that restore.
func HostRestoreID(lost, agentID, archiveID string) string {
	sum := sha256.Sum256([]byte("agentcapsule-host-restore-v1\x00" + lost + "\x00" + agentID + "\x00" + archiveID))
	return "rst_" + hex.EncodeToString(sum[:16])
}

// RestoreHost restores onto this host every agent of a lost host that this
// host took over (ADR 020), each from its newest archive that a store holds,
// and reports each agent to report as it goes. Unfinished restores of this
// host resume first; then the agents follow the capture time of their newest
// recorded archive, oldest first, then their ID. An archive is used from the
// archive root if it is there, else fetched from the standby's copy, else
// from S3; one that no store holds gives way to the agent's next older one.
// Each restore declares the agent's losses and queues its reruns as any
// restore does. One agent's failure does not stop the others. Run it again to
// resume: restored agents are reported again, unfinished ones resume.
func (w *Placements) RestoreHost(ctx context.Context, lost string, archives *volumearchive.Store, fetch ArchiveFetcher,
	paused func(error), report func(HostRestoreItem)) ([]HostRestoreItem, error) {
	if w.authority == nil || archives == nil || report == nil {
		return nil, controlplane.ErrInput
	}
	t, err := w.store.HostTakeoverOf(ctx, lost)
	if errors.Is(err, controlplane.ErrNotFound) || (err == nil && t.HostID != w.hostID) {
		return nil, ErrNotTakenOver
	}
	if err != nil {
		return nil, err
	}
	agents, err := w.store.LostHostAgents(ctx, lost)
	if err != nil {
		return nil, err
	}
	resuming := func(a controlplane.LostHostAgent) bool {
		return a.Restore != nil && a.Restore.Open() && a.Restore.HostID == w.hostID
	}
	newest := func(a controlplane.LostHostAgent) int64 {
		if len(a.Archives) == 0 {
			return 1<<63 - 1
		}
		return a.Archives[0].CapturedAt.UnixMicro()
	}
	slices.SortStableFunc(agents, func(x, y controlplane.LostHostAgent) int {
		if rx, ry := resuming(x), resuming(y); rx != ry {
			if rx {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(newest(x), newest(y)), strings.Compare(x.AgentID, y.AgentID))
	})
	items := make([]HostRestoreItem, 0, len(agents))
	for _, a := range agents {
		item := w.restoreLostAgent(ctx, lost, a, archives, fetch, paused)
		if ctx.Err() != nil {
			return items, ctx.Err()
		}
		items = append(items, item)
		report(item)
	}
	return items, nil
}

// restoreLostAgent restores one agent of a lost host, or says why not.
func (w *Placements) restoreLostAgent(ctx context.Context, lost string, a controlplane.LostHostAgent, archives *volumearchive.Store,
	fetch ArchiveFetcher, paused func(error)) HostRestoreItem {
	item := HostRestoreItem{AgentID: a.AgentID}
	skip := func(reason string) HostRestoreItem { item.Result, item.Reason = "skipped", reason; return item }
	fail := func(reason string) HostRestoreItem { item.Result, item.Reason = "failed", reason; return item }
	switch {
	case a.Phase == "PROVISIONING":
		return skip("provisioning")
	case a.Phase != "LIVE":
		return skip("deleting")
	case a.HostID != lost && a.HostID != w.hostID:
		return skip("elsewhere")
	}
	if r := a.Restore; r != nil && r.HostID == w.hostID && a.HostID == w.hostID {
		item.RestoreID, item.ArchiveID = r.ID, r.ArchiveID
		if !r.Open() {
			// Restored by an earlier run.
			losses, err := w.store.VolumeRestoreLosses(ctx, r.ID)
			if err != nil {
				return fail(RestoreFailure(err))
			}
			item.Result, item.Incarnation, item.Losses = "restored", r.Incarnation, len(losses)
			item.Unmatched, item.Queued, item.Skipped = RestoreCounts(losses)
			return item
		}
		// Unfinished: resume it, with its archive.
		store, err := w.FetchArchive(ctx, archives, fetch, r.ArchiveID, paused)
		if err != nil {
			return fail(hostRestoreFailure(err))
		}
		item.ArchiveStore = store
		return w.finishLostAgent(ctx, item, archives, paused)
	}
	if len(a.Archives) == 0 {
		return skip("no_archive")
	}
	for _, archive := range a.Archives {
		store, err := w.FetchArchive(ctx, archives, fetch, archive.ID, paused)
		if errors.Is(err, ErrArchiveUnavailable) {
			continue // the next older one
		}
		if err != nil {
			return fail(hostRestoreFailure(err))
		}
		item.ArchiveID, item.ArchiveStore = archive.ID, store
		item.RestoreID = HostRestoreID(lost, a.AgentID, archive.ID)
		return w.finishLostAgent(ctx, item, archives, paused)
	}
	return fail("archive_unavailable")
}

func (w *Placements) finishLostAgent(ctx context.Context, item HostRestoreItem, archives *volumearchive.Store, paused func(error)) HostRestoreItem {
	restore := w.RestoreFromArchive
	if w.hostRestore != nil {
		restore = w.hostRestore
	}
	result, err := restore(ctx, item.RestoreID, item.AgentID, item.ArchiveID, archives, paused)
	if err != nil {
		item.Result, item.Reason = "failed", RestoreFailure(err)
		return item
	}
	item.Result, item.Incarnation, item.Losses = "restored", result.Incarnation, len(result.Losses)
	item.Unmatched, item.Queued, item.Skipped = RestoreCounts(result.Losses)
	return item
}

func hostRestoreFailure(err error) string {
	if errors.Is(err, ErrArchiveUnavailable) {
		return "archive_unavailable"
	}
	return RestoreFailure(err)
}
