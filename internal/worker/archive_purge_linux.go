//go:build linux

package worker

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// purgeEvery is how often the archive pass looks for the archives of deleted
// agents: at its first pass, then once an hour.
const purgeEvery = time.Hour

// purgeArchives runs purgeDeletedArchives at the first pass and then every
// purgeEvery, and reports what it removed. A failure waits for the next turn
// too: the archives it left are unreadable already.
func (w *Placements) purgeArchives(ctx context.Context, a *Archives) {
	now := time.Now()
	if !a.purged.IsZero() && now.Sub(a.purged) < purgeEvery {
		return
	}
	a.purged = now
	removed, err := w.purgeDeletedArchives(ctx, a.Store)
	if ctx.Err() != nil {
		return
	}
	if a.Purged != nil && (removed > 0 || err != nil) {
		a.Purged(removed, err)
	}
}

// purgeDeletedArchives deletes from the host's archive root every archive
// whose volume key is destroyed (ADR 018): the agent was deleted, its key
// revoked, its volume removed. Such an archive no longer opens anywhere; only
// its manifest still names the agent. Recorded captures and archives taken on
// demand go alike, each in one step (volumearchive.Store.Remove), then its
// record. An archive whose manifest is unreadable, or names another volume,
// stays for the operator. It returns how many archives it removed from disk.
func (w *Placements) purgeDeletedArchives(ctx context.Context, archives *volumearchive.Store) (int, error) {
	ids, err := archives.List()
	if err != nil {
		return 0, err
	}
	found := make([]controlplane.ArchiveBinding, 0, len(ids))
	for _, id := range ids {
		if m, err := archives.Manifest(id); err == nil {
			found = append(found, controlplane.ArchiveBinding{ID: id, AgentID: m.Binding.Store, VolumeID: m.Binding.Volume})
		}
	}
	purge, err := w.store.PurgeableVolumeArchives(ctx, w.hostID, found)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, p := range purge {
		if err = ctx.Err(); err != nil {
			return removed, err
		}
		var size int64
		m, err := archives.Manifest(p.ID)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// Gone already, or never published: finish an interrupted removal.
		case err != nil, m.Binding.Store != p.AgentID, m.Binding.Volume != p.VolumeID:
			continue
		default:
			size = m.Size
		}
		if err = archives.Remove(p.ID); err != nil {
			return removed, err
		}
		if size > 0 {
			removed++
		}
		if err = w.store.PurgedVolumeArchive(ctx, p.ID, size); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
