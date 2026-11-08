//go:build linux && cgo

package volumestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Remove retires an already published container after the trusted caller has
// permanently sealed execution and revoked its key. It establishes local name
// removal, not erasure of copied keys, backups, open external descriptors or raw
// storage blocks. The journal and reservation lock are deliberately retained.
// Only a prior REMOVING intent allows a missing file during crash recovery.
func (s *Store) Remove(ctx context.Context, spec Spec, device, inode uint64) error {
	if !identifier(spec.AgentID, "agt_") || !identifier(spec.VolumeID, "vol_") || spec.SizeMiB < 64 || spec.SizeMiB > 32768 || inode == 0 {
		return ErrInput
	}
	base := filepath.Join(s.root, "volume-state", spec.VolumeID)
	lock, err := file(base+".lock", false)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = flock(ctx, lock, true); err != nil {
		return err
	}
	j, err := load(base + ".json")
	if err != nil {
		return err
	}
	if j.Spec != spec || j.Device != device || j.Inode != inode {
		return ErrConflict
	}
	if j.Stage != "READY" && j.Stage != "REMOVING" && j.Stage != "REMOVED" {
		return ErrState
	}
	path := filepath.Join(s.root, "volumes", spec.VolumeID+".luks")
	if !absence(filepath.Join(s.root, "volumes", spec.VolumeID+".pending")) {
		return ErrState
	}
	f, err := file(path, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if f == nil {
		if j.Stage == "READY" {
			return ErrState
		}
	} else {
		defer f.Close()
		if j.Stage == "REMOVED" {
			return ErrState
		}
		if err = flock(ctx, f, false); err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		id := st.Sys().(*syscall.Stat_t)
		if uint64(id.Dev) != device || id.Ino != inode || id.Nlink != 1 || st.Size() != spec.SizeMiB<<20 {
			return ErrState
		}
		if j.Stage == "READY" {
			j.Stage = "REMOVING"
			if err = save(base+".json", j); err != nil {
				return err
			}
		}
		s.boundary("removal_intent")
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		s.boundary("volume_unlinked")
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	s.boundary("removal_synced")
	j.Stage = "REMOVED"
	if err = save(base+".json", j); err != nil {
		return err
	}
	s.boundary("removal_committed")
	return nil
}
