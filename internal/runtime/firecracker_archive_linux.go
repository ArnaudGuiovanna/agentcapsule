//go:build linux

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"
)

// WithStoppedVolume reads the registered ciphertext inode under physical
// exclusion and the host registry lock. It never infers retirement from SQL.
// The caller must have quiesced/retired the VM under exclusive admission. The
// callback may enter the independent authority, but must not re-enter the host.
func (h *FirecrackerHost) WithStoppedVolume(ctx context.Context, id string, generation, device, inode uint64, use func(io.Reader) error) error {
	if use == nil {
		return errors.New("archive reader required")
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil || a.Run != nil {
			return ErrVolumeBusy
		}
		if a.Fenced || a.SealID != "" || a.VolumeRemoved {
			return ErrHostFenced
		}
		if a.Generation != generation {
			return ErrGeneration
		}
		if a.Device != device || a.Inode != inode || inode == 0 {
			return errors.New("archive volume identity changed")
		}
		fd, err := syscall.Open(a.Volume, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), a.Volume)
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		s := st.Sys().(*syscall.Stat_t)
		if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || uint64(s.Dev) != device || s.Ino != inode || s.Nlink != 1 {
			return errors.New("archive volume inode is inconsistent")
		}
		if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return errors.Join(ErrVolumeBusy, err)
		}
		return use(f)
	})
}
