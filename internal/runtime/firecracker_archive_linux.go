//go:build linux

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"syscall"
)

// ErrVolumeImage reports a restored image that is not exactly the expected
// bytes. The volume then holds an incomplete image: the install must be redone.
var ErrVolumeImage = errors.New("restored volume image is incomplete or does not match its digest")

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

// InstallVolume writes a restored image into the registered ciphertext inode,
// in place, under physical exclusion and the host registry lock (REC-02). The
// caller has retired the agent's VMs under exclusive admission. image must
// yield exactly size bytes, the size of the registered container, whose
// SHA-256 is digest. Otherwise ErrVolumeImage: the volume holds a partial
// image, and the caller keeps the agent out of service until an install
// completes. The volume keeps its inode, so its identity in the registry and
// in PostgreSQL does not change. It never infers retirement from SQL.
func (h *FirecrackerHost) InstallVolume(ctx context.Context, id string, generation, device, inode uint64, image io.Reader, size int64, digest [32]byte) error {
	if image == nil || size <= 0 {
		return ErrVolumeImage
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
			return errors.New("restored volume identity changed")
		}
		fd, err := syscall.Open(a.Volume, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
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
			return errors.New("restored volume inode is inconsistent")
		}
		if st.Size() != size {
			return ErrVolumeImage
		}
		if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return errors.Join(ErrVolumeBusy, err)
		}
		hash := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(contextReader{ctx, image}, size))
		if err != nil {
			return err
		}
		if n != size {
			return ErrVolumeImage
		}
		var extra [1]byte
		if n, _ := image.Read(extra[:]); n != 0 {
			return ErrVolumeImage
		}
		if err = f.Sync(); err != nil {
			return err
		}
		if !bytes.Equal(hash.Sum(nil), digest[:]) {
			return ErrVolumeImage
		}
		return nil
	})
}

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
