//go:build linux

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// linkOrCopy shares a read-only file with a jail by hard link, or copies it
// when the registry cache lives on another filesystem.
func linkOrCopy(src, dst string) error {
	err := os.Link(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}

type VMResources struct {
	VCPUs     int `json:"vcpus"`
	MemoryMiB int `json:"memory_mib"`
	VolumeMiB int `json:"volume_mib"`
}

func (r VMResources) valid() bool {
	return r.VCPUs >= 1 && r.VCPUs <= 8 && r.MemoryMiB >= 128 && r.MemoryMiB <= 8192 && r.VolumeMiB >= 64 && r.VolumeMiB <= 32768
}
func (a *HostAgent) resources() VMResources {
	if a.Resources == (VMResources{}) {
		return VMResources{VCPUs: 1, MemoryMiB: 256}
	}
	return a.Resources
}

type ProvisionedAgent struct {
	ID, Volume    string
	Device, Inode uint64
	Resources     VMResources
	Harness       *HarnessImage
}

// validHarness: an absolute regular file the VMM can read, a digest and an
// entrypoint the guest accepts. Its content was verified when imported.
func validHarness(img *HarnessImage) error {
	if img == nil {
		return nil
	}
	if !filepath.IsAbs(img.Path) || filepath.Clean(img.Path) != img.Path || !strings.HasPrefix(img.Digest, "sha256:") || len(img.Digest) != 71 ||
		(capsuleprotocol.HarnessLaunch{Entrypoint: img.Entrypoint}).Validate() != nil {
		return errors.New("invalid harness image")
	}
	st, err := os.Lstat(img.Path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o004 == 0 || st.Mode().Perm()&0o022 != 0 || st.Size() < 64<<10 {
		return errors.New("harness image must be a world-readable, write-protected regular file")
	}
	return nil
}

func sameHarness(a, b *HarnessImage) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Path == b.Path && a.Digest == b.Digest && slices.Equal(a.Entrypoint, b.Entrypoint)
}

// RegisterProvisioned binds an already published encrypted container. Retrying
// accepts only the exact original inode, size and immutable resources. UIDs of
// retired/sealed agents remain reserved. The operator must dedicate the entire
// UID range to this runtime root; it is never supplied by an API caller.
func (h *FirecrackerHost) RegisterProvisioned(ctx context.Context, in ProvisionedAgent, firstUID, lastUID uint32) error {
	if in.ID == "" || in.Inode == 0 || !in.Resources.valid() || firstUID < 10000 || lastUID < firstUID || lastUID == ^uint32(0) || lastUID-firstUID > 1<<20 {
		return errors.New("invalid provisioning registration")
	}
	if err := validHarness(in.Harness); err != nil {
		return err
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		path, err := filepath.Abs(in.Volume)
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if real != path || filepath.Dir(path) != filepath.Join(h.root, "volumes") {
			return errors.New("volume outside managed directory")
		}
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		s := st.Sys().(*syscall.Stat_t)
		if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != int64(in.Resources.VolumeMiB)<<20 || s.Ino != in.Inode || uint64(s.Dev) != in.Device {
			return errors.New("provisioned volume binding changed")
		}
		if a := r.Agents[in.ID]; a != nil {
			if a.Fenced || a.SealID != "" {
				return ErrHostFenced
			}
			if a.Volume != path || a.Device != in.Device || a.Inode != in.Inode || a.Resources != in.Resources || !sameHarness(a.Harness, in.Harness) || a.UID < firstUID || a.UID > lastUID || s.Uid != a.UID || s.Gid != a.UID {
				return errors.New("provisioned registration is immutable")
			}
			return nil
		}
		used := map[uint32]bool{}
		for _, a := range r.Agents {
			if a.Device == in.Device && a.Inode == in.Inode {
				return errors.New("volume inode already assigned")
			}
			used[a.UID] = true
		}
		uid := firstUID
		for used[uid] && uid < lastUID {
			uid++
		}
		if used[uid] {
			return errors.New("dedicated UID range exhausted")
		}
		if err = f.Chown(int(uid), int(uid)); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		r.Agents[in.ID] = &HostAgent{ID: in.ID, UID: uid, Volume: path, Device: in.Device, Inode: in.Inode, Resources: in.Resources, Harness: in.Harness}
		return h.save(r)
	})
}

// ErrHarnessInUse: the agent has a VM run; its harness changes only once that
// VM has stopped, at a later boot.
var ErrHarnessInUse = errors.New("harness in use by a running VM")

// HarnessOf returns the harness image recorded for an agent (nil: the
// platform image's built-in harness).
func (h *FirecrackerHost) HarnessOf(ctx context.Context, id string) (*HarnessImage, error) {
	var img *HarnessImage
	err := h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("agent not registered on this host")
		}
		if a.Harness != nil {
			c := *a.Harness
			c.Entrypoint = slices.Clone(a.Harness.Entrypoint)
			img = &c
		}
		return nil
	})
	return img, err
}

// ReplaceHarness records another verified harness image (nil: built-in) for a
// provisioned agent, used from its next boot. Refused while a VM run exists,
// and for a fenced, sealed or removed agent.
func (h *FirecrackerHost) ReplaceHarness(ctx context.Context, id string, img *HarnessImage) error {
	if err := validHarness(img); err != nil {
		return err
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		switch {
		case a == nil:
			return errors.New("agent not registered on this host")
		case sameHarness(a.Harness, img):
			return nil
		case a.Fenced || a.SealID != "" || a.VolumeRemoved:
			return ErrHostFenced
		case a.Run != nil:
			return ErrHarnessInUse
		}
		a.Harness = img
		return h.save(r)
	})
}

// HarnessImagesInUse lists the image paths that registered agents may still
// boot from. A cached package whose image is listed must be kept.
func (h *FirecrackerHost) HarnessImagesInUse(ctx context.Context) (map[string]bool, error) {
	paths := map[string]bool{}
	err := h.locked(ctx, func(r *hostRegistry) error {
		for _, a := range r.Agents {
			if a.Harness != nil && !a.VolumeRemoved {
				paths[a.Harness.Path] = true
			}
		}
		return nil
	})
	return paths, err
}
