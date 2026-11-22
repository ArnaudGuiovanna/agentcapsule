//go:build linux

package runtime

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// linkOrCopy shares a read-only harness image with a jail by hard link, or
// copies it when the registry cache lives on another filesystem. A corpus
// image or a build drive is never copied (linkShared).
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
		err = out.Chmod(0444)
	}
	if err == nil {
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
	SystemImage   *BootImageID
	ID, Volume    string
	Device, Inode uint64
	Resources     VMResources
	Harness       *HarnessImage
	// Corpora are mounted from the first boot, in this order (ADR 023 §5).
	Corpora []CorpusImage
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
//
// It holds the agent's lock throughout. host.lock is held only to choose the
// UID and to record the registration: the volume's owner and data are made
// durable between the two, before the registry names the volume, so that a
// large volume's fsync never holds the host's other agents back.
func (h *FirecrackerHost) RegisterProvisioned(ctx context.Context, in ProvisionedAgent, firstUID, lastUID uint32) error {
	if in.ID == "" || in.Inode == 0 || !in.Resources.valid() || firstUID < 10000 || lastUID < firstUID || lastUID == ^uint32(0) || lastUID-firstUID > 1<<20 {
		return errors.New("invalid provisioning registration")
	}
	if err := validHarness(in.Harness); err != nil {
		return err
	}
	if err := h.verifyCorpora(in.Corpora); err != nil {
		return err
	}
	unlock, err := h.lockAgent(ctx, in.ID)
	if err != nil {
		return err
	}
	defer unlock()
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
	// The registration, if one exists, or a UID that neither a registered
	// agent nor a registration under way holds.
	var uid uint32
	registered := false
	err = h.locked(ctx, func(r *hostRegistry) error {
		if a := r.Agents[in.ID]; a != nil {
			registered = true
			return sameRegistration(a, in, path, s, firstUID, lastUID)
		}
		used := map[uint32]bool{}
		for _, a := range r.Agents {
			if a.Device == in.Device && a.Inode == in.Inode {
				return errors.New("volume inode already assigned")
			}
			used[a.UID] = true
		}
		h.uidMu.Lock()
		defer h.uidMu.Unlock()
		uid = firstUID
		for (used[uid] || h.uidsHeld[uid]) && uid < lastUID {
			uid++
		}
		if used[uid] || h.uidsHeld[uid] {
			return errors.New("dedicated UID range exhausted")
		}
		if h.uidsHeld == nil {
			h.uidsHeld = map[uint32]bool{}
		}
		h.uidsHeld[uid] = true
		return nil
	})
	if err != nil || registered {
		return err
	}
	defer func() {
		h.uidMu.Lock()
		delete(h.uidsHeld, uid)
		h.uidMu.Unlock()
	}()
	own := h.ownVolume
	if own == nil {
		own = ownVolume
	}
	if err = own(f, uid); err != nil {
		return err
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		// Another worker process may have registered meanwhile.
		if a := r.Agents[in.ID]; a != nil {
			return sameRegistration(a, in, path, s, firstUID, lastUID)
		}
		for _, a := range r.Agents {
			if a.Device == in.Device && a.Inode == in.Inode {
				return errors.New("volume inode already assigned")
			}
			if a.UID == uid {
				return errors.New("UID taken by another registration; retry")
			}
		}
		r.Agents[in.ID] = &HostAgent{SystemImage: in.SystemImage, ID: in.ID, UID: uid, Volume: path, Device: in.Device, Inode: in.Inode, Resources: in.Resources, Harness: in.Harness,
			Corpora: slices.Clone(in.Corpora)}
		return h.save(r)
	})
}

// ownVolume gives a provisioned volume to its agent's UID and makes its data
// and owner durable.
func ownVolume(f *os.File, uid uint32) error {
	if err := f.Chown(int(uid), int(uid)); err != nil {
		return err
	}
	return f.Sync()
}

// sameRegistration accepts a retry of a's registration only: the same
// volume, binding, resources, harness and corpora, and a UID of the range
// that owns the volume.
func sameRegistration(a *HostAgent, in ProvisionedAgent, path string, s *syscall.Stat_t, firstUID, lastUID uint32) error {
	if a.Fenced || a.SealID != "" {
		return ErrHostFenced
	}
	if (a.SystemImage == nil) != (in.SystemImage == nil) || (a.SystemImage != nil && *a.SystemImage != *in.SystemImage) || a.Volume != path || a.Device != in.Device || a.Inode != in.Inode || a.Resources != in.Resources || !sameHarness(a.Harness, in.Harness) || !sameCorpora(a.Corpora, in.Corpora) || a.UID < firstUID || a.UID > lastUID || s.Uid != a.UID || s.Gid != a.UID {
		return errors.New("provisioned registration is immutable")
	}
	return nil
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

// HarnessImagesInUseAt is HarnessImagesInUse for the runtime root root, read
// without a host driver: for a command that runs beside the worker
// (agentcapsule-worker -collect-garbage). It takes the host's lock, as the
// worker does. A root without a registry has no agent.
func HarnessImagesInUseAt(ctx context.Context, root string) (map[string]bool, error) {
	h, err := registeredHost(root)
	if h == nil || err != nil {
		return map[string]bool{}, err
	}
	return h.HarnessImagesInUse(ctx)
}
func registeredHost(root string) (*FirecrackerHost, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(filepath.Join(abs, "registry.json")); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if real, err := filepath.EvalSymlinks(abs); err != nil || real != abs {
		return nil, errors.New("runtime root must not contain symlinks")
	}
	return &FirecrackerHost{root: abs}, nil
}

// SetRolloutProfile changes only a stopped, unsealed agent. Its encrypted
// device, inode, volume size and dedicated UID stay bound to the same agent.
func (h *FirecrackerHost) SetRolloutProfile(ctx context.Context, agent, rollout string, resources VMResources, system *BootImageID, harness *HarnessImage) error {
	if rollout == "" || system == nil || !resources.valid() {
		return ErrGeneration
	}
	if err := validHarness(harness); err != nil {
		return err
	}
	for _, a := range []struct{ name, digest string }{{"kernel", system.Kernel}, {"initrd", system.Initrd}} {
		if raw, err := hex.DecodeString(a.digest); err != nil || len(raw) != 32 {
			return ErrGeneration
		}
		f, err := os.Stat(filepath.Join(h.root, "bin", a.name+"-"+a.digest))
		if err != nil {
			return err
		}
		if !f.Mode().IsRegular() {
			return ErrGeneration
		}
	}
	return h.setStoppedRolloutProfile(ctx, agent, rollout, resources, system, harness)
}

// ResizeRollout keeps the installed image and harness, including legacy agents
// that use this host's built-in image without an explicit system-image pin.
func (h *FirecrackerHost) ResizeRollout(ctx context.Context, agent, rollout string, resources VMResources) error {
	if rollout == "" || !resources.valid() {
		return ErrGeneration
	}
	return h.setStoppedRolloutProfile(ctx, agent, rollout, resources, nil, nil)
}

func (h *FirecrackerHost) setStoppedRolloutProfile(ctx context.Context, agent, rollout string, resources VMResources, system *BootImageID, harness *HarnessImage) error {
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[agent]
		if a == nil || a.Fenced || a.SealID != "" || a.VolumeRemoved {
			return ErrHostFenced
		}
		if a.Resources.VolumeMiB != resources.VolumeMiB {
			return ErrGeneration
		}
		if a.Run != nil {
			return ErrHarnessInUse
		}
		a.Rollout = rollout
		a.Resources = resources
		if system != nil {
			a.SystemImage = system
			a.Harness = harness
		}
		return h.save(r)
	})
}
