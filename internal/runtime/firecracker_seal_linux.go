//go:build linux

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"syscall"
)

// StoreSeal attests managed execution retirement, NOT destruction of data/keys.
// It assumes one trusted host registry; copying/restoring a volume under another
// registry or rolling back this registry requires a separate restore protocol.
type StoreSeal struct {
	AgentID, ID               string
	Generation, Device, Inode uint64
}

// SealAgent persists the admission ban before draining the attempt cgroup, then
// records a stable receipt. No receipt is returned on uncertain persistence,
// remaining writers or changed/missing volume identity. Retrying revalidates the
// local record and inode, even when PostgreSQL already remembers a receipt.
func (h *FirecrackerHost) SealAgent(ctx context.Context, id string, generation uint64) (StoreSeal, error) {
	var receipt StoreSeal
	err := h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("unregistered agent")
		}
		if a.Generation > generation || (a.SealID != "" && a.Generation != generation) {
			return ErrGeneration
		}
		if a.VolumeRemoved {
			// A completed cleanup keeps the execution seal forever. A restored
			// file at this name is an inconsistency, not permission to restart.
			if err := removedVolume(a.Volume); err != nil {
				return err
			}
			receipt = sealedReceipt(a)
			return nil
		}
		a.Fenced = true
		if err := h.save(r); err != nil {
			return err
		}
		if h.hook != nil {
			h.hook("seal-intent", VMRun{Generation: generation})
		}
		if a.Run != nil {
			if err := h.cleanup(a.Run); err != nil {
				return err
			}
			a.Run = nil
		}
		// O_NOFOLLOW and fstat bind the proof to the registered regular inode.
		fd, err := syscall.Open(a.Volume, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), a.Volume)
		defer file.Close()
		st, err := file.Stat()
		if err != nil {
			return err
		}
		inode := st.Sys().(*syscall.Stat_t)
		if !st.Mode().IsRegular() || uint64(inode.Dev) != a.Device || inode.Ino != a.Inode {
			return errors.New("sealed volume identity changed")
		}
		if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return errors.Join(ErrVolumeBusy, err)
		}
		if a.SealID == "" {
			nonce := make([]byte, 16)
			if _, err = rand.Read(nonce); err != nil {
				return err
			}
			a.SealID = hex.EncodeToString(nonce)
		}
		a.Generation = generation
		if err = h.save(r); err != nil {
			return err
		}
		if h.hook != nil {
			h.hook("sealed", VMRun{Generation: generation})
		}
		receipt = sealedReceipt(a)
		return nil
	})
	return receipt, err
}

func sealedReceipt(a *HostAgent) StoreSeal {
	return StoreSeal{AgentID: a.ID, ID: a.SealID, Generation: a.Generation, Device: a.Device, Inode: a.Inode}
}

func removedVolume(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("retired volume name is still present")
}

// RemoveSealedVolume runs the trusted key/volume cleanup while holding the host
// registry lock. It requires an existing physical execution seal, so the key
// cannot be revoked while a managed VMM is alive. The callback must durably
// revoke the key and remove the exact registered inode with its own crash
// journal. It is retried after ANY uncertain outcome, including a missing file
// before the final host receipt. No callback may re-enter this host.
func (h *FirecrackerHost) RemoveSealedVolume(ctx context.Context, id string, generation uint64, remove func(StoreSeal) error) (StoreSeal, error) {
	var receipt StoreSeal
	if remove == nil {
		return receipt, errors.New("volume cleanup callback required")
	}
	err := h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil || !a.Fenced || a.SealID == "" || a.Run != nil {
			return errors.New("permanent execution seal required before volume removal")
		}
		if a.Generation != generation {
			return ErrGeneration
		}
		proof := sealedReceipt(a)
		if err := remove(proof); err != nil {
			return err
		}
		if err := removedVolume(a.Volume); err != nil {
			return err
		}
		a.VolumeRemoved = true
		if err := h.save(r); err != nil {
			return err
		}
		if h.hook != nil {
			h.hook("volume-removed", VMRun{Generation: generation})
		}
		receipt = proof
		return nil
	})
	return receipt, err
}
