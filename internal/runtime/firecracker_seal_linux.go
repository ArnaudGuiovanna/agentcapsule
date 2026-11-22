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
// It runs under the agent's lock; host.lock only records each step.
func (h *FirecrackerHost) SealAgent(ctx context.Context, id string, generation uint64) (StoreSeal, error) {
	var receipt StoreSeal
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return receipt, err
	}
	defer unlock()
	var a *HostAgent
	removed := false
	err = h.locked(ctx, func(r *hostRegistry) error {
		current := r.Agents[id]
		if current == nil {
			return errors.New("unregistered agent")
		}
		if current.Generation > generation || (current.SealID != "" && current.Generation != generation) {
			return ErrGeneration
		}
		if current.VolumeRemoved {
			// A completed cleanup keeps the execution seal forever. A restored
			// file at this name is an inconsistency, not permission to restart.
			if err := removedVolume(current.Volume); err != nil {
				return err
			}
			receipt, removed = sealedReceipt(current), true
			return nil
		}
		current.Fenced = true
		a = current.clone()
		return h.save(r)
	})
	if err != nil || removed {
		return receipt, err
	}
	if h.hook != nil {
		h.hook("seal-intent", VMRun{Generation: generation})
	}
	if a.Run != nil {
		if err = h.retireRun(ctx, id, a.Run); err != nil {
			return receipt, err
		}
	}
	// O_NOFOLLOW and fstat bind the proof to the registered regular inode,
	// which root opens: it is the VM's user's (ADR 024).
	file, err := h.privileged().OpenVolume(ctx, a.Volume, true)
	if err != nil {
		return receipt, err
	}
	defer file.Close()
	fd := int(file.Fd())
	st, err := file.Stat()
	if err != nil {
		return receipt, err
	}
	inode := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || uint64(inode.Dev) != a.Device || inode.Ino != a.Inode {
		return receipt, errors.New("sealed volume identity changed")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return receipt, errors.Join(ErrVolumeBusy, err)
	}
	err = h.locked(ctx, func(r *hostRegistry) error {
		current := r.Agents[id]
		if current == nil || !current.Fenced || current.Run != nil || current.Generation > generation || current.Device != a.Device || current.Inode != a.Inode {
			return ErrGeneration
		}
		if current.SealID == "" {
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			current.SealID = hex.EncodeToString(nonce)
		}
		current.Generation = generation
		if err := h.save(r); err != nil {
			return err
		}
		receipt = sealedReceipt(current)
		return nil
	})
	if err != nil {
		return StoreSeal{}, err
	}
	if h.hook != nil {
		h.hook("sealed", VMRun{Generation: generation})
	}
	return receipt, nil
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

// RemoveSealedVolume runs the trusted key/volume cleanup while holding the
// agent's lock, never host.lock. It requires an existing physical execution
// seal, so the key cannot be revoked while a managed VMM is alive. The callback
// must durably revoke the key and remove the exact registered inode with its
// own crash journal. It is retried after ANY uncertain outcome, including a
// missing file before the final host receipt. No callback may re-enter this
// host.
func (h *FirecrackerHost) RemoveSealedVolume(ctx context.Context, id string, generation uint64, remove func(StoreSeal) error) (StoreSeal, error) {
	var receipt StoreSeal
	if remove == nil {
		return receipt, errors.New("volume cleanup callback required")
	}
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return receipt, err
	}
	defer unlock()
	a, err := h.agent(ctx, id)
	if err != nil {
		return receipt, err
	}
	if a == nil || !a.Fenced || a.SealID == "" || a.Run != nil {
		return receipt, errors.New("permanent execution seal required before volume removal")
	}
	if a.Generation != generation {
		return receipt, ErrGeneration
	}
	proof := sealedReceipt(a)
	if err = remove(proof); err != nil {
		return receipt, err
	}
	if err = removedVolume(a.Volume); err != nil {
		return receipt, err
	}
	if err = h.locked(ctx, func(r *hostRegistry) error {
		current := r.Agents[id]
		if current == nil || current.SealID != proof.ID || current.Generation != generation || current.Run != nil {
			return ErrGeneration
		}
		current.VolumeRemoved = true
		return h.save(r)
	}); err != nil {
		return receipt, err
	}
	if h.hook != nil {
		h.hook("volume-removed", VMRun{Generation: generation})
	}
	return proof, nil
}
