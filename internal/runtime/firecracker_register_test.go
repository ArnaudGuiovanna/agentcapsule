//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// RegisterProvisioned makes a volume's owner and data durable without
// host.lock, so that another registry change goes on during a large
// volume's fsync (S-03, the leftover of PERF-1); the registry names the
// volume only once it is durable. Before, the chown and the fsync ran under
// host.lock.
func TestAProvisionedVolumeIsSyncedOutsideTheHostLock(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "volumes"), 0o700); err != nil {
		t.Fatal(err)
	}
	h := &FirecrackerHost{root: root}
	volume := func(name string) ProvisionedAgent {
		path := filepath.Join(root, "volumes", name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err = f.Truncate(64 << 20); err != nil {
			t.Fatal(err)
		}
		st, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		s := st.Sys().(*syscall.Stat_t)
		return ProvisionedAgent{ID: name, Volume: path, Device: uint64(s.Dev), Inode: s.Ino, Resources: VMResources{VCPUs: 1, MemoryMiB: 256, VolumeMiB: 64}}
	}
	var mu sync.Mutex
	owners := map[string]uint32{}
	h.ownVolume = func(f *os.File, uid uint32) error {
		// Another registry change takes host.lock meanwhile, and the
		// registry does not name this volume yet.
		changed := make(chan error, 1)
		var named bool
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			changed <- h.locked(ctx, func(r *hostRegistry) error {
				for _, a := range r.Agents {
					named = named || a.Volume == f.Name()
				}
				return nil
			})
		}()
		select {
		case err := <-changed:
			if err != nil {
				return err
			}
		case <-time.After(5 * time.Second):
			return errors.New("host.lock held during the volume's fsync")
		}
		if named {
			return errors.New("the registry named the volume before it was durable")
		}
		mu.Lock()
		owners[filepath.Base(f.Name())] = uid
		mu.Unlock()
		return nil
	}
	// Two registrations at once take two UIDs.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, name := range []string{"a", "b"} {
		in := volume(name)
		wg.Go(func() { errs <- h.RegisterProvisioned(t.Context(), in, 60000, 60010) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	err := h.locked(t.Context(), func(r *hostRegistry) error {
		for _, name := range []string{"a", "b"} {
			if a := r.Agents[name]; a == nil || a.UID != owners[name] {
				t.Errorf("%s registered as %+v, owned by %d", name, a, owners[name])
			}
		}
		if r.Agents["a"].UID == r.Agents["b"].UID {
			t.Error("two volumes share a UID", r.Agents["a"].UID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.uidsHeld) != 0 {
		t.Fatal("UIDs still held after the registrations", h.uidsHeld)
	}
}
