//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestResizeStoppedHostProfileKeepsVolumeAndImages(t *testing.T) {
	h := &FirecrackerHost{root: t.TempDir()}
	for i, pinned := range []bool{false, true} {
		a := HostAgent{ID: fmt.Sprintf("agent-%d", i), UID: uint32(10000 + i), Volume: filepath.Join(h.root, "volumes", fmt.Sprint(i)), Device: 3, Inode: uint64(20 + i), Resources: VMResources{1, 256, 64}}
		if pinned {
			a.SystemImage = &BootImageID{Kernel: strings.Repeat("a", 64), Initrd: strings.Repeat("b", 64)}
			a.Harness = &HarnessImage{Digest: "sha256:" + strings.Repeat("c", 64), Path: filepath.Join(h.root, "harness.ext4"), Entrypoint: []string{"/bin/example"}}
		}
		if err := h.locked(t.Context(), func(r *hostRegistry) error { r.Agents[a.ID] = &a; return h.save(r) }); err != nil {
			t.Fatal(err)
		}
		if err := h.ResizeRollout(t.Context(), a.ID, "resize", VMResources{2, 512, 128}); !errors.Is(err, ErrGeneration) {
			t.Fatal("resize changed disk size", err)
		}
		target := VMResources{2, 512, 64}
		for range 2 {
			if err := h.ResizeRollout(t.Context(), a.ID, "resize", target); err != nil {
				t.Fatal(err)
			}
		}
		a.Rollout, a.Resources = "resize", target
		if err := h.locked(t.Context(), func(r *hostRegistry) error {
			if !reflect.DeepEqual(&a, r.Agents[a.ID]) {
				t.Fatalf("unrelated host fields changed: got %+v, want %+v", r.Agents[a.ID], a)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostBootCapacitySerializesComputeAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cpus   int
		memory int64
		want   int
	}{
		{"cpu", 3, 0, 1}, {"memory-with-vmm-overhead", 0, 1280, 1}, {"legacy-unlimited-compute", 0, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newAdoptionLab(t, 1, false)
			h := l.h
			h.opts.MaxActive, h.opts.HostVCPUs, h.opts.HostMemoryMiB = 4, tc.cpus, tc.memory
			for _, id := range []string{"one", "two"} {
				l.register(t, id)
			}
			// The peer has the legacy 1 vCPU/256 MiB profile. A restricted
			// boot and a partially started VM spend physical resources too.
			if err := h.locked(t.Context(), func(r *hostRegistry) error {
				r.Agents["agent-00"].Run.FenceOnly = true
				return h.save(r)
			}); err != nil {
				t.Fatal(err)
			}
			ch := make(chan error, 2)
			var wg sync.WaitGroup
			for i, id := range []string{"one", "two"} {
				wg.Go(func() {
					ch <- h.locked(t.Context(), func(r *hostRegistry) error {
						p := VMResources{2, 512, 64}
						if !h.hasBootCapacity(r, p) {
							return ErrCapacity
						}
						a := r.Agents[id]
						a.Resources = p
						a.Generation = 1
						a.Run = &VMRun{ID: fmt.Sprintf("%016x", i+4), Generation: 1, Phase: "STARTING"}
						a.Run.Socket = filepath.Join(h.jail(a.Run), "vsock")
						return h.save(r)
					})
				})
			}
			wg.Wait()
			close(ch)
			var admitted int
			for err := range ch {
				if err == nil {
					admitted++
				} else if !errors.Is(err, ErrCapacity) {
					t.Fatal(err)
				}
			}
			if admitted != tc.want {
				t.Fatal(admitted, tc.want)
			}
		})
	}
}
