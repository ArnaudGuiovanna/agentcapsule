//go:build linux && cgo && kvm_integration && kvm_product_integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

func openProductVolume(ctx context.Context, c *capsuleprotocol.Client, v capsuleprotocol.VolumeBoot, key []byte) error {
	for {
		err := c.OpenVolume(ctx, v, key)
		if err == nil || !errors.Is(err, capsuleprotocol.ErrTransport) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestProductGuestEncryptedPersistenceAndIsolation(t *testing.T) {
	authorityRoot, err := os.MkdirTemp(kvmSettings(t).RootParent, "keys-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(authorityRoot) })
	keys, err := keyauthority.Initialize(t.Context(), authorityRoot)
	if err != nil {
		t.Fatal(err)
	}
	volumes := map[string]volumestore.Container{}
	initialize := map[string]bool{}
	var wrongKey atomic.Bool
	h, _ := newHostWithOptions(t, func(opts *FirecrackerOptions) {
		opts.Ready = nil
		opts.AuthenticatedControl = true
		opts.BootTimeout = 60 * time.Second
		opts.PrepareGuest = func(ctx context.Context, id string, run VMRun, c *capsuleprotocol.Client) error {
			volume, ok := volumes[id]
			if !ok {
				return errors.New("unknown test volume")
			}
			if err := ownedVolumeLock(run.PID, volume.Path); err != nil {
				return err
			}
			return keys.WithKey(ctx, id, volume.Spec.VolumeID, func(key []byte) error {
				// Durable initrd files must contain transport credentials only.
				b, err := os.ReadFile(filepath.Join(opts.Root, "jails", "firecracker", run.ID, "root", "initrd"))
				if err != nil {
					return err
				}
				if bytes.Contains(b, key) {
					return errors.New("volume key persisted in initrd")
				}
				input := key
				if wrongKey.Load() {
					input = append([]byte(nil), key...)
					input[0] ^= 1
					defer clear(input)
				}
				return openProductVolume(ctx, c, capsuleprotocol.VolumeBoot{Incarnation: 1, VolumeID: volume.Spec.VolumeID, UUID: volume.UUID, Initialize: initialize[id], PreviousShutdown: capsuleprotocol.ShutdownUnclean}, input)
			})
		}
	})
	storage, err := volumestore.New(h.root)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"agt_" + strings.Repeat("a", 32), "agt_" + strings.Repeat("b", 32)}
	for i, id := range ids {
		volumeID := "vol_" + strings.Repeat(string(rune('c'+i)), 32)
		if err = keys.Ensure(t.Context(), id, volumeID); err != nil {
			t.Fatal(err)
		}
		var volume volumestore.Container
		err = keys.WithKey(t.Context(), id, volumeID, func(key []byte) error {
			var e error
			volume, e = storage.Prepare(t.Context(), volumestore.Spec{AgentID: id, VolumeID: volumeID, SizeMiB: 128}, key)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		volumes[id] = volume
		initialize[id] = true
		registration := ProvisionedAgent{ID: id, Volume: volume.Path, Device: volume.Device, Inode: volume.Inode, Resources: VMResources{VCPUs: 1 + i, MemoryMiB: 256 + i*128, VolumeMiB: 128}}
		for range 2 {
			if err = h.RegisterProvisioned(t.Context(), registration, 62100, 62101); err != nil {
				t.Fatal("registration replay", err)
			}
		}
		changed := registration
		changed.Resources.MemoryMiB += 128
		if err = h.RegisterProvisioned(t.Context(), changed, 62100, 62101); err == nil {
			t.Fatal("resources changed on replay")
		}
		changed = registration
		changed.Inode++
		if err = h.RegisterProvisioned(t.Context(), changed, 62100, 62101); err == nil {
			t.Fatal("inode changed on replay")
		}
		changed = registration
		changed.ID = "alias"
		if err = h.RegisterProvisioned(t.Context(), changed, 62100, 62102); err == nil {
			t.Fatal("volume alias assigned to another agent")
		}
		run, err := h.StartForFence(t.Context(), id, 1)
		if err != nil || !run.FenceOnly {
			t.Fatal("restricted filesystem initialization", err)
		}
		for file, want := range map[string]string{"memory.max": fmt.Sprint(int64(registration.Resources.MemoryMiB+256) << 20), "cpu.max": fmt.Sprintf("%d 100000", registration.Resources.VCPUs*100000)} {
			b, err := os.ReadFile(filepath.Join(h.group(&run), file))
			if err != nil || strings.TrimSpace(string(b)) != want {
				t.Fatal("kernel resource limit", file, string(b), err)
			}
		}
		if err = h.RegisterProvisioned(t.Context(), registration, 62100, 62101); err != nil {
			t.Fatal("exact replay disturbed running VM", err)
		}
		c, err := h.Control(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Fence(t.Context(), "agent/historical"); err != nil {
			t.Fatal(err)
		}
		if err = h.Stop(t.Context(), id, 1); err != nil {
			t.Fatal(err)
		}
		initialize[id] = false
	}
	clients := map[string]*capsuleprotocol.Client{}
	events := map[string]harnessstore.Event{}
	for _, id := range ids {
		if _, err = h.Start(t.Context(), id, 2); err != nil {
			t.Fatal("ordinary encrypted wake", err)
		}
		c, err := h.Control(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		clients[id] = c
		e := harnessstore.Event{ID: "same-event-id", Subjects: []string{"agent/" + id, "request/" + id}, Body: []byte("private body for " + id)}
		events[id] = e
		r, err := c.Send(t.Context(), e)
		if err != nil || r.Replayed {
			t.Fatal("independent guest event", err)
		}
		var reply struct {
			Echo []byte `json:"echo"`
		}
		if err = json.Unmarshal(r.Result, &reply); err != nil || !bytes.Equal(reply.Echo, e.Body) {
			t.Fatal("cross-volume result or invalid echo", err)
		}
		revoked := harnessstore.Event{ID: "historical", Subjects: []string{"agent/" + id, "agent/historical"}, Body: []byte("must refuse")}
		if _, err = c.Send(t.Context(), revoked); !errors.Is(err, harnessstore.ErrFenced) {
			t.Fatal("initialization fence lost on wake", err)
		}
	}
	runs, err := h.Reconcile(t.Context())
	if err != nil || len(runs) != 2 {
		t.Fatal("two independent encrypted VMs are not running", err)
	}
	a, b := ids[0], ids[1]
	if err = h.Stop(t.Context(), a, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Start(t.Context(), a, 3); err != nil {
		t.Fatal(err)
	}
	c, err := h.Control(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := c.Send(t.Context(), events[a]); err != nil || !r.Replayed {
		t.Fatal("encrypted effect repeated after VMM kill", err)
	}
	if err = c.Fence(t.Context(), "request/"+a); err != nil {
		t.Fatal(err)
	}
	if err = h.Stop(t.Context(), a, 3); err != nil {
		t.Fatal(err)
	}
	wrongKey.Store(true)
	if _, err = h.Start(t.Context(), a, 4); err == nil {
		t.Fatal("guest accepted wrong unlock secret")
	}
	wrongKey.Store(false)
	if _, err = h.Start(t.Context(), a, 5); err != nil {
		t.Fatal("wrong-key refusal damaged existing volume", err)
	}
	c, err = h.Control(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Send(t.Context(), events[a]); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("encrypted fence lost after restart", err)
	}
	if r, err := clients[b].Send(t.Context(), events[b]); err != nil || !r.Replayed {
		t.Fatal("other VM changed during first VM retirement", err)
	}
	t.Log("Two real encrypted guests, independent process harnesses, durable dedup/fences after forced VMM retirement, wrong-key refusal and secret-free initrd verified; SQL/API orchestration remains outside this test.")
}

func TestProductGuestRejectsUnlockedVMMBeforeKeyDelivery(t *testing.T) {
	var prepared atomic.Bool
	h, _ := newHostWithOptions(t, func(opts *FirecrackerOptions) {
		opts.Ready = nil
		opts.AuthenticatedControl = true
		opts.BootTimeout = 3 * time.Second
		opts.PrepareGuest = func(context.Context, string, VMRun, *capsuleprotocol.Client) error {
			prepared.Store(true)
			return errors.New("must not receive key capability")
		}
	})
	path := enroll(t, h, "negative-lock", 62102) // Plain test volume; no secret is required.
	upstream, err := os.ReadFile(kvmSettings(t).UpstreamFirecracker)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(h.root, "bin", "firecracker"), upstream, 0500); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Start(t.Context(), "negative-lock", 1); err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatal("unpatched VMM not refused", err)
	}
	if prepared.Load() {
		t.Fatal("key capability reached unlocked VMM")
	}
	requireLock(t, path, false)
}
