//go:build linux

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Real local registry/inode tests. No VMM is started; the KVM campaign remains
// responsible for proving cgroup retirement before the execution seal.
func TestSealedVolumeRemovalRetryAndFutureFence(t *testing.T) {
	h := admissionHost(t)
	path := filepath.Join(h.root, "volumes", "a")
	if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents["a"].Device, r.Agents["a"].Inode = uint64(id.Dev), id.Ino
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err = h.RemoveSealedVolume(t.Context(), "a", 0, func(StoreSeal) error { called = true; return nil }); err == nil || called {
		t.Fatal("unsealed cleanup entered", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err = h.SealAgent(t.Context(), "a", 0); !errors.Is(err, ErrVolumeBusy) {
		t.Fatal("busy volume sealed", err)
	}
	f.Close()
	proof, err := h.SealAgent(t.Context(), "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.RemoveSealedVolume(t.Context(), "a", 1, func(StoreSeal) error { t.Error("wrong generation callback"); return nil }); !errors.Is(err, ErrGeneration) {
		t.Fatal(err)
	}
	if _, err = h.RemoveSealedVolume(t.Context(), "a", 0, func(StoreSeal) error { return nil }); err == nil {
		t.Fatal("present volume acknowledged removed")
	}
	lost := errors.New("lost cleanup outcome")
	if _, err = h.RemoveSealedVolume(t.Context(), "a", 0, func(p StoreSeal) error {
		if p != proof {
			t.Fatal("changed seal")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		return lost
	}); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	if _, err = h.SealAgent(t.Context(), "a", 0); err == nil {
		t.Fatal("uncertain cleanup used as fence ACK")
	}
	// A fresh host reads the same durable seal and resumes the callback. Actual
	// cleanup uses the volume journal to distinguish this from unexplained loss.
	h = &FirecrackerHost{root: h.root}
	got, err := h.RemoveSealedVolume(t.Context(), "a", 0, func(StoreSeal) error { return removedVolume(path) })
	if err != nil || got != proof {
		t.Fatal(got, err)
	}
	got, err = h.SealAgent(t.Context(), "a", 0)
	if err != nil || got != proof {
		t.Fatal("retired volume cannot acknowledge later fence", got, err)
	}
	if err = os.WriteFile(path, []byte("restored old data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = h.SealAgent(t.Context(), "a", 0); err == nil {
		t.Fatal("restored file ignored")
	}
}

// One agent whose attempt cannot be cleaned must not stop the others from being
// recovered, and the cleanups that succeeded must be persisted. Map iteration is
// random, so the scenario is repeated.
func TestRecoverIsolatesAFailingAgent(t *testing.T) {
	for round := range 12 {
		h := admissionHost(t)
		h.cgroup = filepath.Join(h.root, "groups")
		if err := os.MkdirAll(filepath.Join(h.root, "credentials"), 0700); err != nil {
			t.Fatal(err)
		}
		r := &hostRegistry{Version: 1, Agents: map[string]*HostAgent{}}
		for i := range 8 {
			id := fmt.Sprintf("agent-%d", i)
			r.Agents[id] = &HostAgent{ID: id, Run: &VMRun{ID: fmt.Sprintf("%016x", round*100+i), Generation: 1, Phase: "STARTING"}}
		}
		bad := r.Agents["agent-3"]
		// A non-empty cgroup directory cannot be removed, so cleanup fails.
		group := h.group(bad.Run)
		if err := os.MkdirAll(group, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(group, "occupied"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		err := h.recover(t.Context(), r)
		if err == nil || !strings.Contains(err.Error(), "agent-3") {
			t.Fatal("failure of one agent was not reported:", err)
		}
		for id, a := range r.Agents {
			if id == "agent-3" {
				if a.Run == nil {
					t.Fatal("failing agent lost its run record")
				}
				continue
			}
			if a.Run != nil {
				t.Fatalf("round %d: %s was left unrecovered by another agent's failure", round, id)
			}
		}
		saved, err := os.ReadFile(filepath.Join(h.root, "registry.json"))
		if err != nil {
			t.Fatal("recovery progress was not persisted:", err)
		}
		var onDisk hostRegistry
		if err = json.Unmarshal(saved, &onDisk); err != nil {
			t.Fatal(err)
		}
		if onDisk.Agents["agent-0"] == nil || onDisk.Agents["agent-0"].Run != nil || onDisk.Agents["agent-3"].Run == nil {
			t.Fatal("persisted registry does not match the recovered state")
		}
	}
}
