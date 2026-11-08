//go:build linux && cgo && kvm_integration && kvm_product_integration

package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// This is a privileged host/SQL/SQLite projection, not a three-VM ITF replay.
// Initial placements and VMM retirement remain fixtures. The local mTLS server
// really drains/closes, and the host seals the SAME SQLite inode it used.
// Separate product KVM tests establish retirement of actual guest processes.
func TestPreimplementationP1HostSealITF(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("host seal projection requires the isolated privileged runner")
	}
	runP1ITF(t, map[string]bool{"sealed-store-satisfies-future-barrier": true}, prepareP1HostSeal)
}

func prepareP1HostSeal(t *testing.T, a *p1Replay) p1ITFHooks {
	t.Helper()
	var config struct{ Firecracker, Jailer, Kernel, Initrd, RootParent, Output string }
	b, err := os.ReadFile(os.Getenv("AGENTCAPSULE_KVM_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &config); err != nil || config.RootParent == "" || config.Output == "" {
		t.Fatal("invalid isolated runtime configuration", err)
	}
	root, err := os.MkdirTemp(config.RootParent, "p1seal-")
	if err != nil {
		t.Fatal(err)
	}
	digest := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(b))
	}
	unexpectedBoot := func(context.Context, string, runtime.VMRun) error {
		return errors.New("this host projection must never launch a VMM")
	}
	options := runtime.FirecrackerOptions{Root: root, Firecracker: config.Firecracker, Jailer: config.Jailer,
		Kernel: config.Kernel, Initrd: config.Initrd, FirecrackerSHA256: digest(config.Firecracker),
		JailerSHA256: digest(config.Jailer), KernelSHA256: digest(config.Kernel), InitrdSHA256: digest(config.Initrd),
		MaxActive: 1, AuthenticatedControl: true, Confirm: unexpectedBoot, Adopt: unexpectedBoot}
	host, err := runtime.NewFirecrackerHost(options)
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte("b"))), "harness.db")
	volume := filepath.Join(root, "volumes", "b.sqlite")
	if err = os.Link(local, volume); err != nil {
		t.Fatal(err)
	}
	if err = host.Register(t.Context(), "b", volume, 62400); err != nil {
		t.Fatal(err)
	}
	var proof StoreSeal
	a.seal = func(t *testing.T, agent int) error {
		t.Helper()
		if agent != 1 {
			t.Fatal("unexpected store in the seal projection")
		}
		caller := a.callers[agent]
		p, ready, err := a.s.StoreSealTarget(t.Context(), caller.AgentID, caller.HostID)
		if err != nil {
			return err
		}
		if !ready {
			return ErrPendingFences
		}
		if a.boots[agent].cancel != nil {
			t.Fatal("local writer was not stopped and drained before the host seal")
		}
		if err := a.boots[agent].client.Health(t.Context()); err == nil {
			t.Fatal("sealed local server still responds")
		}
		return host.WithBarrier(t.Context(), caller.AgentID, func(ctx context.Context) error {
			got, err := host.SealAgent(ctx, caller.AgentID, p.Generation)
			if err != nil {
				return err
			}
			next := StoreSeal{AgentID: got.AgentID, HostID: caller.HostID, ID: got.ID,
				Generation: got.Generation, Device: got.Device, Inode: got.Inode}
			if proof.ID != "" && proof != next {
				t.Fatal("host changed its permanent seal receipt")
			}
			if err = a.s.RecordStoreSeal(ctx, next); err != nil {
				return err
			}
			proof = next
			return nil
		})
	}
	if err = a.seal(t, 1); !errors.Is(err, ErrPendingFences) {
		t.Fatal("live store accepted as permanently sealed", err)
	}
	return p1ITFHooks{
		state: func(t *testing.T, raw json.RawMessage, step int) {
			t.Helper()
			want := p1ITFSealed(t, raw, "1")
			p1Equal(t, step, "adapter seal", a.sealed[1], want)
			registry, err := os.ReadFile(filepath.Join(root, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record struct{ Agents map[string]runtime.HostAgent }
			if err = json.Unmarshal(registry, &record); err != nil {
				t.Fatal(err)
			}
			registered, ok := record.Agents["b"]
			if !ok || registered.Run != nil {
				t.Fatal("missing registered inode or unexpected VMM")
			}
			p1Equal(t, step, "host admission ban", registered.Fenced, want)
			p1Equal(t, step, "host durable seal", registered.SealID != "", want)
			p1Equal(t, step, "SQL seal census", count(t, a.s, "store_seals"), map[bool]int{false: 0, true: 1}[want])
			if want {
				var id, hostID, device, inode string
				var generation uint64
				err := a.s.pool.QueryRow(t.Context(), `SELECT seal_id,host_id,generation,volume_device,volume_inode
				 FROM store_seals WHERE agent_id='b'`).Scan(&id, &hostID, &generation, &device, &inode)
				if err != nil {
					t.Fatal(err)
				}
				p1Equal(t, step, "SQL/host seal binding", []any{id, hostID, generation, device, inode},
					[]any{registered.SealID, a.callers[1].HostID, registered.Generation,
						fmt.Sprintf("%016x", registered.Device), fmt.Sprintf("%016x", registered.Inode)})
				st, err := os.Stat(local)
				if err != nil {
					t.Fatal(err)
				}
				file := st.Sys().(*syscall.Stat_t)
				p1Equal(t, step, "original SQLite inode", []uint64{registered.Device, registered.Inode}, []uint64{uint64(file.Dev), file.Ino})
			}
		},
		final: func(t *testing.T) {
			t.Helper()
			if _, err := host.Start(t.Context(), "b", a.callers[1].Generation+1); !errors.Is(err, runtime.ErrHostFenced) {
				t.Fatal("sealed agent restarted", err)
			}
			// A remembered SQL receipt must not bypass fresh physical checks.
			if err := os.Rename(volume, volume+".offline"); err != nil {
				t.Fatal(err)
			}
			err := a.seal(t, 1)
			restored := os.Rename(volume+".offline", volume)
			if !errors.Is(err, os.ErrNotExist) || restored != nil {
				t.Fatal("missing registered name acknowledged", err, restored)
			}
			busy, err := os.OpenFile(volume, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = syscall.Flock(int(busy.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				busy.Close()
				t.Fatal(err)
			}
			err = a.seal(t, 1)
			closed := busy.Close()
			if !errors.Is(err, runtime.ErrVolumeBusy) || closed != nil {
				t.Fatal("registered writer ignored", err, closed)
			}
			host, err = runtime.NewFirecrackerHost(options)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.seal(t, 1); err != nil {
				t.Fatal("fresh host did not recover the same durable receipt", err)
			}
			out := filepath.Join(config.Output, "TestPreimplementationP1HostSealITF")
			if err = os.MkdirAll(out, 0700); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(root, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(out, "registry.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			t.Log("host/SQL/SQLite seal projection: same inode, 23 transitions/24 states; missing file, busy lock and restart refused; no VMM replay claimed")
		},
	}
}

func p1ITFSealed(t *testing.T, raw json.RawMessage, agent string) bool {
	t.Helper()
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	for key, value := range state {
		if !strings.HasSuffix(key, "::concurrentProtocol::s") {
			continue
		}
		var s struct {
			Agents struct {
				Entries [][]json.RawMessage `json:"#map"`
			}
		}
		if err := json.Unmarshal(value, &s); err != nil || len(s.Agents.Entries) != 3 {
			t.Fatal("malformed ITF agent inventory", err)
		}
		for _, pair := range s.Agents.Entries {
			if len(pair) != 2 {
				t.Fatal("malformed ITF agent entry")
			}
			var id map[string]string
			var observation struct{ Sealed *bool }
			if err := json.Unmarshal(pair[0], &id); err != nil {
				t.Fatal(err)
			}
			if id["#bigint"] == agent {
				if err := json.Unmarshal(pair[1], &observation); err != nil || observation.Sealed == nil {
					t.Fatal("missing ITF seal state", err)
				}
				return *observation.Sealed
			}
		}
	}
	t.Fatal("missing ITF agent state")
	return false
}
