//go:build linux && cgo

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

func (b *bootLab) withAuthority(t *testing.T, register bool) *restoreauthority.Catalog {
	t.Helper()
	keys := b.keys.Provider.(*keyauthority.Files)
	a, err := restoreauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	if register {
		if _, err = a.Register(t.Context(), b.e.AgentID, b.e.VolumeID); err != nil {
			t.Fatal(err)
		}
	}
	b.w.authority = a
	b.opts, err = b.w.runtimeOptions(runtime.FirecrackerOptions{AuthenticatedControl: true}, b.keys)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBootAuthorityRefusesBeforeKeyDelivery(t *testing.T) {
	for _, failure := range []string{"missing", "reserved", "sealed", "unavailable", "wrong-boot"} {
		t.Run(failure, func(t *testing.T) {
			b := newBootLab(t)
			a := b.withAuthority(t, failure != "missing")
			run := b.claim(t)
			client := bootClient(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error {
				t.Error("obsolete boot received the volume key")
				return nil
			}, false)
			switch failure {
			case "reserved":
				if _, err := a.ReserveIncarnation(t.Context(), enrollmentBinding(b.e), "restore"); err != nil {
					t.Fatal(err)
				}
			case "sealed":
				if err := a.RecordRetiredSeal(t.Context(), enrollmentBinding(b.e)); err != nil {
					t.Fatal(err)
				}
			case "unavailable":
				if err := a.Close(); err != nil {
					t.Fatal(err)
				}
			case "wrong-boot":
				run.Incarnation++
			}
			if failure != "wrong-boot" {
				if _, err := b.opts.ResolveIncarnation(t.Context(), b.e.AgentID); err == nil {
					t.Fatal("obsolete identity resolved")
				}
			}
			if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err == nil {
				t.Fatal("obsolete boot prepared")
			}
			if b.keys.uses != 0 || b.initialized(t) {
				t.Fatal("failed gate granted key or initialization")
			}
			if failure == "missing" {
				if _, err := a.Lookup(t.Context(), b.e.AgentID); !errors.Is(err, restoreauthority.ErrStale) {
					t.Fatal("boot enrolled missing store", err)
				}
			}
		})
	}
}

func TestBootAuthorityRechecksAfterAuthenticatedACK(t *testing.T) {
	b := newBootLab(t)
	a := b.withAuthority(t, true)
	run := b.claim(t)
	client := bootClient(t, b.e.AgentID, run, func(v capsuleprotocol.VolumeBoot, _ []byte) error {
		if v.Incarnation != run.Incarnation {
			t.Error("bootstrap lost incarnation")
		}
		return nil
	}, true) // actual lost response + idempotent authenticated retry
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReserveIncarnation(t.Context(), enrollmentBinding(b.e), "restore-after-ack"); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("old ACK confirmed", err)
	}
	if b.initialized(t) {
		t.Fatal("old ACK initialized replacement")
	}
	var state string
	if err := b.db.QueryRow(t.Context(), "SELECT state FROM agent_placements WHERE agent_id=$1", b.e.AgentID).Scan(&state); err != nil || state != "STARTING" {
		t.Fatal(state, err)
	}
}

func TestBootAuthorityAdoptionDistinguishesStaleFromOutage(t *testing.T) {
	for _, failure := range []string{"reserved", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			b := newBootLab(t)
			a := b.withAuthority(t, true)
			run := b.claim(t)
			client := bootClient(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { return nil }, false)
			if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
				t.Fatal(err)
			}
			if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); err != nil {
				t.Fatal(err)
			}
			if err := b.opts.Adopt(t.Context(), b.e.AgentID, run); err != nil {
				t.Fatal("current boot not adoptable", err)
			}
			if failure == "reserved" {
				if _, err := a.ReserveIncarnation(t.Context(), enrollmentBinding(b.e), "restore"); err != nil {
					t.Fatal(err)
				}
			} else if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			err := b.opts.Adopt(t.Context(), b.e.AgentID, run)
			if err == nil || errors.Is(err, runtime.ErrGeneration) != (failure == "reserved") {
				t.Fatal("adoption lost failure distinction", err)
			}
		})
	}
}

func TestRestoreAuthorityConfigurationRequiresExistingPinnedCatalogue(t *testing.T) {
	root := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := restoreauthority.Initialize(t.Context(), filepath.Join(root, "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c := ServiceConfig{Root: filepath.Join(root, "runtime"), RestoreAuthority: &ServiceKeyAuthority{Root: filepath.Join(root, "authority"), Identity: a.Identity()}}
	opened, err := c.OpenRestoreAuthority(t.Context(), keys)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
	c.Root = root
	if _, err = c.OpenRestoreAuthority(t.Context(), keys); err == nil {
		t.Fatal("authority inside restored root")
	}
	c.Root = filepath.Join(root, "runtime")
	c.RestoreAuthority.Identity = "restoreauth_ffffffffffffffffffffffffffffffff"
	if _, err = c.OpenRestoreAuthority(t.Context(), keys); err == nil {
		t.Fatal("foreign identity accepted")
	}
	c.RestoreAuthority.Identity = a.Identity()
	c.RestoreAuthority.Root = filepath.Join(root, "missing")
	if _, err = c.OpenRestoreAuthority(t.Context(), keys); err == nil {
		t.Fatal("missing authority initialized")
	}
	if _, err = os.Stat(c.RestoreAuthority.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup created missing authority", err)
	}
}

func TestProductConfigurationRequiresBothAuthorities(t *testing.T) {
	c := ServiceConfig{Version: 1, HostID: "host", BootTimeout: "30s", BootLease: "2m", PollInterval: "1s", AttemptTimeout: "45s"}
	if _, _, _, err := c.Settings(); err != nil {
		t.Fatal("explicit legacy probe configuration", err)
	}
	c.KeyAuthority = &ServiceKeyAuthority{}
	if _, _, _, err := c.Settings(); err == nil {
		t.Fatal("encrypted service without independent authority")
	}
	c.RestoreAuthority = &ServiceKeyAuthority{}
	if _, _, _, err := c.Settings(); err != nil {
		t.Fatal("paired configuration", err)
	}
	c.KeyAuthority = nil
	if _, _, _, err := c.Settings(); err == nil {
		t.Fatal("independent catalogue without key authority")
	}
}
