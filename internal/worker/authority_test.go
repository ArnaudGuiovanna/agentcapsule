//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// withAuthority gives the boot lab's worker both authorities, through
// implementation; register enrolls the lab's store. The keys it holds are
// counted in b.keys.
func (b *bootLab) withAuthority(t *testing.T, implementation string, register bool) *testAuthority {
	t.Helper()
	keys := b.keys.Provider.(*keyauthority.Files)
	a := openAuthority(t, implementation, keys, filepath.Join(t.TempDir(), "authority"))
	a.observed = b.keys
	if register {
		if _, err := a.Register(t.Context(), b.e.AgentID, b.e.VolumeID); err != nil {
			t.Fatal(err)
		}
	}
	b.w.authority = a
	var err error
	b.opts, err = b.w.runtimeOptions(runtime.FirecrackerOptions{AuthenticatedControl: true}, b.keys)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBootAuthorityRefusesBeforeKeyDelivery(t *testing.T) {
	forEachAuthority(t, testBootAuthorityRefusesBeforeKeyDelivery)
}

func testBootAuthorityRefusesBeforeKeyDelivery(t *testing.T, implementation string) {
	for _, failure := range []string{"missing", "reserved", "sealed", "unavailable", "wrong-boot"} {
		t.Run(failure, func(t *testing.T) {
			b := newBootLab(t)
			a := b.withAuthority(t, implementation, failure != "missing")
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
	forEachAuthority(t, testBootAuthorityRechecksAfterAuthenticatedACK)
}

func testBootAuthorityRechecksAfterAuthenticatedACK(t *testing.T, implementation string) {
	b := newBootLab(t)
	a := b.withAuthority(t, implementation, true)
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
	forEachAuthority(t, testBootAuthorityAdoptionDistinguishesStaleFromOutage)
}

func testBootAuthorityAdoptionDistinguishesStaleFromOutage(t *testing.T, implementation string) {
	for _, failure := range []string{"reserved", "sealed", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			b := newBootLab(t)
			a := b.withAuthority(t, implementation, true)
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
			switch failure {
			case "reserved":
				if _, err := a.ReserveIncarnation(t.Context(), enrollmentBinding(b.e), "restore"); err != nil {
					t.Fatal(err)
				}
			case "sealed":
				if err := a.RecordRetiredSeal(t.Context(), enrollmentBinding(b.e)); err != nil {
					t.Fatal(err)
				}
			default:
				if err := a.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// A stale or sealed binding makes the VM obsolete: the host
			// retires it at its next adoption. An outage keeps it.
			err := b.opts.Adopt(t.Context(), b.e.AgentID, run)
			if err == nil || errors.Is(err, runtime.ErrGeneration) != (failure != "unavailable") {
				t.Fatal("adoption lost failure distinction", err)
			}
		})
	}
}

// While the authority service is down, the worker keeps its VMs: adoption
// treats the outage as an outage, never as a stale binding, and a platform
// call fails with an error the guest can retry. Once the service is back,
// the same VM is adopted again (ADR 006 §4).
func TestWorkerKeepsItsVMsWhileTheServiceIsDown(t *testing.T) {
	b := newBootLab(t)
	a := b.withAuthority(t, throughService, true)
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
	api := platformAPI{store: b.w.store, caller: controlplane.VMCaller{AgentID: b.e.AgentID, HostID: b.e.HostID}, authority: b.w.authority, incarnation: 1}
	a.service.stop(t)
	err := b.opts.Adopt(t.Context(), b.e.AgentID, run)
	if err == nil || errors.Is(err, runtime.ErrGeneration) || !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("an outage of the service retired the VM", err)
	}
	if _, err = b.opts.ResolveIncarnation(t.Context(), b.e.AgentID); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("an incarnation resolved without the service", err)
	}
	err = api.withIdentity(t.Context(), func(context.Context) error { t.Error("a platform call without the service"); return nil })
	if !errors.Is(err, restoreauthority.ErrUnavailable) || platformError(err) == nil {
		t.Fatal("a platform call ran without the service", err)
	}
	var e *capsuleprotocol.PlatformError
	if !errors.As(platformError(err), &e) || e.Code != "unavailable" {
		t.Fatal("a platform call failed without a retryable error", platformError(err))
	}
	a.service.restart(t)
	if err = b.opts.Adopt(t.Context(), b.e.AgentID, run); err != nil {
		t.Fatal("the VM was not adopted once the service was back", err)
	}
}
