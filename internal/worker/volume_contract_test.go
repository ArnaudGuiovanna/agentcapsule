//go:build linux

package worker

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func TestVolumeContractFailureCannotConfirmInitialization(t *testing.T) {
	for _, mode := range []string{"legacy", "missing-fences", "smaller-limit"} {
		t.Run(mode, func(t *testing.T) {
			b := newBootLab(t)
			run := b.claim(t)
			identity := capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: b.e.AgentID, VMID: run.ID, Generation: run.Generation, FenceOnly: true}
			contract := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				out := map[string]any{"protocol": capsuleprotocol.Version, "identity": identity}
				if mode == "legacy" {
					out["code"] = "unknown_operation"
					w.WriteHeader(http.StatusNotFound)
				} else {
					w.Header().Set("X-Capsule-Protocol", capsuleprotocol.Version)
					out["features"] = []capsuleprotocol.ControlFeature{capsuleprotocol.ControlHealth}
					out["limits"] = capsuleprotocol.ControlLimits{MessageBytes: capsuleprotocol.MaxMessageBytes, ContentBytes: capsuleprotocol.MaxContentBytes}
					if mode == "smaller-limit" {
						out["features"] = []capsuleprotocol.ControlFeature{capsuleprotocol.ControlHealth, capsuleprotocol.ControlFences}
						out["limits"] = capsuleprotocol.ControlLimits{MessageBytes: capsuleprotocol.MaxMessageBytes / 2, ContentBytes: capsuleprotocol.MaxContentBytes}
					}
				}
				_ = json.NewEncoder(w).Encode(out)
			})
			var opened atomic.Bool
			client, _ := bootClientHarnessContract(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { opened.Store(true); return nil }, false, nil, nil, contract)
			want := capsuleprotocol.ErrUnsupportedProtocol
			if mode == "legacy" {
				want = capsuleprotocol.ErrCapabilitiesUnavailable
			} else if mode == "missing-fences" {
				want = capsuleprotocol.ErrProtocol
			}
			if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); !errors.Is(err, want) {
				t.Fatal("incompatible boot prepared", err)
			}
			if !opened.Load() {
				t.Fatal("test did not reach post-volume contract gate")
			}
			if err := client.Health(t.Context()); err != nil {
				t.Fatal("test guest not healthy", err)
			}
			if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
				t.Fatal("contract failure confirmed initialization", err)
			}
			if b.initialized(t) {
				t.Fatal("failed contract published initialized enrollment")
			}
			var state string
			if err := b.db.QueryRow(t.Context(), "SELECT state FROM agent_placements WHERE agent_id=$1", b.e.AgentID).Scan(&state); err != nil || state != "STARTING" {
				t.Fatal("failed contract published RUNNING", state, err)
			}
		})
	}
}
