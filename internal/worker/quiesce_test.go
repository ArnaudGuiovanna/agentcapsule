//go:build linux

package worker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// Real PostgreSQL and per-boot mTLS exercise the commit/RPC boundary. The retire
// callback is an explicit physical observation fixture, not a running VMM.
func TestQuiesceStopRequiresGuestACKAndPhysicalRetirement(t *testing.T) {
	for _, mode := range []string{"clean", "failed_close", "lost_ack", "failed_retirement", "canceled", "wrong_generation", "no_control"} {
		t.Run(mode, func(t *testing.T) {
			b := newBootLab(t)
			run := b.claim(t)
			if err := b.w.store.ConfirmFencePlacement(t.Context(), b.e.AgentID, b.e.HostID, b.w.workerID, run.Generation, run.ID); err != nil {
				t.Fatal(err)
			}
			identity := capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: b.e.AgentID, VMID: run.ID, Generation: run.Generation, FenceOnly: true}
			if mode == "wrong_generation" {
				identity.Generation++
			}
			h, g, err := capsuleprotocol.NewCredentials(identity, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			state := func(ctx context.Context) (string, bool, error) {
				var status string
				var unclean bool
				err := b.db.QueryRow(ctx, "SELECT state,unclean_stop FROM agent_placements WHERE agent_id=$1", b.e.AgentID).Scan(&status, &unclean)
				return status, unclean, err
			}
			var calls atomic.Int32
			server, err := capsuleprotocol.NewQuiescingVolumeServer(g, func(context.Context, capsuleprotocol.VolumeBoot, []byte) (http.Handler, error) {
				return http.NotFoundHandler(), nil
			},
				func(ctx context.Context) error {
					calls.Add(1)
					status, _, err := state(ctx)
					if err != nil || status != "STOPPING" {
						return errors.New("guest quiesce preceded durable intent")
					}
					if err = b.w.store.ValidatePlacement(ctx, b.e.AgentID, b.e.HostID, run.Generation, run.ID); !errors.Is(err, controlplane.ErrPlacement) {
						return errors.New("stopping boot retained SQL authority")
					}
					if mode == "failed_close" {
						return errors.New("filesystem synchronization failed")
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			lifetime, stopServer := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- capsuleprotocol.ServeAuthenticated(lifetime, listener, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "lost_ack" && r.URL.Path == "/v1/lifecycle/quiesce" {
						server.ServeHTTP(lostBootACK{w}, r)
					} else {
						server.ServeHTTP(w, r)
					}
				}))
			}()
			t.Cleanup(func() { stopServer(); <-done })
			client, err := capsuleprotocol.NewClient(h, func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			command, err := volumeCommand(controlplane.VolumeBootPlan{Enrollment: b.e, Initialize: true})
			if err != nil {
				t.Fatal(err)
			}
			if err = client.OpenVolume(t.Context(), command, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "canceled" {
				b.w.afterStopIntent = cancel
			}
			var retirement runtime.RetirementControl = client
			if mode == "no_control" {
				retirement = nil
			}
			retired := false
			retire := func(ctx context.Context) error {
				if ctx.Err() != nil {
					t.Fatal("cleanup inherited canceled RPC context")
				}
				status, _, err := state(ctx)
				if err != nil || status != "STOPPING" {
					t.Fatal("physical retirement preceded intent or STOPPED published early", status, err)
				}
				if mode == "failed_retirement" {
					return errors.New("VMM still alive")
				}
				retired = true
				return nil
			}
			err = b.w.stopPrepared(ctx, b.e.AgentID, run.Generation, retirement, retire)
			status, unclean, queryErr := state(t.Context())
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if mode == "wrong_generation" {
				if !errors.Is(err, controlplane.ErrPlacement) || status != "RUNNING" || retired || calls.Load() != 0 {
					t.Fatal("wrong boot changed current placement", err, status)
				}
				return
			}
			if mode == "failed_retirement" {
				if err == nil || status != "STOPPING" || retired {
					t.Fatal("guest ACK treated as physical absence", err, status)
				}
				return
			}
			if err != nil || status != "STOPPED" || !retired || unclean != (mode != "clean") {
				t.Fatal("incorrect shutdown outcome", err, status, retired, unclean)
			}
			if mode != "canceled" && mode != "no_control" && calls.Load() != 1 {
				t.Fatal("shutdown callback missing or repeated", calls.Load())
			}
		})
	}
}
