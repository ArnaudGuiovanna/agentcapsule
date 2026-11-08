//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// The real mTLS probe is exercised here; there is no VMM/physical census fixture.
// Product adoption and retirement are separate KVM integration scenarios.
func contractProbeClient(t *testing.T, mode string, calls *atomic.Int32) *capsuleprotocol.Client {
	t.Helper()
	id := capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	host, guest, err := capsuleprotocol.NewCredentials(id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"protocol": capsuleprotocol.Version, "identity": id}
		if r.URL.Path == "/v1/health" {
			out["previous_shutdown"] = capsuleprotocol.ShutdownClean
		} else {
			attempt := calls.Add(1)
			switch {
			case mode == "legacy":
				out["code"] = "unknown_operation"
				w.WriteHeader(http.StatusNotFound)
			case mode == "outage" || (mode == "recover" && attempt == 1):
				out["code"] = "volume_unavailable"
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				w.Header().Set("X-Capsule-Protocol", capsuleprotocol.Version)
				out["features"] = []capsuleprotocol.ControlFeature{capsuleprotocol.ControlHealth, capsuleprotocol.ControlFences,
					capsuleprotocol.ControlEvents, capsuleprotocol.ControlInvokeText}
				out["limits"] = capsuleprotocol.ControlLimits{MessageBytes: capsuleprotocol.MaxMessageBytes, ContentBytes: capsuleprotocol.MaxContentBytes}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, listener, guest, handler) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewClient(host, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestControlReadinessRequiresNegotiationAfterHealth(t *testing.T) {
	var calls atomic.Int32
	client := contractProbeClient(t, "legacy", &calls)
	if err := client.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := waitControlReady(ctx, client); !errors.Is(err, capsuleprotocol.ErrCapabilitiesUnavailable) {
		t.Fatal("legacy health became application readiness", err)
	}
	if calls.Load() != 1 {
		t.Fatal("permanent incompatibility was retried", calls.Load())
	}
}

func TestControlReadinessRetriesOnlyTransientTransportFailure(t *testing.T) {
	var calls atomic.Int32
	client := contractProbeClient(t, "recover", &calls)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := waitControlReady(ctx, client); err != nil || calls.Load() != 2 {
		t.Fatal("transient negotiation did not recover", calls.Load(), err)
	}
}

func TestUnavailableContractNeverMeansObsoleteGeneration(t *testing.T) {
	var calls atomic.Int32
	client := contractProbeClient(t, "outage", &calls)
	err := checkControlContract(t.Context(), client)
	if !errors.Is(err, capsuleprotocol.ErrTransport) || errors.Is(err, ErrGeneration) || errors.Is(err, ErrNoVM) {
		t.Fatal("network outage became physical absence", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err = waitControlReady(ctx, client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("readiness exceeded its deadline", err)
	}
}

func TestControlObservationFailureBlocksAdmissionWithoutClaimingAbsence(t *testing.T) {
	sqlFailure := errors.New("injected SQL failure")
	var calls atomic.Int32
	client := contractProbeClient(t, "compatible", &calls)
	observed := false
	host := &FirecrackerHost{opts: FirecrackerOptions{ObserveControl: func(ctx context.Context, id string, run VMRun, compatible bool) error {
		if id != "a" || run.ID != "boot" || !compatible {
			t.Fatal("wrong observation")
		}
		observed = true
		return sqlFailure
	}}}
	err := host.observeControlResult(t.Context(), "a", VMRun{ID: "boot"}, checkControlContract(t.Context(), client))
	if !observed || !errors.Is(err, sqlFailure) || errors.Is(err, ErrGeneration) || errors.Is(err, ErrNoVM) {
		t.Fatal("SQL failure granted admission or implied absence", err)
	}
}

func TestFailedControlProbeInvalidatesObservationDespiteCanceledDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	observed := false
	host := &FirecrackerHost{opts: FirecrackerOptions{ObserveControl: func(ctx context.Context, id string, run VMRun, compatible bool) error {
		if compatible || ctx.Err() != nil {
			t.Fatal("failed probe kept readiness or inherited cancellation")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("invalidation cleanup is unbounded")
		}
		observed = true
		return nil
	}}}
	err := host.observeControlResult(ctx, "a", VMRun{ID: "boot"}, context.DeadlineExceeded)
	if !observed || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("canceled probe did not invalidate", err)
	}
}
