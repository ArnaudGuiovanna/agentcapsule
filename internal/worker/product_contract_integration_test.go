//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// A real product VMM remains alive while its host control transport is hidden.
// This tests an unreachable negotiated contract, not a legacy image/profile.
func TestProductWorkerContractOutagePreservesCensusAndMaintenance(t *testing.T) {
	c := config(t)
	b := newBootReservation(t, false, "sha256:"+digest(t, c.Initrd))
	root, err := os.MkdirTemp(c.RootParent, "product-contract-")
	if err != nil {
		t.Fatal(err)
	}
	options := opts(t, root)
	options.AuthenticatedControl, options.Ready, options.BootTimeout = true, nil, time.Minute
	keys := b.keys.Provider.(*keyauthority.Files)
	authority, err := restoreauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	w, err := NewProvisioningPlacements(b.w.store, b.e.HostID, "contract-installer", 2*time.Minute, options, keys, authority, ProvisioningConfig{FirstUID: 62400, LastUID: 62409})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := w.host.Retire(ctx, b.e.AgentID, ^uint64(0)); err != nil {
			t.Error(err)
		}
		w.Close()
	})
	job := controlplane.WorkerJob{HostID: b.e.HostID, AgentID: b.e.AgentID, ID: b.e.OperationID, Kind: "provision"}
	if err = w.provision(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	run, err := w.Start(t.Context(), b.e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewAgentCatalog(b.accounts, b.e.HostID)
	if err != nil {
		t.Fatal(err)
	}
	view := func(want string) {
		t.Helper()
		v, err := catalog.Get(t.Context(), b.admin, b.e.AgentID)
		if err != nil || v.State != want {
			t.Fatal("application state", v.State, want, err)
		}
	}
	view("READY")
	// Simulate a worker restart: physical adoption must work with no RPC.
	w.Close()
	next, err := NewProvisioningPlacements(b.w.store, b.e.HostID, "contract-adopter", 2*time.Minute, options, keys, authority, ProvisioningConfig{FirstUID: 62400, LastUID: 62409})
	if err != nil {
		t.Fatal(err)
	}
	w = next
	hidden := run.Socket + ".hidden"
	if err = os.Rename(run.Socket, hidden); err != nil {
		t.Fatal(err)
	}
	adopted, err := w.Reconcile(t.Context())
	if err != nil || adopted[b.e.AgentID].ID != run.ID || adopted[b.e.AgentID].PID != run.PID {
		t.Fatal("transport outage lost physical census", adopted, err)
	}
	if _, err = w.host.Control(t.Context(), b.e.AgentID); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("unreachable control admitted", err)
	}
	view("STARTING")
	receipt, err := catalog.RequestLifecycle(t.Context(), b.admin, b.e.AgentID, "wake-during-outage", "wake")
	if err != nil {
		t.Fatal(err)
	}
	var accepted controlplane.AgentCreation
	if err = json.Unmarshal(receipt.Body, &accepted); err != nil {
		t.Fatal(err)
	}
	wake := controlplane.WorkerJob{HostID: b.e.HostID, AgentID: b.e.AgentID, ID: accepted.OperationID, Kind: "wake"}
	if err = w.lifecycleOperation(t.Context(), wake); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("physical adoption completed wake", err)
	}
	operation, err := catalog.Operation(t.Context(), b.admin, accepted.OperationID)
	if err != nil || operation.Status != "RUNNING" {
		t.Fatal("failed negotiation completed wake", operation, err)
	}
	adopted, err = w.Reconcile(t.Context())
	if err != nil || adopted[b.e.AgentID].ID != run.ID {
		t.Fatal("failed wake retired live VMM", err)
	}
	if err = os.Rename(hidden, run.Socket); err != nil {
		t.Fatal(err)
	}
	if err = w.lifecycleOperation(t.Context(), wake); err != nil {
		t.Fatal("recovered contract did not complete wake", err)
	}
	view("READY")

	// Expiring credentials can be replaced while the old transport is absent.
	if err = os.Rename(run.Socket, hidden); err != nil {
		t.Fatal(err)
	}
	w.credentialNow = func() time.Time { return time.Now().Add(24 * time.Hour) }
	if err = w.refreshCredentials(t.Context(), 90*time.Second); err != nil {
		t.Fatal("contract outage blocked rotation", err)
	}
	w.credentialNow = nil
	adopted, err = w.Reconcile(t.Context())
	if err != nil || adopted[b.e.AgentID].Generation <= run.Generation {
		t.Fatal("rotation did not replace old generation", err)
	}
	run = adopted[b.e.AgentID]
	view("READY")

	// A black-holed control session consumes the operation deadline only AFTER
	// STOPPING. The independent physical cleanup must still run and mark unclean.
	if err = os.Rename(run.Socket, run.Socket+".hidden"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", run.Socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	stopping := false
	w.afterStopIntent = func() { stopping = true }
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	err = w.Stop(ctx, b.e.AgentID, run.Generation)
	cancel()
	if err != nil || !stopping {
		t.Fatal("negotiation timeout prevented durable stop/retirement", stopping, err)
	}
	var state string
	var unclean bool
	if err = b.db.QueryRow(t.Context(), "SELECT state,unclean_stop FROM agent_placements WHERE agent_id=$1", b.e.AgentID).Scan(&state, &unclean); err != nil || state != "STOPPED" || !unclean {
		t.Fatal("forced stop outcome", state, unclean, err)
	}
	adopted, err = w.Reconcile(t.Context())
	if err != nil || len(adopted) != 0 {
		t.Fatal("forced stop retained VMM", adopted, err)
	}
}
