package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// A local boot exercises the production mTLS server and durable harness store.
// It is NOT a VMM. Allocation/publication/retirement are environment inputs to
// the SQL projection, not observations of the Firecracker host registry.
type p1Boot struct {
	host     capsuleprotocol.Credentials
	client   *capsuleprotocol.Client
	dial     func(context.Context) (net.Conn, error)
	store    *harnessstore.Store
	cancel   context.CancelFunc
	done     chan error
	mu       sync.Mutex
	closing  bool
	handlers sync.WaitGroup
	gates    map[string]*p1EffectGate
}

type p1EffectGate struct {
	entered chan struct{}
	release chan struct{}
}

func (a *p1Replay) launchLocal(t *testing.T, agent int, restricted bool) *p1Boot {
	t.Helper()
	id := a.callers[agent]
	host, guest, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{Incarnation: 1,
		AgentID: id.AgentID, Generation: id.Generation, VMID: id.VMID, FenceOnly: restricted,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte(id.AgentID))))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := harnessstore.Open(t.Context(), filepath.Join(dir, "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	b := &p1Boot{host: host, store: store, gates: map[string]*p1EffectGate{}}
	server, err := capsuleprotocol.NewServer(guest, capsuleprotocol.ShutdownUnclean, store, func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		b.mu.Lock()
		gate := b.gates[e.ID]
		b.mu.Unlock()
		if gate == nil {
			return nil, errors.New("effect reached local application without an execution gate")
		}
		result, err := recordDelivery(ctx, id.AgentID, e, tx)
		close(gate.entered)
		if err != nil {
			return nil, err
		}
		select {
		case <-gate.release:
			return result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	b.cancel, b.done = cancel, make(chan error, 1)
	// Close admission under the same mutex as Add before waiting at shutdown.
	// A canceled HTTP client alone does not establish that its SQL writer exited.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		if b.closing {
			b.mu.Unlock()
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		b.handlers.Add(1)
		b.mu.Unlock()
		defer b.handlers.Done()
		server.ServeHTTP(w, r)
	})
	go func() { b.done <- capsuleprotocol.ServeAuthenticated(ctx, l, guest, handler) }()
	b.dial = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	b.client, err = capsuleprotocol.NewClient(host, b.dial)
	t.Cleanup(func() { b.stop(t) })
	if err != nil {
		t.Fatal(err)
	}
	if err := b.client.Health(t.Context()); err != nil {
		t.Fatal("local boot authentication", err)
	}
	if restricted {
		_, err := b.client.Send(t.Context(), harnessstore.Event{ID: "restricted-probe", Subjects: []string{"agent/" + id.AgentID}})
		if !errors.Is(err, capsuleprotocol.ErrFenceOnly) {
			t.Fatal("restricted boot did not reject application delivery", err)
		}
	}
	return b
}

func (b *p1Boot) stop(t *testing.T) {
	t.Helper()
	if b == nil || b.cancel == nil {
		return
	}
	b.mu.Lock()
	b.closing = true
	b.mu.Unlock()
	b.cancel()
	select {
	case err := <-b.done:
		if !errors.Is(err, context.Canceled) {
			t.Error("local server shutdown", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("local server did not stop")
	}
	drained := make(chan struct{})
	go func() { b.handlers.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(6 * time.Second):
		t.Fatal("local server left an application handler running")
	}
	if err := b.store.Close(); err != nil {
		t.Error(err)
	}
	b.cancel = nil
}

func p1AgentNumber(id string) int {
	for i := range 3 {
		if p1Agent(i) == id {
			return i
		}
	}
	panic("unbound P1 agent")
}

func (a *p1Replay) stopLocal(t *testing.T, agent int) {
	t.Helper()
	a.boots[agent].stop(t)
	// Only ExecutingRPC is aborted by physicallyStopped/bootRetired. A sent
	// but not started message keeps its old credentials for the refusal test.
	for slot, r := range a.rpc {
		if r == nil || r.attempt.Destination != p1Agent(agent) || !r.executing {
			continue
		}
		r.cancel()
		if r.done != nil {
			select {
			case err := <-r.done:
				if err == nil {
					t.Fatal("interrupted writer returned success")
				}
			case <-time.After(6 * time.Second):
				t.Fatal("interrupted client did not finish")
			}
		}
		a.rpc[slot] = nil
	}
}

func (a *p1Replay) lifecycleStep(t *testing.T, op protocolAction) (bool, error) {
	t.Helper()
	switch op.Name {
	case "stopVM", "retireBoot", "observeStopped", "bootVM", "launchBoot", "confirmBoot",
		"publishBoot", "expireBootLease", "abandonBoot", "beginStop":
	default:
		return false, nil
	}
	agent := p1Int(op.Args[0])
	id := a.callers[agent]
	switch op.Name {
	case "stopVM", "retireBoot":
		a.stopLocal(t, agent)
	case "observeStopped":
		// The physical retirement precondition is an explicit fixture here.
		// Only KVM tests can establish the production host's retirement proof.
		return true, a.s.ObservePlacementStopped(t.Context(), id.AgentID, id.HostID, id.Generation, true)
	case "bootVM":
		var p Placement
		var err error
		if op.Args[1].(bool) {
			p, err = a.s.ClaimFencePlacement(t.Context(), id.AgentID, id.HostID, "worker", time.Hour)
		} else {
			p, err = a.s.ClaimPlacement(t.Context(), id.AgentID, id.HostID, "worker", time.Hour)
		}
		if err != nil {
			return true, err
		}
		a.callers[agent] = VMCaller{AgentID: id.AgentID, HostID: id.HostID, Generation: p.Generation, VMID: fmt.Sprintf("%016x", p.Generation)}
		a.restricted[agent] = p.FenceOnly
	case "launchBoot":
		a.boots[agent] = a.launchLocal(t, agent, a.restricted[agent])
	case "confirmBoot":
		if a.restricted[agent] {
			return true, a.s.ConfirmFencePlacement(t.Context(), id.AgentID, id.HostID, "worker", id.Generation, id.VMID)
		}
		return true, a.s.ConfirmPlacement(t.Context(), id.AgentID, id.HostID, "worker", id.Generation, id.VMID)
	case "beginStop":
		return true, a.s.BeginPlacementStop(t.Context(), id.AgentID, id.HostID, id.Generation)
	case "expireBootLease":
		_, err := a.s.pool.Exec(t.Context(), "UPDATE agent_placements SET lease_until=clock_timestamp()-interval '1 second' WHERE agent_id=$1", id.AgentID)
		return true, err
	case "publishBoot", "abandonBoot":
		// No SQL mutation; publication/start ownership belong to the excluded
		// host registry. Do not manufacture matching state in this adapter.
	}
	return true, nil
}
