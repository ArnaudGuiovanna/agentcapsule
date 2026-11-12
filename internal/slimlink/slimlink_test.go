package slimlink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentB = "agentcapsule/org_1/agt-b"

// bridge stands for the SLIM bridge: /v1/send calls the worker back on
// /v1/deliver, as the bridge serving the recipient's name does once the A2A
// message has crossed the SLIM node. Tests change what it forwards.
type bridge struct {
	t       *testing.T
	worker  *http.Client
	mu      sync.Mutex
	served  []string
	caller  string
	mutate  func(*DeliverRequest)
	answer  func(http.ResponseWriter, SendRequest) bool // true when it answered itself
	replays []DeliverRequest
}

func unixClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}}
}

func (b *bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case HealthPath:
		_ = json.NewEncoder(w).Encode(Health{Name: PlatformNamespace + "host-1"})
	case ServePath:
		var in ServeRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		b.mu.Lock()
		b.served = append(b.served, in.Name)
		b.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case SendPath:
		var in SendRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			b.t.Error(err)
			return
		}
		b.mu.Lock()
		answer, mutate, caller := b.answer, b.mutate, b.caller
		b.mu.Unlock()
		if answer != nil && answer(w, in) {
			return
		}
		call := DeliverRequest{To: in.To, Caller: caller, Nonce: in.Nonce, Event: in.Event}
		if mutate != nil {
			mutate(&call)
		}
		b.mu.Lock()
		b.replays = append(b.replays, call)
		b.mu.Unlock()
		body, _ := json.Marshal(call)
		res, err := b.worker.Post("http://worker"+DeliverPath, "application/json", bytes.NewReader(body))
		if err != nil {
			fail(w, http.StatusBadGateway, CodeUnreachable)
			return
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			fail(w, http.StatusBadGateway, CodeRefused)
			return
		}
		_, _ = w.Write(data)
	default:
		fail(w, http.StatusNotFound, CodeInvalid)
	}
}

// setup starts the worker's socket and the bridge's socket, both for the
// current user, and returns the worker's link.
func setup(t *testing.T) (*Link, *bridge, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "slimlink")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	uid := uint32(os.Getuid())
	bridgeSocket, workerSocket := filepath.Join(dir, "bridge.sock"), filepath.Join(dir, "worker.sock")
	link := Open(bridgeSocket, uid)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	wl, err := Listen(workerSocket, uid)
	if err != nil {
		t.Fatal(err)
	}
	b := &bridge{t: t, worker: unixClient(workerSocket), caller: PlatformNamespace + "host-1/0123"}
	bl, err := Listen(bridgeSocket, uid)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = ServeLocal(ctx, wl, link) }()
	go func() { defer wg.Done(); _ = ServeLocal(ctx, bl, b) }()
	t.Cleanup(wg.Wait)
	t.Cleanup(cancel)
	return link, b, workerSocket
}

func event() Event {
	return Event{ID: "evt-1", Subjects: []string{"request:arq_1"}, Body: []byte(`{"text":"hello"}`)}
}

// guest stands for the VM: it records the events delivered to it.
type guest struct {
	mu   sync.Mutex
	seen []Event
	err  error
}

func (g *guest) deliver(_ context.Context, e Event) (Receipt, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, e)
	if g.err != nil {
		return Receipt{}, g.err
	}
	return Receipt{Result: []byte("ok:" + e.ID), Replayed: len(g.seen) > 1}, nil
}

func TestADeliveryCrossesTheBridgeAndComesBackWithTheGuestsReceipt(t *testing.T) {
	link, b, _ := setup(t)
	ctx := t.Context()
	name, err := link.Health(ctx)
	if err != nil || name != PlatformNamespace+"host-1" {
		t.Fatal(name, err)
	}
	if err = link.Serve(ctx, agentB); err != nil || len(b.served) != 1 || b.served[0] != agentB {
		t.Fatal(err, b.served)
	}
	g := &guest{}
	r, err := link.Deliver(ctx, agentB, event(), g.deliver)
	if err != nil || string(r.Result) != "ok:evt-1" || r.Replayed {
		t.Fatal(r, err)
	}
	// The guest got the event that crossed the bridge, unchanged.
	if len(g.seen) != 1 || g.seen[0].ID != "evt-1" || string(g.seen[0].Body) != `{"text":"hello"}` || g.seen[0].Subjects[0] != "request:arq_1" {
		t.Fatal(g.seen)
	}
	// A redelivery of the same event is a new attempt; the guest says it replayed.
	if r, err = link.Deliver(ctx, agentB, event(), g.deliver); err != nil || !r.Replayed {
		t.Fatal(r, err)
	}
	if len(link.open) != 0 {
		t.Fatal("attempts left open", len(link.open))
	}
}

func TestTheGuestsFailureIsReturnedUnchanged(t *testing.T) {
	link, _, _ := setup(t)
	sentinel := errors.New("guest refused")
	g := &guest{err: sentinel}
	if _, err := link.Deliver(t.Context(), agentB, event(), g.deliver); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

// The worker delivers nothing the bridge cannot tie to an attempt it runs.
func TestTheWorkerRefusesCallsItDidNotStart(t *testing.T) {
	cases := map[string]func(*DeliverRequest){
		"unknown nonce":     func(d *DeliverRequest) { d.Nonce = strings.Repeat("0", 64) },
		"another recipient": func(d *DeliverRequest) { d.To = "agentcapsule/org_1/agt-c" },
		"another body":      func(d *DeliverRequest) { d.Event.Body = []byte(`{"text":"evil"}`) },
		"another event":     func(d *DeliverRequest) { d.Event.ID = "evt-2" },
		"another subject":   func(d *DeliverRequest) { d.Event.Subjects = []string{"request:arq_2"} },
		"an agent's name":   func(d *DeliverRequest) { d.Caller = "agentcapsule/org_1/agt-a/77" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			link, b, _ := setup(t)
			b.mutate = mutate
			g := &guest{}
			_, err := link.Deliver(t.Context(), agentB, event(), g.deliver)
			var be *BridgeError
			if !errors.As(err, &be) || be.Code != CodeRefused || len(g.seen) != 0 {
				t.Fatal(err, g.seen)
			}
		})
	}
}

// An attempt is delivered at most once, even if the same call comes back twice.
func TestASecondCallForTheSameAttemptIsRefused(t *testing.T) {
	link, b, workerSocket := setup(t)
	g := &guest{}
	var again int
	b.answer = func(w http.ResponseWriter, in SendRequest) bool {
		call, _ := json.Marshal(DeliverRequest{To: in.To, Caller: b.caller, Nonce: in.Nonce, Event: in.Event})
		worker := unixClient(workerSocket)
		first, err := worker.Post("http://worker"+DeliverPath, "application/json", bytes.NewReader(call))
		if err != nil {
			t.Error(err)
			return true
		}
		data, _ := io.ReadAll(first.Body)
		first.Body.Close()
		second, err := worker.Post("http://worker"+DeliverPath, "application/json", bytes.NewReader(call))
		if err == nil {
			again = second.StatusCode
			second.Body.Close()
		}
		_, _ = w.Write(data)
		return true
	}
	if _, err := link.Deliver(t.Context(), agentB, event(), g.deliver); err != nil {
		t.Fatal(err)
	}
	if again != http.StatusForbidden || len(g.seen) != 1 {
		t.Fatal(again, len(g.seen))
	}
}

// A receipt the guest did not give is never taken as a delivery.
func TestAReceiptNotFromTheGuestIsRefused(t *testing.T) {
	t.Run("never delivered", func(t *testing.T) {
		link, b, _ := setup(t)
		b.answer = func(w http.ResponseWriter, _ SendRequest) bool {
			_ = json.NewEncoder(w).Encode(Receipt{Result: []byte("ok:evt-1")})
			return true
		}
		g := &guest{}
		if _, err := link.Deliver(t.Context(), agentB, event(), g.deliver); !errors.Is(err, ErrReceipt) || len(g.seen) != 0 {
			t.Fatal(err)
		}
	})
	t.Run("altered", func(t *testing.T) {
		link, b, workerSocket := setup(t)
		b.answer = func(w http.ResponseWriter, in SendRequest) bool {
			call, _ := json.Marshal(DeliverRequest{To: in.To, Caller: b.caller, Nonce: in.Nonce, Event: in.Event})
			res, err := unixClient(workerSocket).Post("http://worker"+DeliverPath, "application/json", bytes.NewReader(call))
			if err == nil {
				res.Body.Close()
			}
			_ = json.NewEncoder(w).Encode(Receipt{Result: []byte("forged")})
			return true
		}
		g := &guest{}
		if _, err := link.Deliver(t.Context(), agentB, event(), g.deliver); !errors.Is(err, ErrReceipt) || len(g.seen) != 1 {
			t.Fatal(err)
		}
	})
}

func TestBridgeRefusalsAndAbsence(t *testing.T) {
	link, b, _ := setup(t)
	b.answer = func(w http.ResponseWriter, _ SendRequest) bool {
		fail(w, http.StatusBadGateway, CodeUnreachable)
		return true
	}
	g := &guest{}
	_, err := link.Deliver(t.Context(), agentB, event(), g.deliver)
	var be *BridgeError
	if !errors.As(err, &be) || be.Code != CodeUnreachable || be.Status != http.StatusBadGateway {
		t.Fatal(err)
	}
	// A late call back for that finished attempt is refused.
	if len(link.open) != 0 {
		t.Fatal("attempt left open")
	}
	absent := Open(filepath.Join(t.TempDir(), "none.sock"), uint32(os.Getuid()))
	if err = absent.Serve(t.Context(), agentB); err == nil {
		t.Fatal("no bridge, yet served")
	}
	if _, err = absent.Deliver(t.Context(), agentB, event(), g.deliver); err == nil {
		t.Fatal("no bridge, yet delivered")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	b.answer = func(http.ResponseWriter, SendRequest) bool { time.Sleep(time.Second); return true }
	if _, err = link.Deliver(ctx, agentB, event(), g.deliver); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// The worker talks only to the bridge's user, and the reverse.
func TestSocketsCheckThePeersUser(t *testing.T) {
	_, _, workerSocket := setup(t)
	other := Open(filepath.Join(filepath.Dir(workerSocket), "bridge.sock"), uint32(os.Getuid())+1)
	if _, err := other.Health(t.Context()); !errors.Is(err, ErrPeer) {
		t.Fatal(err)
	}
	if info, err := os.Stat(workerSocket); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode(), err)
	}
	plain := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(plain, uint32(os.Getuid())); err == nil {
		t.Fatal("replaced a regular file")
	}
}

func TestNames(t *testing.T) {
	for _, c := range []struct{ tenant, agent, want string }{
		{"org_1", "agt-b", "agentcapsule/org_1/agt-b"},
		{"", "agt-b", "agentcapsule/personal/agt-b"},
	} {
		if got, err := Name(c.tenant, c.agent); err != nil || got != c.want || !ValidName(got) {
			t.Fatal(c, got, err)
		}
	}
	for _, c := range [][2]string{{"platform", "x"}, {"org/1", "a"}, {"org", ""}, {"org", strings.Repeat("a", 129)}, {"org", "a b"}} {
		if _, err := Name(c[0], c[1]); !errors.Is(err, ErrInput) {
			t.Fatal(c, err)
		}
	}
	for _, s := range []string{"agentcapsule/a", "other/a/b", "agentcapsule/a/b/c", "agentcapsule/a/b c"} {
		if ValidName(s) {
			t.Fatal(s)
		}
	}
	link := Open("/nonexistent", 0)
	if err := link.Serve(t.Context(), "agentcapsule/a"); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	if _, err := link.Deliver(t.Context(), agentB, Event{}, nil); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
}
