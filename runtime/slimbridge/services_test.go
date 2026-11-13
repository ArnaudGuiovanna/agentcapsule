//go:build interop_services

// The bridge against the private SLIM node of deploy/interop, started by
// scripts/verify-interop.py --services with INTEROP_CERTS,
// INTEROP_SLIM_ENDPOINT and INTEROP_SLIM_RESTART (a script that restarts the
// node and prints its new address). Each bridge runs in its own process, as
// in production; fake workers stand on the other side of the local sockets.
// Synthetic data only.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if path := os.Getenv("SLIMBRIDGE_HELPER"); path != "" {
		os.Exit(run([]string{"-config", path}))
	}
	os.Exit(m.Run())
}

const secret = "slimbridge-synthetic-app-secret-0123456789abcdef" // gitleaks:allow (synthetic)

// worker stands for the platform's worker: it answers the bridge's calls back
// on its socket and records them.
type worker struct {
	mu     sync.Mutex
	calls  []DeliverRequest
	answer int // HTTP status: 200 delivers, anything else refuses
}

func (w *worker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var in DeliverRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if r.URL.Path != deliverPath || d.Decode(&in) != nil {
		fail(rw, http.StatusBadRequest, codeInvalid)
		return
	}
	w.mu.Lock()
	w.calls = append(w.calls, in)
	status := w.answer
	w.mu.Unlock()
	if status != http.StatusOK {
		fail(rw, status, codeRefused)
		return
	}
	_ = json.NewEncoder(rw).Encode(Receipt{Result: []byte("guest:" + in.Event.ID), Replayed: false})
}

func (w *worker) last(t *testing.T) DeliverRequest {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.calls) == 0 {
		t.Fatal("the worker was never called")
	}
	return w.calls[len(w.calls)-1]
}

type host struct {
	name, dir, config string
	worker            *worker
	client            *http.Client
	cmd               *exec.Cmd
	exited            chan error
	out               *bytes.Buffer
}

func unixClient(path string) *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}}
}

// newHost writes a bridge configuration for one host, starts its fake worker
// and the bridge process, and waits until the bridge has reached the node.
func newHost(t *testing.T, name, endpoint string) *host {
	t.Helper()
	dir, err := os.MkdirTemp("", "sb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	certs := filepath.Join(os.Getenv("INTEROP_CERTS"), "slim-bridge")
	key := filepath.Join(dir, "client.key")
	raw, err := os.ReadFile(filepath.Join(certs, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Config{Version: 1, Node: endpoint, CA: filepath.Join(certs, "slim-ca.pem"), Cert: filepath.Join(certs, "client.crt"), Key: key,
		SecretFile: filepath.Join(dir, "secret"), Name: "agentcapsule/platform/" + name, Socket: filepath.Join(dir, "bridge.sock"),
		WorkerSocket: filepath.Join(dir, "worker.sock"), WorkerUID: os.Getuid(), ProbeSeconds: 1, CallSeconds: 20}
	h := &host{name: c.Name, dir: dir, config: filepath.Join(dir, "bridge.json"), worker: &worker{answer: http.StatusOK}, client: unixClient(c.Socket)}
	encoded, _ := json.Marshal(c)
	if err = os.WriteFile(h.config, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := listen(c.WorkerSocket, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: h.worker}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { server.Close() })
	h.start(t)
	return h
}

func (h *host) start(t *testing.T) {
	t.Helper()
	h.cmd = exec.Command(os.Args[0], "-test.run=^$")
	h.cmd.Env = append(os.Environ(), "SLIMBRIDGE_HELPER="+h.config)
	h.out = &bytes.Buffer{}
	h.cmd.Stdout, h.cmd.Stderr = h.out, h.out
	if err := h.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h.exited = make(chan error, 1)
	go func(cmd *exec.Cmd, exited chan error) { exited <- cmd.Wait() }(h.cmd, h.exited)
	t.Cleanup(func() { _ = h.cmd.Process.Signal(syscall.SIGTERM) })
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if status, _ := h.call(t, http.MethodGet, healthPath, nil, nil); status == http.StatusOK {
			return
		}
		select {
		case err := <-h.exited:
			t.Fatal("the bridge stopped", err, h.out.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("the bridge never reached the node", h.out.String())
}

// call is the worker's side of the local protocol.
func (h *host) call(t *testing.T, method, path string, in, out any) (int, string) {
	t.Helper()
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, "http://bridge"+path, body)
	res, err := h.client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		var f Failure
		_ = json.Unmarshal(raw, &f)
		return res.StatusCode, f.Error
	}
	if out != nil {
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, ""
}

func outgoing(to, id string) SendRequest {
	return SendRequest{To: to, Nonce: strings.Repeat("ab", 32), Event: Event{ID: id, Subjects: []string{"agent/agt-a", "agent/agt-b", "request/arq_1", "event/" + id},
		Body: []byte(`{"kind":"request","text":"synthetic question"}`)}}
}

// Two hosts: the bridge of host 1 delivers to an agent whose name the bridge
// of host 2 answers on; host 2's worker sees the delivery unchanged, with the
// sending bridge's identity as SLIM verified it, and its receipt comes back.
// Then the single-host case: a bridge delivers to a name it answers on itself,
// through the node. Refusals and absent names come back as codes.
func TestBridgesCarryDeliveriesThroughTheNode(t *testing.T) {
	endpoint := os.Getenv("INTEROP_SLIM_ENDPOINT")
	one, two := newHost(t, "host-1", endpoint), newHost(t, "host-2", endpoint)
	const agentB, agentA = "agentcapsule/org_1/agt-b", "agentcapsule/org_1/agt-a"
	var health Health
	if status, _ := one.call(t, http.MethodGet, healthPath, nil, &health); status != http.StatusOK || health.Name != one.name {
		t.Fatal("health", status, health)
	}
	if status, code := two.call(t, http.MethodPost, servePath, ServeRequest{Name: agentB}, nil); status != http.StatusNoContent {
		t.Fatal("serve", status, code)
	}
	in := outgoing(agentB, "mbx_1")
	var r Receipt
	if status, code := one.call(t, http.MethodPost, sendPath, in, &r); status != http.StatusOK || string(r.Result) != "guest:mbx_1" {
		t.Fatal("delivery across hosts", status, code, r)
	}
	got := two.worker.last(t)
	if got.To != agentB || got.Nonce != in.Nonce || got.Event.ID != in.Event.ID || !bytes.Equal(got.Event.Body, in.Event.Body) ||
		strings.Join(got.Event.Subjects, ",") != strings.Join(in.Event.Subjects, ",") || !strings.HasPrefix(got.Caller, one.name+"_") {
		t.Fatal("the delivery changed on its way, or the caller is not host 1's bridge", got)
	}
	t.Log("the receiving worker saw the caller", got.Caller)

	// One host: the bridge answers on the name it delivers to.
	if status, code := one.call(t, http.MethodPost, servePath, ServeRequest{Name: agentA}, nil); status != http.StatusNoContent {
		t.Fatal("serve", status, code)
	}
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing(agentA, "mbx_2"), &r); status != http.StatusOK || string(r.Result) != "guest:mbx_2" {
		t.Fatal("delivery on one host", status, code, r)
	}
	if got = one.worker.last(t); got.To != agentA || !strings.HasPrefix(got.Caller, one.name+"_") {
		t.Fatal(got)
	}

	// The worker decides: its refusal and its failure come back as codes.
	two.worker.mu.Lock()
	two.worker.answer = http.StatusForbidden
	two.worker.mu.Unlock()
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing(agentB, "mbx_3"), nil); status != http.StatusForbidden || code != codeRefused {
		t.Fatal("refusal", status, code)
	}
	two.worker.mu.Lock()
	two.worker.answer = http.StatusBadGateway
	two.worker.mu.Unlock()
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing(agentB, "mbx_4"), nil); status != http.StatusBadGateway || code != codeFailed {
		t.Fatal("failure", status, code)
	}

	// Nobody answers on this name: unreachable, within the call's bound.
	started := time.Now()
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing("agentcapsule/org_1/agt-absent", "mbx_5"), nil); status != http.StatusBadGateway || code != codeUnreachable {
		t.Fatal("absent name", status, code)
	}
	t.Log("an absent name answered unreachable after", time.Since(started).Round(time.Millisecond))
	if time.Since(started) > 25*time.Second {
		t.Fatal("an absent name held the delivery beyond its bound")
	}

	// Malformed calls and the platform's own names are refused.
	if status, code := one.call(t, http.MethodPost, servePath, ServeRequest{Name: "agentcapsule/platform/host-9"}, nil); status != http.StatusBadRequest || code != codeInvalid {
		t.Fatal("served a platform name", status, code)
	}
	if status, code := one.call(t, http.MethodPost, sendPath, map[string]string{"to": agentB, "extra": "x"}, nil); status != http.StatusBadRequest || code != codeInvalid {
		t.Fatal("unknown field", status, code)
	}
	// A delivery to a bridge's probe is not a delivery.
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing(two.name+".probe", "mbx_6"), nil); status != http.StatusForbidden || code != codeRefused {
		t.Fatal("a bridge's name took a delivery", status, code)
	}
}

// A node that comes back at another address (Docker publishes it on a new
// port) is never found again by a SLIM client: the bridge sees its probes fail
// and ends, so that its supervisor starts a new one, which works. A node that
// restarts at the same address is found again (verify-interop.py --systemd).
func TestABridgeEndsWhenTheNodeIsLostAndANewOneWorks(t *testing.T) {
	restart := os.Getenv("INTEROP_SLIM_RESTART")
	if restart == "" {
		t.Fatal("INTEROP_SLIM_RESTART must name the script that restarts the node")
	}
	one := newHost(t, "host-1", os.Getenv("INTEROP_SLIM_ENDPOINT"))
	out, err := exec.Command(restart).Output()
	if err != nil {
		t.Fatal("restart", err)
	}
	address := strings.TrimSpace(string(out))
	endpoint := "https://" + address
	select {
	case err := <-one.exited:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(one.out.String(), "slim_node_lost") {
			t.Fatal("the bridge ended without saying the node was lost", err, one.out.String())
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the bridge kept running without its node", one.out.String())
	}
	// The supervisor's new process, with the node's new address, once the
	// node listens again.
	for deadline := time.Now().Add(30 * time.Second); ; {
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the node did not come back", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	raw, _ := os.ReadFile(one.config)
	var c Config
	_ = json.Unmarshal(raw, &c)
	c.Node = endpoint
	raw, _ = json.Marshal(c)
	if err = os.WriteFile(one.config, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	one.start(t)
	const agentA = "agentcapsule/org_1/agt-a"
	if status, code := one.call(t, http.MethodPost, servePath, ServeRequest{Name: agentA}, nil); status != http.StatusNoContent {
		t.Fatal("serve after restart", status, code)
	}
	var r Receipt
	if status, code := one.call(t, http.MethodPost, sendPath, outgoing(agentA, "mbx_7"), &r); status != http.StatusOK || string(r.Result) != "guest:mbx_7" {
		t.Fatal("delivery after restart", status, code)
	}
	scanner := bufio.NewScanner(strings.NewReader(one.out.String()))
	for scanner.Scan() {
		t.Log("bridge:", scanner.Text())
	}
}
