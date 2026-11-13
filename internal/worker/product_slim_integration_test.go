//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
)

// slimBridgeUID is the bridge's own user in this campaign: not root, and
// outside the agents' provisioning range of the lab (62300-62309).
const slimBridgeUID = 62398

// lockedBuffer collects the bridge's output from its own goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// slimBridge is a real agentcapsule-slim-bridge process, laid out as
// deploy/systemd installs it: its own user, its key and secret readable by it
// alone, its socket in a directory of its own, and the worker's socket in a
// directory it can only traverse.
type slimBridge struct {
	t          *testing.T
	binary     string
	config     string
	socket     string
	cmd        *exec.Cmd
	exited     chan error
	out        *lockedBuffer
	link       *slimlink.Link
	stopServer context.CancelFunc
}

func startSLIMBridge(t *testing.T, w *Placements, binary, endpoint, certs string) *slimBridge {
	t.Helper()
	// The bridge's user must reach these files: not under the campaign's
	// root-only output directory.
	base, err := os.MkdirTemp("/var/tmp", "acp-slim-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dirs := map[string]os.FileMode{base: 0o711, "bin": 0o755, "etc": 0o755, "run-slim": 0o750, "run-worker": 0o711}
	for name, mode := range dirs {
		path := name
		if name != base {
			path = filepath.Join(base, name)
			if err = os.Mkdir(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		if err = os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chown(filepath.Join(base, "run-slim"), slimBridgeUID, slimBridgeUID); err != nil {
		t.Fatal(err)
	}
	copyFile := func(from, to string, mode os.FileMode, owner int) {
		t.Helper()
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(to, raw, mode); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(to, mode); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(to, owner, owner); err != nil {
			t.Fatal(err)
		}
	}
	b := &slimBridge{t: t, binary: filepath.Join(base, "bin/agentcapsule-slim-bridge"), config: filepath.Join(base, "etc/slim-bridge.json"),
		socket: filepath.Join(base, "run-slim/bridge.sock")}
	copyFile(binary, b.binary, 0o755, 0)
	etc := filepath.Join(base, "etc")
	copyFile(filepath.Join(certs, "slim-bridge/slim-ca.pem"), filepath.Join(etc, "slim-ca.pem"), 0o644, 0)
	copyFile(filepath.Join(certs, "slim-bridge/client.crt"), filepath.Join(etc, "client.crt"), 0o644, 0)
	copyFile(filepath.Join(certs, "slim-bridge/client.key"), filepath.Join(etc, "client.key"), 0o600, slimBridgeUID)
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(etc, "secret"), []byte(hex.EncodeToString(secret[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(filepath.Join(etc, "secret"), slimBridgeUID, slimBridgeUID); err != nil {
		t.Fatal(err)
	}
	workerSocket := filepath.Join(base, "run-worker/slim.sock")
	config, _ := json.Marshal(map[string]any{"version": 1, "node": endpoint, "ca": filepath.Join(etc, "slim-ca.pem"),
		"cert": filepath.Join(etc, "client.crt"), "key": filepath.Join(etc, "client.key"), "secret_file": filepath.Join(etc, "secret"),
		"name": "agentcapsule/platform/local", "socket": b.socket, "worker_socket": workerSocket, "worker_uid": os.Geteuid()})
	if err = os.WriteFile(b.config, config, 0o644); err != nil {
		t.Fatal(err)
	}

	// The worker's side, as cmd/agentcapsule-worker wires its "slim" section.
	listener, err := slimlink.Listen(workerSocket, slimBridgeUID)
	if err != nil {
		t.Fatal(err)
	}
	b.link = slimlink.Open(b.socket, slimBridgeUID)
	if err = w.EnableSLIM(b.link); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.stopServer = cancel
	go func() { _ = slimlink.ServeLocal(ctx, listener, b.link) }()
	t.Cleanup(func() {
		b.stop()
		cancel()
	})
	b.start()
	return b
}

// start runs the bridge as its own user, with nothing of the test's
// environment, and waits until it has reached the node.
func (b *slimBridge) start() {
	b.t.Helper()
	b.out = &lockedBuffer{}
	b.cmd = exec.Command(b.binary, "-config", b.config)
	b.cmd.Env = []string{"PATH=/usr/bin:/bin"}
	b.cmd.Dir = "/"
	b.cmd.Stdout, b.cmd.Stderr = b.out, b.out
	b.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: slimBridgeUID, Gid: slimBridgeUID}, Setpgid: true}
	if err := b.cmd.Start(); err != nil {
		b.t.Fatal(err)
	}
	b.exited = make(chan error, 1)
	go func() { b.exited <- b.cmd.Wait() }()
	deadline := time.Now().Add(time.Minute)
	for {
		ctx, cancel := context.WithTimeout(b.t.Context(), 5*time.Second)
		name, err := b.link.Health(ctx)
		cancel()
		if err == nil && name == "agentcapsule/platform/local" {
			return
		}
		select {
		case err := <-b.exited:
			b.cmd = nil
			b.t.Fatal("the SLIM bridge ended before reaching the node", err, b.out.String())
		default:
		}
		if time.Now().After(deadline) {
			b.t.Fatal("the SLIM bridge did not reach the node", err, b.out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// stop ends the bridge as its supervisor would (SIGTERM, code 0).
func (b *slimBridge) stop() {
	if b.cmd == nil {
		return
	}
	_ = b.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-b.exited:
		if err != nil {
			b.t.Error("the SLIM bridge did not stop cleanly", err)
		}
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
		<-b.exited
		b.t.Error("the SLIM bridge did not stop within 20s")
	}
	b.cmd = nil
}

// onlyBridgeAway accepts a pass whose only failures are deliveries waiting
// for an absent bridge: its socket is gone, or it answers unavailable.
func onlyBridgeAway(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyBridgeAway(child) {
				return false
			}
		}
		return true
	}
	var refused *slimlink.BridgeError
	if errors.As(err, &refused) {
		return refused.Code == slimlink.CodeUnavailable
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

// The two A2A agents of TestProductWorkerTenantAgentsTalkOverA2A, on a host
// that carries deliveries between agents through the SLIM bridge (INT-04). The
// worker hands each request and reply to a real bridge process, which sends it
// through the private SLIM node of deploy/interop to the bridge serving the
// recipient's name; that bridge calls the worker back, which delivers to the
// VM over vsock. While the bridge is away, a request waits without spending an
// attempt, and it is delivered once the bridge is back. A request also wakes
// a sleeping recipient through SLIM. Owner instructions never cross SLIM.
func TestProductWorkerTenantAgentsTalkOverSLIM(t *testing.T) {
	pkg, binary := os.Getenv("AGENTCAPSULE_KVM_A2A_HARNESS"), os.Getenv("AGENTCAPSULE_KVM_SLIM_BRIDGE")
	endpoint, certs := os.Getenv("AGENTCAPSULE_KVM_SLIM_ENDPOINT"), os.Getenv("AGENTCAPSULE_KVM_SLIM_CERTS")
	if pkg == "" || binary == "" || endpoint == "" || certs == "" {
		t.Fatal("AGENTCAPSULE_KVM_A2A_HARNESS, AGENTCAPSULE_KVM_SLIM_BRIDGE, AGENTCAPSULE_KVM_SLIM_ENDPOINT and AGENTCAPSULE_KVM_SLIM_CERTS are required (verify-product-guest.py --slim-bridge-build)")
	}
	l := newRegistryLab(t)
	bridge := startSLIMBridge(t, l.worker, binary, endpoint, certs)
	ref := l.importPackage(pkg, "acme/a2a-agent", "1.0.0")
	a := l.createOn("slim-a", "a2a-agent", "1.0.0").AgentID
	b := l.createOn("slim-b", "a2a-agent", "1.0.0").AgentID
	for _, id := range []string{a, b} {
		l.bootsFrom(id, ref, 2)
	}
	l.request(l.owner(), "PUT", "/v1/agents/"+b+"/directory", "b-visible", map[string]any{"visible": true,
		"description": "Answers with the text it receives.", "skills": []int{10301}}, 200, nil)
	l.request(l.owner(), "PUT", "/v1/agents/"+b+"/inbound", "b-auto", map[string]string{"mode": "auto"}, 200, nil)
	slimName := func(agent string) string {
		t.Helper()
		tenant, err := l.store.AgentOrganization(t.Context(), agent)
		if err != nil {
			t.Fatal(err)
		}
		name, err := slimlink.Name(tenant, agent)
		if err != nil {
			t.Fatal(err)
		}
		return name
	}
	requests := func() map[string]int {
		t.Helper()
		rows, err := l.db.Query(t.Context(), "SELECT state,count(*) FROM agent_requests WHERE sender_agent_id=$1 AND recipient_agent_id=$2 GROUP BY state", a, b)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var state string
			var n int
			if err = rows.Scan(&state, &n); err != nil {
				t.Fatal(err)
			}
			out[state] = n
		}
		return out
	}

	t.Log("stage: a asks b over A2A; the request and the reply cross the SLIM bridge and node")
	question := "what crosses the SLIM node?"
	if got := l.ask(a, "slim-ask", "ask "+b+" "+question); !strings.Contains(got, b+" answered: echo: "+question) {
		t.Fatal("a did not get b's answer through SLIM", got)
	}
	// The bridge served b's name for the request and a's for the reply: each
	// name subscribed on the node.
	for _, agent := range []string{b, a} {
		if !strings.Contains(bridge.out.String(), slimName(agent)) {
			t.Fatal("the bridge never served the name of", agent, bridge.out.String())
		}
	}
	if n := requests(); len(n) != 1 || n["REPLIED"] != 1 {
		t.Fatal("the exchange is not one replied request", n)
	}

	t.Log("stage: without its bridge, a request waits and spends no attempt")
	bridge.stop()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+a+"/invocations", "slim-away", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "ask " + b + " is the bridge back?"}}}, 202, &inv)
	held := 0
	opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
	for deadline := time.Now().Add(2 * time.Minute); held < 5; {
		if time.Now().After(deadline) {
			t.Fatal("the request never waited for the bridge", requests())
		}
		err := l.worker.DispatchPass(t.Context(), opts, 90*time.Second)
		if err != nil && !onlyBridgeAway(err) {
			t.Fatal("dispatch without the bridge", err)
		}
		if err != nil {
			held++
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n := requests(); n["DELIVERING"] != 1 {
		t.Fatal("the request is not waiting for the bridge", n)
	}
	var attempts int
	if err := l.db.QueryRow(t.Context(), `SELECT m.attempts FROM agent_mailboxes m JOIN agent_requests r ON r.id=m.ref_id
        WHERE m.kind='request' AND r.state='DELIVERING' AND r.sender_agent_id=$1`, a).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal("waiting for the bridge spent a delivery attempt", attempts, err)
	}
	bridge.start()
	l.await("the request once the bridge is back", true, func() bool {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	if got := string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil)); !strings.Contains(got, b+" answered: echo: is the bridge back?") {
		t.Fatal("a did not get b's answer once the bridge was back", got)
	}

	t.Log("stage: a request wakes a sleeping b through SLIM")
	l.lifecycle(b, "sleep", "slim-b-sleep")
	if got := l.ask(a, "slim-wake", "ask "+b+" are you awake?"); !strings.Contains(got, b+" answered: echo: are you awake?") {
		t.Fatal("a did not get an answer from a sleeping b through SLIM", got)
	}
	if _, ok := l.runs(2)[b]; !ok {
		t.Fatal("b did not wake for the request")
	}
	if n := requests(); len(n) != 1 || n["REPLIED"] != 3 {
		t.Fatal("exchanges", n)
	}
}
