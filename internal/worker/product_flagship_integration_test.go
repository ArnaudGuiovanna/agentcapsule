//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
)

// awaitExit waits for the bridge to end by itself.
func (b *slimBridge) awaitExit(within time.Duration) error {
	b.t.Helper()
	select {
	case err := <-b.exited:
		b.cmd = nil
		return err
	case <-time.After(within):
		b.t.Fatal("the SLIM bridge kept running", b.out.String())
		return nil
	}
}

// The flagship journey of gate G2 (INT-05), with the private services of
// deploy/interop: agent a finds agent b by its skill in the Directory while b
// sleeps, and gets b's answer over A2A and SLIM, b waking for it. Then the
// same journey with each service down:
//   - the Directory down, a's search fails and says so, but a still reaches b,
//     whom it knows, and finds it again once the Directory is back;
//   - the SLIM node down, the bridge ends with code 3 (slim_node_lost), a's
//     request waits, and once the node is back the bridge started again (as
//     its systemd unit would) delivers it.
//
// The search runs from a's VM: a's adapter lists the agents offering the skill
// (INT-02), the Directory narrows them to the organization, and PostgreSQL
// keeps those a may reach now.
func TestProductWorkerTenantFlagshipJourney(t *testing.T) {
	pkg, binary := os.Getenv("AGENTCAPSULE_KVM_A2A_HARNESS"), os.Getenv("AGENTCAPSULE_KVM_SLIM_BRIDGE")
	endpoint, certs := os.Getenv("AGENTCAPSULE_KVM_SLIM_ENDPOINT"), os.Getenv("AGENTCAPSULE_KVM_INTEROP_CERTS")
	address, control := os.Getenv("AGENTCAPSULE_KVM_DIRECTORY_ADDR"), os.Getenv("AGENTCAPSULE_KVM_INTEROP_CONTROL")
	if pkg == "" || binary == "" || endpoint == "" || certs == "" || address == "" || control == "" {
		t.Fatal("the A2A harness, the SLIM bridge and the private services are required (verify-product-guest.py --slim-bridge-build)")
	}
	l := newRegistryLab(t)
	bridge := startSLIMBridge(t, l.worker, binary, endpoint, certs)
	// The Directory, as the worker's "directory" section wires it.
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(certs, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	dir, err := directory.Dial(address, directory.Credentials{CA: read("control-plane/directory-ca.pem"),
		Cert: read("control-plane/directory.crt"), Key: read("control-plane/directory.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err = l.worker.EnableDirectory(dir); err != nil {
		t.Fatal(err)
	}
	publisher := &directory.Publisher{Store: l.store, Directory: dir}
	interop := func(action, service string) {
		t.Helper()
		out, err := exec.Command(control, action, service).CombinedOutput()
		if err != nil {
			t.Fatal(action, service, err, string(out))
		}
	}

	ref := l.importPackage(pkg, "acme/a2a-agent", "1.0.0")
	a := l.createOn("flag-a", "a2a-agent", "1.0.0").AgentID
	b := l.createOn("flag-b", "a2a-agent", "1.0.0").AgentID
	for _, id := range []string{a, b} {
		l.bootsFrom(id, ref, 2)
	}
	tenant, err := l.store.AgentOrganization(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	l.request(l.owner(), "PUT", "/v1/agents/"+b+"/directory", "b-visible", map[string]any{"visible": true,
		"description": "Answers with the text it receives.", "skills": []int{10301}}, 200, nil)
	l.request(l.owner(), "PUT", "/v1/agents/"+b+"/inbound", "b-auto", map[string]string{"mode": "auto"}, 200, nil)
	l.await("b's record in the Directory", false, func() bool {
		if _, err := publisher.RunOnce(t.Context()); err != nil {
			t.Log("publish:", err)
			return false
		}
		var e controlplane.DirectoryEntry
		l.request(l.owner(), "GET", "/v1/agents/"+b+"/directory", "", nil, 200, &e)
		return e.Publication == "published"
	})
	replied := func() int {
		t.Helper()
		var n int
		if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM agent_requests WHERE sender_agent_id=$1 AND recipient_agent_id=$2 AND state='REPLIED'", a, b).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	asleep := func(key string) {
		t.Helper()
		l.lifecycle(b, "sleep", key)
		if _, ok := l.runs(1)[a]; !ok {
			t.Fatal("a stopped with b")
		}
	}
	answered := func(got, question string) {
		t.Helper()
		if !strings.Contains(got, b+" answered: echo: "+question) {
			t.Fatal("a did not get b's answer", got)
		}
		if _, ok := l.runs(2)[b]; !ok {
			t.Fatal("b did not wake for the request")
		}
	}

	t.Log("stage: a finds b by its skill while b sleeps, and gets b's answer over A2A and SLIM")
	asleep("flag-sleep-1")
	question := "who answers for skill 10301?"
	answered(l.ask(a, "flag-find", "find 10301 "+question), question)
	name, err := slimlink.Name(tenant, b)
	if err != nil || !strings.Contains(bridge.out.String(), name) {
		t.Fatal("the request did not cross the SLIM bridge", err)
	}
	if replied() != 1 {
		t.Fatal("requests", replied())
	}

	t.Log("stage: with the Directory down, a cannot find b, but reaches b, whom it knows")
	interop("stop", "directory")
	asleep("flag-sleep-2")
	if got := l.ask(a, "flag-find-down", "find 10301 is anyone there?"); !strings.Contains(got, "could not find an agent offering skill 10301") {
		t.Fatal("a search without the Directory did not fail", got)
	}
	question = "do you still answer without the Directory?"
	answered(l.ask(a, "flag-ask-known", "ask "+b+" "+question), question)
	interop("start", "directory")
	l.awaitFor("the Directory answering again", false, 3*time.Minute, func() bool {
		found, err := dir.Search(t.Context(), tenant, []int{10301}, 10)
		return err == nil && len(found) > 0
	})
	question = "found again?"
	answered(l.ask(a, "flag-find-back", "find 10301 "+question), question)
	if replied() != 3 {
		t.Fatal("requests", replied())
	}

	t.Log("stage: with the SLIM node down, a's request waits; the restarted bridge delivers it once the node is back")
	asleep("flag-sleep-3")
	interop("stop", "slim")
	var exit *exec.ExitError
	if err = bridge.awaitExit(90 * time.Second); !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(bridge.out.String(), "slim_node_lost") {
		t.Fatal("the bridge did not end with slim_node_lost (code 3)", err, bridge.out.String())
	}
	var inv controlplane.Invocation
	question = "is the SLIM node back?"
	l.request(l.user(), "POST", "/v1/agents/"+a+"/invocations", "flag-slim-down", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "ask " + b + " " + question}}}, 202, &inv)
	held := 0
	opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
	for deadline := time.Now().Add(2 * time.Minute); held < 3; {
		if time.Now().After(deadline) {
			t.Fatal("the request never waited for SLIM")
		}
		err := l.worker.DispatchPass(t.Context(), opts, 90*time.Second)
		if err != nil && !onlyBridgeAway(err) {
			t.Fatal("dispatch with the SLIM node down", err)
		}
		if err != nil {
			held++
		}
		time.Sleep(200 * time.Millisecond)
	}
	if replied() != 3 {
		t.Fatal("a request was answered with the SLIM node down", replied())
	}
	interop("start", "slim")
	bridge.start()
	l.await("the request once SLIM is back", true, func() bool {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	answered(string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil)), question)
	if replied() != 4 {
		t.Fatal("requests", replied())
	}
}
