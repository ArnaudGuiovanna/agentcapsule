//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

type labOrganization struct {
	id     *tenantIdentity
	agent  string
	bob    controlplane.Member
	owner  func() string
	member func() string
}

// ask sends text as the member and returns the result once the invocation completed.
func (l *productPeerLab) ask(token func() string, agent, key, text string, attachments ...string) (controlplane.Invocation, string) {
	l.t.Helper()
	body := map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}
	if len(attachments) > 0 {
		body["attachments"] = attachments
	}
	var inv controlplane.Invocation
	l.request(token(), "POST", "/v1/agents/"+agent+"/invocations", key, body, 202, &inv)
	l.await("invocation "+key, true, func() bool {
		var v controlplane.Invocation
		l.request(token(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			l.t.Fatal("invocation ended without an answer", key, v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	return inv, string(l.request(token(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
}

// Two organizations run agents at the same time on one host. Each trusts its
// own identity provider and has its own members, agent, files, model and
// audit trail. Everything of the other organization is invisible (the same
// 404 as an unknown ID), its model alias is unusable, its files cannot be
// attached, and the two agents run in separate jailed VMs with separate users,
// encrypted volumes and volume keys.
func TestProductWorkerTwoOrganizationsStayIsolated(t *testing.T) {
	lab := newProductPeerLab(t)
	var modelCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Messages) != 1 || r.Header.Get("Authorization") != "Bearer kvm-model-secret" {
			http.Error(w, "bad request", 400)
			return
		}
		answer, _ := json.Marshal("model answer to: " + req.Messages[0].Content)
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"content":%s},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`, answer)
	}))
	t.Cleanup(provider.Close)
	svc, err := controlplane.NewLLMService(lab.accounts, llmgateway.New(llmgateway.Config{Timeout: 10 * time.Second, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err = lab.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}

	ids, _, _ := lab.installOrganizations(t, 2)
	orgs := make([]*labOrganization, 2)
	for i, id := range ids {
		o := &labOrganization{id: id}
		o.owner = func() string { return id.token(t, "alice") }
		o.member = func() string { return id.token(t, "bob") }
		var created controlplane.AgentCreation
		lab.request(o.owner(), "POST", "/v1/agents", "agent", controlplane.CreateAgentInput{Name: fmt.Sprintf("agent-%d", i),
			Harness:   controlplane.HarnessReference{Name: "reference", Version: "1.0.0"},
			Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}, 202, &created)
		lab.peers = append(lab.peers, &productPeer{agent: created}) // retired at cleanup
		lab.awaitOperation(o.owner, created.OperationID)
		o.agent = created.AgentID
		lab.request(o.owner(), "POST", "/v1/members", "bob", controlplane.CreateMemberInput{Issuer: id.trust.Issuer, Subject: "bob",
			DisplayName: "Bob", Role: "agent_user"}, 201, &o.bob)
		lab.request(o.owner(), "POST", "/v1/agents/"+o.agent+"/assignments", "assign-bob", controlplane.CreateAssignmentInput{
			PrincipalID: o.bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
		var wake controlplane.AgentCreation
		lab.request(o.owner(), "POST", "/v1/agents/"+o.agent+"/wake", "wake", map[string]any{}, 202, &wake)
		lab.awaitOperation(o.owner, wake.OperationID)
		orgs[i] = o
	}
	a, b := orgs[0], orgs[1]
	// Only organization A has a model.
	var p controlplane.LLMProvider
	lab.request(a.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "a-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	lab.request(a.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "host"}, 201, nil)

	// Both agents run at the same time, in separate jailed VMs with their own
	// user, encrypted volume and volume key.
	runs := lab.runs(2)
	if runs[a.agent].ID == runs[b.agent].ID {
		t.Fatal("the organizations share a VM")
	}
	var registry struct {
		Agents map[string]struct {
			UID    uint32 `json:"uid"`
			Volume string `json:"volume"`
		} `json:"agents"`
	}
	raw, err := os.ReadFile(filepath.Join(lab.root, "registry.json"))
	if err != nil || json.Unmarshal(raw, &registry) != nil {
		t.Fatal("host registry", err)
	}
	ra, rb := registry.Agents[a.agent], registry.Agents[b.agent]
	if ra.UID == 0 || ra.UID == rb.UID || ra.Volume == "" || ra.Volume == rb.Volume {
		t.Fatal("the organizations share a user or a volume", ra, rb)
	}
	va, errA := os.Stat(ra.Volume)
	vb, errB := os.Stat(rb.Volume)
	if errA != nil || errB != nil || os.SameFile(va, vb) {
		t.Fatal("the organizations share a volume file", errA, errB)
	}

	// Each member is answered by its own agent; the model belongs to A only.
	invA, answer := lab.ask(a.member, a.agent, "ask-a", "only for organization A")
	if !strings.Contains(answer, "only for organization A") {
		t.Fatal("A's agent did not answer A")
	}
	invB, answer := lab.ask(b.member, b.agent, "ask-b", "only for organization B")
	if !strings.Contains(answer, "only for organization B") || strings.Contains(answer, "organization A") {
		t.Fatal("B's agent did not answer B alone")
	}
	if _, answer = lab.ask(a.member, a.agent, "llm-a", "/llm fast hello from A"); !strings.Contains(answer, "model answer to: hello from A") {
		t.Fatal("A's agent could not use A's model", answer)
	}
	if _, answer = lab.ask(b.member, b.agent, "llm-b", "/llm fast hello from B"); !strings.Contains(answer, "Model unavailable") || modelCalls.Load() != 1 {
		t.Fatal("B's agent used A's model alias", answer, modelCalls.Load())
	}

	// Nothing of B exists for A's owner or member: the same 404 as an unknown ID.
	for _, c := range []struct {
		token        func() string
		method, path string
		body         any
	}{
		{a.owner, "GET", "/v1/agents/" + b.agent, nil},
		{a.owner, "DELETE", "/v1/agents/" + b.agent, nil},
		{a.owner, "POST", "/v1/agents/" + b.agent + "/wake", map[string]any{}},
		{a.owner, "POST", "/v1/agents/" + b.agent + "/sleep", map[string]any{}},
		{a.owner, "POST", "/v1/agents/" + b.agent + "/idle-policy", map[string]any{"idle_timeout_seconds": 0}},
		{a.owner, "POST", "/v1/agents/" + b.agent + "/release", controlplane.ReleaseChange{Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}}},
		{a.owner, "POST", "/v1/agents/" + b.agent + "/assignments", controlplane.CreateAssignmentInput{PrincipalID: a.bob.PrincipalID, Permissions: []string{"invoke"}}},
		{a.member, "POST", "/v1/agents/" + b.agent + "/invocations", map[string]any{"content": []map[string]string{{"type": "text", "text": "intrusion"}}}},
		{a.member, "GET", "/v1/invocations/" + invB.ID, nil},
		{a.member, "GET", "/v1/invocations/" + invB.ID + "/result", nil},
		{a.owner, "GET", "/v1/invocations/" + invB.ID, nil},
		{b.member, "GET", "/v1/invocations/" + invA.ID + "/result", nil},
	} {
		key := ""
		if c.method != "GET" {
			key = "cross-" + strings.ReplaceAll(c.path, "/", "-")
		}
		lab.request(c.token(), c.method, c.path, key, c.body, 404, nil)
	}
	lab.raw(a.member(), "/v1/agents/"+b.agent+"/attachments", "cross-upload", map[string]string{"Content-Type": "text/plain",
		"X-Attachment-Name": "x.txt", "X-Content-SHA256": hex.EncodeToString(sha256Sum([]byte("x")))}, []byte("x"), 404, nil)

	// A file uploaded in A cannot be attached to an invocation in B.
	file := bytes.Repeat([]byte("organization A private notes\n"), 100)
	var attachment controlplane.Attachment
	lab.raw(a.member(), "/v1/agents/"+a.agent+"/attachments", "file-a", map[string]string{"Content-Type": "text/plain",
		"X-Attachment-Name": "notes.txt", "X-Content-SHA256": hex.EncodeToString(sha256Sum(file))}, file, 201, &attachment)
	lab.request(b.member(), "POST", "/v1/agents/"+b.agent+"/invocations", "steal-file", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "read it"}}, "attachments": []string{attachment.ID}}, 409, nil)

	// Lists and the audit trail show one organization only.
	for _, o := range orgs {
		var agents struct {
			Items []controlplane.TenantAgent `json:"items"`
		}
		lab.request(o.owner(), "GET", "/v1/agents", "", nil, 200, &agents)
		if len(agents.Items) != 1 || agents.Items[0].ID != o.agent {
			t.Fatal("an organization lists agents that are not its own", agents.Items)
		}
		var members struct {
			Items []controlplane.Member `json:"items"`
		}
		lab.request(o.owner(), "GET", "/v1/members", "", nil, 200, &members)
		for _, m := range members.Items {
			if m.PrincipalID == a.bob.PrincipalID && o != a || m.PrincipalID == b.bob.PrincipalID && o != b {
				t.Fatal("an organization lists another organization's member")
			}
		}
		other := b
		if o == b {
			other = a
		}
		audit := string(lab.request(o.owner(), "GET", "/v1/audit", "", nil, 200, nil))
		if !strings.Contains(audit, o.agent) || strings.Contains(audit, other.agent) || strings.Contains(audit, other.bob.PrincipalID) {
			t.Fatal("an organization's audit trail mentions the other organization")
		}
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
