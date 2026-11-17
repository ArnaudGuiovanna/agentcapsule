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
	"slices"
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
	// principals are its members; identifiers are everything of it that
	// another organization's answers must not name.
	principals  []string
	identifiers []string
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
	svc, err := controlplane.NewLLMService(lab.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 10 * time.Second, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err = lab.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}

	ids, installed, _ := lab.installOrganizations(t, 2)
	orgs := make([]*labOrganization, 2)
	for i, id := range ids {
		o := &labOrganization{id: id, principals: []string{installed[i].OwnerPrincipalID},
			identifiers: []string{installed[i].ID, installed[i].OwnerPrincipalID}}
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
		o.principals = append(o.principals, o.bob.PrincipalID)
		o.identifiers = append(o.identifiers, o.agent, o.bob.PrincipalID, created.OperationID, wake.OperationID)
		orgs[i] = o
	}
	a, b := orgs[0], orgs[1]
	// Only organization A has a model.
	var p controlplane.LLMProvider
	lab.request(a.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "a-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	lab.request(a.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "host"}, 201, nil)
	a.identifiers = append(a.identifiers, p.ID)

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
	llmA, answer := lab.ask(a.member, a.agent, "llm-a", "/llm fast hello from A")
	if !strings.Contains(answer, "model answer to: hello from A") {
		t.Fatal("A's agent could not use A's model", answer)
	}
	llmB, answer := lab.ask(b.member, b.agent, "llm-b", "/llm fast hello from B")
	if !strings.Contains(answer, "Model unavailable") || modelCalls.Load() != 1 {
		t.Fatal("B's agent used A's model alias", answer, modelCalls.Load())
	}
	a.identifiers = append(a.identifiers, invA.ID, llmA.ID)
	b.identifiers = append(b.identifiers, invB.ID, llmB.ID)

	// Nothing of B exists for A's owner or member: the same 404 as an unknown
	// ID. Each attempt at B's agent is made again at an unknown agent.
	unknown := "agt_" + strings.Repeat("0", 32)
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
		paths := []string{c.path}
		if strings.Contains(c.path, b.agent) {
			paths = append(paths, strings.ReplaceAll(c.path, b.agent, unknown))
		}
		for _, path := range paths {
			key := ""
			if c.method != "GET" {
				key = "cross-" + strings.ReplaceAll(path, "/", "-")
			}
			lab.request(c.token(), c.method, path, key, c.body, 404, nil)
		}
	}
	for _, agent := range []string{b.agent, unknown} {
		lab.raw(a.member(), "/v1/agents/"+agent+"/attachments", "cross-upload-"+agent, map[string]string{"Content-Type": "text/plain",
			"X-Attachment-Name": "x.txt", "X-Content-SHA256": hex.EncodeToString(sha256Sum([]byte("x")))}, []byte("x"), 404, nil)
	}

	// A file uploaded in A cannot be attached to an invocation in B.
	file := bytes.Repeat([]byte("organization A private notes\n"), 100)
	var attachment controlplane.Attachment
	lab.raw(a.member(), "/v1/agents/"+a.agent+"/attachments", "file-a", map[string]string{"Content-Type": "text/plain",
		"X-Attachment-Name": "notes.txt", "X-Content-SHA256": hex.EncodeToString(sha256Sum(file))}, file, 201, &attachment)
	lab.request(b.member(), "POST", "/v1/agents/"+b.agent+"/invocations", "steal-file", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "read it"}}, "attachments": []string{attachment.ID}}, 409, nil)
	a.identifiers = append(a.identifiers, attachment.ID)

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
			if !slices.Contains(o.principals, m.PrincipalID) {
				t.Fatal("an organization lists a member that is not its own", m.PrincipalID)
			}
		}
	}
	// A's owner and member made seven administrative attempts at B's agent
	// (delete, wake, sleep, idle policy, release, assignment, upload); B made
	// none at A's.
	lab.trailNamesNothingOf(a, b, unknown, 7)
	lab.trailNamesNothingOf(b, a, unknown, 0)
}

// trailNamesNothingOf checks that o's audit trail names nothing of the other
// organization. The trail keeps o's own refused attempts with the identifier
// its member sent, the other organization's agent included (TEN-009, ADR 014
// §10): each such event must say no more than the same attempt at the unknown
// agent, which got the same 404. A failure prints the events concerned, which
// hold identifiers and codes only.
func (l *productPeerLab) trailNamesNothingOf(o, other *labOrganization, unknown string, attempts int) {
	t := l.t
	t.Helper()
	var trail controlplane.AuditPage
	if err := json.Unmarshal(l.request(o.owner(), "GET", "/v1/audit?limit=200", "", nil, 200, nil), &trail); err != nil || trail.Next != "" {
		t.Fatal("the audit trail in one page", err, trail.Next)
	}
	var atOther, atUnknown []string
	own := false
	for _, e := range trail.Items {
		own = own || e.Target == o.agent
		attempt := e.Outcome + " " + e.Action + " by " + e.Actor + " (" + e.Reason + ")"
		if e.Reference == "" && slices.Contains(o.principals, e.Actor) {
			switch e.Target {
			case unknown:
				atUnknown = append(atUnknown, attempt)
				continue
			case other.agent:
				atOther = append(atOther, attempt)
				continue
			}
		}
		event, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range other.identifiers {
			if strings.Contains(string(event), id) {
				t.Fatalf("the trail of organization %s names %s of the other organization: %s", o.id.trust.TenantID, id, event)
			}
		}
	}
	slices.Sort(atOther)
	slices.Sort(atUnknown)
	if !own || len(atOther) != attempts || !slices.Equal(atOther, atUnknown) {
		t.Fatalf("the trail of organization %s: its own agent named %v; its attempts at the other organization's agent %q and at an unknown agent %q",
			o.id.trust.TenantID, own, atOther, atUnknown)
	}
	for _, attempt := range atOther {
		if !strings.HasPrefix(attempt, "refused ") || !strings.HasSuffix(attempt, " (not_found)") {
			t.Fatal("an attempt at the other organization's agent is recorded as more than a refusal", attempt)
		}
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
