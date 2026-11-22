//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

// publishManifest packs capsule-echo as echo-oci:version, requesting the
// given capabilities (nil: the field is absent), with a test behaviour.
func (l *registryLab) publishManifest(version, dir string, capabilities *[]string, args ...string) ociregistry.Reference {
	t := l.t
	t.Helper()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, filepath.Join(filepath.Dir(config(t).Initrd), "capsule-echo"), filepath.Join(src, dir, "harness"))
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "echo-oci", Version: version, Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: append([]string{"/" + dir + "/harness"}, args...),
		Capabilities: capabilities}
	pkg := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(pkg, harnesspkg.RootfsFile), 64); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(pkg, m); err != nil {
		t.Fatal(err)
	}
	return l.importPackage(pkg, "acme/echo", version)
}

// askContent sends bob's parts to the agent and returns its result's parts.
func (l *registryLab) askContent(agentID, key string, content []capsuleprotocol.ContentPart) []capsuleprotocol.ContentPart {
	t := l.t
	t.Helper()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agentID+"/invocations", key, map[string]any{"content": content}, 202, &inv)
	l.await("invocation "+key, true, func() bool {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	var result capsuleprotocol.OwnerMessage
	if err := json.Unmarshal(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil), &result); err != nil {
		t.Fatal(err)
	}
	return result.Content
}

// The guest's /tmp is bounded (product.md §3): a harness that fills it gets
// ENOSPC at a quarter of the VM's 256 MiB, well before its 100 MiB fill ends,
// and serves. With the kernel's default (half the memory), the fill would
// end, the harness would exit and the boot would fail.
func TestProductWorkerBoundsTheGuestTmp(t *testing.T) {
	l := newRegistryLab(t)
	l.publishBehaviour("1.0.0", "opt/fill", "fill-tmp", "104857600")
	agent := l.create("fills-tmp", "1.0.0").AgentID
	l.answers(agent, "after-fill", "the guest survived a full /tmp")
}

// JSON content reaches a harness that accepts it as JSON (EXT-001), and a
// harness built before JSON content as text, through the real guest, its
// negotiation and the worker's delivery.
func TestProductWorkerDeliversJSONContent(t *testing.T) {
	l := newRegistryLab(t)
	l.publish("1.0.0", "opt/echo")
	l.publishBehaviour("2.0.0", "opt/text", "text-only")
	structured := l.create("structured", "1.0.0").AgentID
	older := l.create("text-only", "2.0.0").AgentID
	sent := []capsuleprotocol.ContentPart{{Type: "text", Text: "rows"}, {Type: "json", JSON: `{"rows": [1, 2]}`}}
	got := l.askContent(structured, "json-1", sent)
	if len(got) != 2 || got[1] != (capsuleprotocol.ContentPart{Type: "json", JSON: `{"rows":[1,2]}`}) {
		t.Fatal("a JSON part did not come back as JSON", got)
	}
	got = l.askContent(older, "json-2", sent)
	if len(got) != 2 || got[1] != (capsuleprotocol.ContentPart{Type: "text", Text: `{"rows":[1,2]}`}) {
		t.Fatal("a harness without JSON content did not get text", got)
	}
}

// The platform channel enforces the agent's effective capabilities (CAP-01):
// a model call is refused with capability_denied when the harness did not
// request llm.invoke, and when the organization's policy no longer allows
// it, from the next call, without a reboot.
func TestProductWorkerEnforcesCapabilities(t *testing.T) {
	l := newRegistryLab(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"model answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
	}))
	t.Cleanup(provider.Close)
	// The provider listens on loopback, which the production gateway refuses
	// (ADR 010): the lab's gateway allows it, as in every other KVM lab.
	svc, err := llmservice.New(l.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 10 * time.Second, MaxAttempts: 1},
		llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "host-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "host"}, 201, nil)
	l.publishManifest("1.0.0", "opt/llm", &[]string{"llm.invoke"})
	l.publishManifest("2.0.0", "opt/none", &[]string{})
	asks := l.create("asks-model", "1.0.0").AgentID
	silent := l.create("requests-nothing", "2.0.0").AgentID
	answer := func(agent, key string) string {
		got := l.askContent(agent, key, []capsuleprotocol.ContentPart{{Type: "text", Text: "/llm fast hello"}})
		if len(got) == 0 {
			t.Fatal("no answer", key)
		}
		return got[len(got)-1].Text
	}
	if got := answer(asks, "llm-1"); got != "model answer" {
		t.Fatal("a requested capability was refused", got)
	}
	denied := func(agent, key string) bool { return strings.Contains(answer(agent, key), "capability_denied") }
	if !denied(silent, "llm-2") {
		t.Fatal("a capability the harness did not request was granted")
	}
	var catalog controlplane.AgentCapabilities
	l.request(l.owner(), "GET", "/v1/agents/"+silent+"/capabilities", "", nil, 200, &catalog)
	if !catalog.Declared || len(catalog.Requested) != 0 || len(catalog.Effective) != 0 {
		t.Fatal("catalog", catalog)
	}
	l.request(l.owner(), "PUT", "/v1/organizations/current/capabilities", "no-models", controlplane.CapabilityPolicy{Allowed: []string{}}, 200, nil)
	if !denied(asks, "llm-3") {
		t.Fatal("the organization's policy did not apply to the next call")
	}
}
