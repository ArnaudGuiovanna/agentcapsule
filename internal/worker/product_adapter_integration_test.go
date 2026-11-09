//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// An ordinary agent image (Python, the official OpenAI SDK, a tool loop),
// adapted off-host by scripts/build-adapted-harness.py without changing the
// agent, runs in the guest: capsule-adapter answers each invocation by running
// the agent, whose SDK reaches the organization's model through the endpoint on
// the VM's loopback and the platform channel. The host's model sees the
// agent's own request, tools included, under the upstream model and the
// organization's credential; the agent reads an attached file with a tool call.
func TestProductWorkerTenantRunsAnAdaptedAgent(t *testing.T) {
	pkg := os.Getenv("AGENTCAPSULE_KVM_ADAPTED_HARNESS")
	if pkg == "" {
		t.Fatal("AGENTCAPSULE_KVM_ADAPTED_HARNESS must name the adapted-agent package (verify-product-guest.py --adapted-harness)")
	}
	l := newRegistryLab(t)
	var calls, toolCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Stream   *bool  `json:"stream"`
			Messages []struct {
				Role    string  `json:"role"`
				Content *string `json:"content"`
			} `json:"messages"`
			Tools []json.RawMessage `json:"tools"`
		}
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer kvm-model-secret" ||
			json.NewDecoder(r.Body).Decode(&req) != nil || req.Model != "host-model" || req.Stream != nil || len(req.Tools) != 2 || len(req.Messages) < 2 {
			http.Error(w, "unexpected request", 400)
			return
		}
		calls.Add(1)
		last := req.Messages[len(req.Messages)-1]
		text := ""
		if last.Content != nil {
			text = *last.Content
		}
		reply := func(message string) {
			_, _ = fmt.Fprintf(w, `{"id":"c","object":"chat.completion","created":1,"model":"host-model","choices":[{"index":0,"message":%s,"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":6}}`, message)
		}
		switch {
		case last.Role == "tool":
			answer, _ := json.Marshal(map[string]string{"role": "assistant", "content": "The file says: " + strings.TrimSpace(text)})
			reply(string(answer))
		case strings.Contains(text, "Attached files:\n- "):
			path := strings.SplitN(strings.SplitN(text, "Attached files:\n- ", 2)[1], " (", 2)[0]
			args, _ := json.Marshal(map[string]string{"path": path})
			call, _ := json.Marshal(map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{{"id": "call_1", "type": "function",
				"function": map[string]string{"name": "read_file", "arguments": string(args)}}}})
			toolCalls.Add(1)
			reply(string(call))
		default:
			answer, _ := json.Marshal(map[string]string{"role": "assistant", "content": "model answer to: " + strings.TrimSpace(text)})
			reply(string(answer))
		}
	}))
	t.Cleanup(provider.Close)
	svc, err := controlplane.NewLLMService(l.accounts, llmgateway.New(llmgateway.Config{Timeout: 30 * time.Second, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "host-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	// The organization names its alias after the model the agent asks for.
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "gpt-4o", ProviderID: p.ID, UpstreamModel: "host-model"}, 201, nil)

	ref := l.importPackage(pkg, "acme/adapted-agent", "1.0.0")
	agent := l.createOn("adapted", "adapted-agent", "1.0.0").AgentID
	l.bootsFrom(agent, ref, 1)
	if got := l.ask(agent, "ad-1", "hello"); !strings.Contains(got, "model answer to: hello") {
		t.Fatal("the adapted agent did not answer through its model", got)
	}

	file := []byte("The access code of the vault is 4417.\n")
	sum := sha256.Sum256(file)
	var attachment controlplane.Attachment
	l.raw(l.user(), "/v1/agents/"+agent+"/attachments", "vault", map[string]string{
		"Content-Type": "text/plain", "X-Attachment-Name": "vault.txt", "X-Content-SHA256": hex.EncodeToString(sum[:])}, file, 201, &attachment)
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "ad-file", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "What is the access code of the vault?"}}, "attachments": []string{attachment.ID}}, 202, &inv)
	l.await("adapted invocation with a file", true, func() bool {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	if got := string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil)); !strings.Contains(got, "The file says: The access code of the vault is 4417.") {
		t.Fatal("the adapted agent did not read the attached file with its tool", got)
	}
	if toolCalls.Load() != 1 || calls.Load() != 3 {
		t.Fatal("model calls", calls.Load(), "tool calls", toolCalls.Load())
	}

	// Every model call was metered for this agent.
	var usage controlplane.LLMUsageReport
	l.request(l.owner(), "GET", "/v1/llm/usage?period=day", "", nil, 200, &usage)
	if len(usage.Lines) != 1 || usage.Lines[0].AgentID != agent || usage.Lines[0].Calls != 3 || usage.Lines[0].SettledInput != 60 {
		t.Fatal("usage", usage)
	}

	l.lifecycle(agent, "sleep", "ad-sleep")
	l.lifecycle(agent, "wake", "ad-wake")
	if got := l.ask(agent, "ad-2", "again"); !strings.Contains(got, "model answer to: again") {
		t.Fatal("the adapted agent did not answer after sleep and wake", got)
	}
}

// Pi, the coding agent, unmodified (scripts/build-pi-harness.py packs an
// installed release with the Node.js it runs on), runs in a jailed microVM and
// reaches a real model: the organization's provider is the host's Ollama.
// Pi reads an attached file with its own read tool. It then answers from its
// session alone, in the next invocation and again after sleep and wake: the
// session is on the agent's encrypted volume.
func TestProductWorkerTenantRunsPiOnOllama(t *testing.T) {
	pkg, url, model := os.Getenv("AGENTCAPSULE_KVM_PI_HARNESS"), os.Getenv("AGENTCAPSULE_KVM_OLLAMA_URL"), os.Getenv("AGENTCAPSULE_KVM_OLLAMA_MODEL")
	if pkg == "" || url == "" || model == "" {
		t.Fatal("AGENTCAPSULE_KVM_PI_HARNESS, AGENTCAPSULE_KVM_OLLAMA_URL and AGENTCAPSULE_KVM_OLLAMA_MODEL are required (verify-product-guest.py --pi-harness)")
	}
	l := newRegistryLab(t)
	svc, err := controlplane.NewLLMService(l.accounts, llmgateway.New(llmgateway.Config{Timeout: 3 * time.Minute, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "host-ollama", Kind: "openai_compatible",
		BaseURL: url, Secret: "ollama-ignores-keys"}, 201, &p)
	// Pi asks for "pi-model" (its models.json); the organization decides what it is.
	l.request(l.owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "pi-model", ProviderID: p.ID, UpstreamModel: model}, 201, nil)

	// A model server unloads an idle model and may take minutes to load it
	// again: load it first, so that Pi's answers are timed, not the loading.
	warm := &http.Client{Timeout: 10 * time.Minute}
	body, _ := json.Marshal(map[string]any{"model": model, "max_tokens": 1, "messages": []map[string]string{{"role": "user", "content": "hi"}}})
	resp, err := warm.Post(strings.TrimRight(url, "/")+"/chat/completions", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal("the host's model server did not load the model", err)
	}
	resp.Body.Close()

	ref := l.importPackage(pkg, "acme/pi-agent", "1.0.0")
	agent := l.createWith("pi", "pi-agent", "1.0.0", 1024).AgentID
	l.bootsFrom(agent, ref, 1)

	// ask sends bob's text (and files) and waits for Pi's answer: one run of Pi,
	// several calls to a real model.
	ask := func(key, text string, files ...string) string {
		t.Helper()
		var inv controlplane.Invocation
		in := map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}
		if len(files) > 0 {
			in["attachments"] = files
		}
		l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", key, in, 202, &inv)
		l.awaitFor("Pi answering "+key, true, 5*time.Minute, func() bool {
			var v controlplane.Invocation
			l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
			if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
				t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
			}
			return v.State == "completed"
		})
		return string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
	}

	file := []byte("The access code of the vault is 4417.\n")
	sum := sha256.Sum256(file)
	var attachment controlplane.Attachment
	l.raw(l.user(), "/v1/agents/"+agent+"/attachments", "pi-vault", map[string]string{
		"Content-Type": "text/plain", "X-Attachment-Name": "vault.txt", "X-Content-SHA256": hex.EncodeToString(sum[:])}, file, 201, &attachment)
	first := ask("pi-1", "Read the attached file with the read tool, then tell me the access code of the vault.", attachment.ID)
	t.Log("Pi, first answer:", first)
	if !strings.Contains(first, "4417") {
		t.Fatal("Pi did not read the attached file", first)
	}
	var usage controlplane.LLMUsageReport
	l.request(l.owner(), "GET", "/v1/llm/usage?period=day", "", nil, 200, &usage)
	if len(usage.Lines) != 1 || usage.Lines[0].AgentID != agent || usage.Lines[0].Calls < 2 || usage.Lines[0].SettledInput == 0 {
		t.Fatal("Pi's model calls (a tool call, then the answer) were not metered", usage)
	}
	t.Log("model calls so far:", usage.Lines[0].Calls, "input tokens:", usage.Lines[0].SettledInput)

	question := "Without reading any file again, what was the access code of the vault I asked you about?"
	second := ask("pi-2", question)
	t.Log("Pi, second answer:", second)
	if !strings.Contains(second, "4417") {
		t.Fatal("Pi did not keep its session between invocations", second)
	}
	l.lifecycle(agent, "sleep", "pi-sleep")
	l.lifecycle(agent, "wake", "pi-wake")
	third := ask("pi-3", question)
	t.Log("Pi, after sleep and wake:", third)
	if !strings.Contains(third, "4417") {
		t.Fatal("Pi lost its session across sleep and wake", third)
	}
}
