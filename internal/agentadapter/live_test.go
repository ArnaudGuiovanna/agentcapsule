//go:build linux && adapter_live

// Live qualification of the model endpoint against unmodified clients: the
// official OpenAI and Anthropic Python SDKs, streaming and tools, through the
// platform's real forwarding code to a real provider (in practice a local
// Ollama, which speaks both APIs). scripts/verify-adapter.py runs it:
//
//	AGENTCAPSULE_ADAPTER_PROVIDER_URL  provider base URL (http://127.0.0.1:11434)
//	AGENTCAPSULE_ADAPTER_MODEL         upstream model with tool calling
//	AGENTCAPSULE_ADAPTER_PYTHON        Python with the openai and anthropic SDKs
package agentadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// gatewayForwarder stands in for the worker: the same gateway code, with alias
// "oa" on an OpenAI-compatible provider and "an" on an Anthropic one.
type gatewayForwarder struct {
	g     *llmgateway.Gateway
	base  string
	model string
	calls int
}

func (f *gatewayForwarder) ForwardLLM(ctx context.Context, key string, in capsuleprotocol.LLMForward) (capsuleprotocol.LLMForwardResult, error) {
	f.calls++
	route := llmgateway.Route{Kind: "openai_compatible", BaseURL: f.base + "/v1", UpstreamModel: f.model, Secret: "unused", Key: "live/" + in.Alias}
	if in.Alias == "an" {
		route.Kind, route.BaseURL = "anthropic", f.base
	} else if in.Alias != "oa" {
		return capsuleprotocol.LLMForwardResult{}, &capsuleprotocol.PlatformError{Code: "not_found"}
	}
	out, err := f.g.Forward(ctx, route, in.Dialect, in.Body)
	switch {
	case errors.Is(err, llmgateway.ErrDialect):
		return capsuleprotocol.LLMForwardResult{}, &capsuleprotocol.PlatformError{Code: "dialect"}
	case errors.Is(err, llmgateway.ErrInvalid):
		return capsuleprotocol.LLMForwardResult{}, &capsuleprotocol.PlatformError{Code: "invalid"}
	case err != nil:
		return capsuleprotocol.LLMForwardResult{}, &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	return capsuleprotocol.LLMForwardResult{Body: out.Body, InputTokens: out.Usage.InputTokens, OutputTokens: out.Usage.OutputTokens}, nil
}

func liveEnv(t *testing.T) (base, model, python string) {
	t.Helper()
	base, model, python = os.Getenv("AGENTCAPSULE_ADAPTER_PROVIDER_URL"), os.Getenv("AGENTCAPSULE_ADAPTER_MODEL"), os.Getenv("AGENTCAPSULE_ADAPTER_PYTHON")
	if base == "" || model == "" || python == "" {
		t.Fatal("AGENTCAPSULE_ADAPTER_PROVIDER_URL, AGENTCAPSULE_ADAPTER_MODEL and AGENTCAPSULE_ADAPTER_PYTHON are required")
	}
	return strings.TrimRight(base, "/"), model, python
}

// serveEndpoint starts the model endpoint on a loopback port, as in the VM.
func serveEndpoint(t *testing.T, cfg Config, f Forwarder) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: &ModelEndpoint{Config: cfg, Platform: f}, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// The SDK client script: what an unmodified agent does with each SDK. It only
// reads the standard environment variables the adapter sets.
const sdkScript = `
import json, os, sys
import openai, anthropic

tools_oa = [{"type": "function", "function": {"name": "list_directory", "description": "List the files of a directory.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]
tools_an = [{"name": "list_directory", "description": "List the files of a directory.",
    "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}]
ask = "Use the list_directory tool to list the directory /tmp. Do not answer in text."
out = {}

oa = openai.OpenAI()  # OPENAI_BASE_URL and OPENAI_API_KEY from the environment
r = oa.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": ask}], tools=tools_oa, max_tokens=200)
out["openai_model"] = r.model
out["openai_tool"] = [c.function.name for c in (r.choices[0].message.tool_calls or [])]
out["openai_args"] = [json.loads(c.function.arguments) for c in (r.choices[0].message.tool_calls or [])]

names, args = {}, {}
stream = oa.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": ask}], tools=tools_oa, max_tokens=200,
    stream=True, stream_options={"include_usage": True})
usage = None
for chunk in stream:
    if chunk.usage:
        usage = chunk.usage.completion_tokens
    for choice in chunk.choices:
        for c in choice.delta.tool_calls or []:
            if c.function and c.function.name:
                names[c.index] = c.function.name
            if c.function and c.function.arguments:
                args[c.index] = args.get(c.index, "") + c.function.arguments
out["openai_stream_tool"] = [names[i] for i in sorted(names)]
out["openai_stream_args"] = [json.loads(args[i]) for i in sorted(args)]
out["openai_stream_usage"] = usage

text = oa.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "Reply with the single word: ready"}], max_tokens=20, stream=True)
out["openai_stream_text"] = "".join(c.choices[0].delta.content or "" for c in text if c.choices)

an = anthropic.Anthropic()  # ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY from the environment
m = an.messages.create(model="claude-sonnet", max_tokens=200, tools=tools_an, messages=[{"role": "user", "content": ask}])
out["anthropic_model"] = m.model
out["anthropic_tool"] = [b.name for b in m.content if b.type == "tool_use"]
with an.messages.stream(model="claude-sonnet", max_tokens=200, tools=tools_an, messages=[{"role": "user", "content": ask}]) as s:
    final = s.get_final_message()
out["anthropic_stream_tool"] = [b.name for b in final.content if b.type == "tool_use"]
out["anthropic_stream_input"] = [b.input for b in final.content if b.type == "tool_use"]
out["anthropic_stream_stop"] = final.stop_reason

try:
    oa.chat.completions.create(model="no-such-alias", messages=[{"role": "user", "content": "x"}])
    out["missing"] = "accepted"
except openai.NotFoundError as e:
    out["missing"] = "not_found"
json.dump(out, sys.stdout)
`

func TestLiveOfficialSDKsThroughTheModelEndpoint(t *testing.T) {
	base, model, python := liveEnv(t)
	f := &gatewayForwarder{g: llmgateway.New(llmgateway.Config{Timeout: 2 * time.Minute}), base: base, model: model}
	cfg, err := ParseConfig([]byte(`{"version":1,"command":["/bin/true"],"models":{"gpt-4o":"oa","claude-sonnet":"an"}}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ModelAddress = serveEndpoint(t, cfg, f)
	script := filepath.Join(t.TempDir(), "client.py")
	if err = os.WriteFile(script, []byte(sdkScript), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", script)
	cmd.Env = cfg.Environment(t.TempDir(), nil)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	t.Log(string(raw))
	var out struct {
		OpenAIModel       string           `json:"openai_model"`
		OpenAITool        []string         `json:"openai_tool"`
		OpenAIArgs        []map[string]any `json:"openai_args"`
		OpenAIStreamTool  []string         `json:"openai_stream_tool"`
		OpenAIStreamArgs  []map[string]any `json:"openai_stream_args"`
		OpenAIStreamUsage *int             `json:"openai_stream_usage"`
		OpenAIStreamText  string           `json:"openai_stream_text"`
		AnthropicModel    string           `json:"anthropic_model"`
		AnthropicTool     []string         `json:"anthropic_tool"`
		AnthropicStream   []string         `json:"anthropic_stream_tool"`
		AnthropicInput    []map[string]any `json:"anthropic_stream_input"`
		AnthropicStop     string           `json:"anthropic_stream_stop"`
		Missing           string           `json:"missing"`
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.OpenAIModel != "gpt-4o" || len(out.OpenAITool) != 1 || out.OpenAITool[0] != "list_directory" || out.OpenAIArgs[0]["path"] != "/tmp" {
		t.Error("OpenAI SDK, tools", out.OpenAIModel, out.OpenAITool, out.OpenAIArgs)
	}
	if len(out.OpenAIStreamTool) != 1 || out.OpenAIStreamTool[0] != "list_directory" || out.OpenAIStreamArgs[0]["path"] != "/tmp" || out.OpenAIStreamUsage == nil {
		t.Error("OpenAI SDK, streamed tools", out.OpenAIStreamTool, out.OpenAIStreamArgs, out.OpenAIStreamUsage)
	}
	if strings.TrimSpace(out.OpenAIStreamText) == "" {
		t.Error("OpenAI SDK, streamed text")
	}
	if out.AnthropicModel != "claude-sonnet" || len(out.AnthropicTool) != 1 || out.AnthropicTool[0] != "list_directory" {
		t.Error("Anthropic SDK, tools", out.AnthropicModel, out.AnthropicTool)
	}
	if len(out.AnthropicStream) != 1 || out.AnthropicStream[0] != "list_directory" || out.AnthropicInput[0]["path"] != "/tmp" || out.AnthropicStop != "tool_use" {
		t.Error("Anthropic SDK, streamed tools", out.AnthropicStream, out.AnthropicInput, out.AnthropicStop)
	}
	if out.Missing != "not_found" {
		t.Error("an unknown alias", out.Missing)
	}
}

// The whole adapter: a delivered invocation runs an unmodified Python agent
// (the OpenAI SDK in a tool loop), whose model calls go through the endpoint;
// its printed answer is the invocation's result.
const agentScript = `
import json, os, sys
import openai
client = openai.OpenAI()
question = sys.stdin.read()
tools = [{"type": "function", "function": {"name": "read_file", "description": "Read a text file.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]
messages = [{"role": "system", "content": "Answer the user. To read a file, call read_file with its path."},
            {"role": "user", "content": question}]
for _ in range(4):
    r = client.chat.completions.create(model="gpt-4o", messages=messages, tools=tools, max_tokens=300)
    m = r.choices[0].message
    if not m.tool_calls:
        print(m.content)
        break
    messages.append(m.model_dump(exclude_none=True))
    for c in m.tool_calls:
        path = json.loads(c.function.arguments)["path"]
        try:
            content = open(path).read()
        except OSError as e:
            content = "error: " + str(e)
        messages.append({"role": "tool", "tool_call_id": c.id, "content": content})
`

type livePlatform struct {
	*gatewayForwarder
	file        []byte
	completions []capsuleprotocol.InvocationCompletion
}

func (p *livePlatform) FetchAttachment(context.Context, capsuleprotocol.AttachmentRef) ([]byte, error) {
	return append([]byte(nil), p.file...), nil
}
func (p *livePlatform) CompleteInvocation(_ context.Context, _ string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	if err := in.Validate(); err != nil {
		return capsuleprotocol.CompletionReceipt{}, err
	}
	p.completions = append(p.completions, in)
	return capsuleprotocol.CompletionReceipt{OperationID: in.OperationID, State: in.Outcome}, nil
}
func (p *livePlatform) Reply(context.Context, string, string, capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	return capsuleprotocol.PlatformReceipt{}, errors.New("unused")
}

func TestLiveUnmodifiedAgentAnswersAnInvocation(t *testing.T) {
	base, model, python := liveEnv(t)
	p := &livePlatform{gatewayForwarder: &gatewayForwarder{g: llmgateway.New(llmgateway.Config{Timeout: 2 * time.Minute}), base: base, model: model},
		file: []byte("The access code of the vault is 4417.\n")}
	dir := t.TempDir()
	agent := filepath.Join(dir, "agent.py")
	if err := os.WriteFile(agent, []byte(agentScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig([]byte(`{"version":1,"command":["` + python + `","-I","` + agent + `"],"models":{"gpt-4o":"oa"},"timeout_seconds":600}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ModelAddress = serveEndpoint(t, cfg, p)
	store, err := harnessstore.Open(t.Context(), filepath.Join(dir, "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	home := t.TempDir()
	engine, err := New("a", home, store, p, CommandRunner(cfg, home))
	if err != nil {
		t.Fatal(err)
	}
	ref := capsuleprotocol.AttachmentRef{ID: "att_0123456789abcdef0123456789abcdef", Name: "vault.txt", MediaType: "text/plain", Size: int64(len(p.file)),
		SHA256: strings.Repeat("0", 64)}
	b, _ := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op-live", Attachments: []capsuleprotocol.AttachmentRef{ref},
		Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: "What is the access code of the vault, according to the attached file?"}}})
	e := harnessstore.Event{ID: "live", Subjects: []string{"agent/a", "event/live"}, Body: b}
	r, err := store.Apply(t.Context(), e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) { return engine.Handle(ctx, e, tx) })
	if err != nil || !capsuleprotocol.IsWorkingResult(r.Result) {
		t.Fatal(string(r.Result), err)
	}
	if _, err = engine.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(p.completions) != 1 || p.completions[0].Outcome != "completed" {
		t.Fatal("no answer", p.completions)
	}
	answer := p.completions[0].Content[0].Text
	t.Log("agent answer:", answer, "model calls:", p.calls)
	if !strings.Contains(answer, "4417") || p.calls < 2 {
		t.Fatal("the agent did not read the file through a tool call", answer, p.calls)
	}
}
