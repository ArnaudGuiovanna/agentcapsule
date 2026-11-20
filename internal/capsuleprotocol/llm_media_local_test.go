//go:build linux

package capsuleprotocol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const pythonMediaCalls = `import json, sys
sys.path.insert(0, sys.argv[1])
from agentcapsule_harness import Identity, Platform, PlatformError
p = Platform(Identity.from_json(json.loads(sys.argv[2])), sys.argv[3])
out = {"embed": p.embed_llm("e1", "embed", ["one", "two"]),
       "transcribe": p.transcribe_llm("t1", "voice", b"bonjour", "mp3", 3, language="fr"),
       "ocr": p.ocr_llm("o1", "ocr", b"%PDF", "application/pdf", 2)}
try:
    p.ocr_llm("unsupported", "ocr", b"%PDF", "application/pdf", 2)
except PlatformError as e:
    out["refused"] = e.code
print(json.dumps(out))
`

// The guest's relay carries the media routes from the harness's Unix socket
// to the host, and the Python SDK speaks them: the harness sees the host's
// answers and its typed refusals.
func TestLLMMediaRoutesCrossTheGuestRelayAndThePythonSDK(t *testing.T) {
	remote, host, _, api, _ := platformFixture(t)
	s, err := NewLocalPlatformServer(remote)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "platform.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l, uint32(os.Geteuid())) }()
	t.Cleanup(func() { cancel(); <-done })
	local, err := NewLocalPlatformClient(host.Identity, path)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := local.EmbedLLM(t.Context(), "e1", mediaEmbed); err != nil || len(e.Embeddings) != 2 {
		t.Fatal(e, err)
	}
	if tr, err := local.TranscribeLLM(t.Context(), "t1", mediaTranscribe); err != nil || tr.Text != "heard bonjour" {
		t.Fatal(tr, err)
	}
	if o, err := local.OCRLLM(t.Context(), "o1", mediaOCR); err != nil || o.PagesProcessed != 2 {
		t.Fatal(o, err)
	}
	var pe *PlatformError
	if _, err = local.OCRLLM(t.Context(), "unsupported", mediaOCR); !errors.As(err, &pe) || pe.Code != "unsupported" {
		t.Fatal("the relay lost the unsupported code", err)
	}
	before := api.calls.Load()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the Python SDK test")
	}
	dir := t.TempDir()
	sdk, err := os.ReadFile("../../sdk/python/agentcapsule_harness.py")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "media.py")
	if err = os.WriteFile(filepath.Join(dir, "agentcapsule_harness.py"), sdk, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(script, []byte(pythonMediaCalls), 0o644); err != nil {
		t.Fatal(err)
	}
	id, _ := json.Marshal(host.Identity)
	cmd := exec.Command(python, "-I", script, dir, string(id), path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(raw))
	}
	var got struct {
		Embed struct {
			Embeddings  [][]float64 `json:"embeddings"`
			Dimensions  int         `json:"dimensions"`
			InputTokens int         `json:"input_tokens"`
		} `json:"embed"`
		Transcribe LLMTranscribeResult `json:"transcribe"`
		OCR        LLMOCRResult        `json:"ocr"`
		Refused    string              `json:"refused"`
	}
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err, string(raw))
	}
	if len(got.Embed.Embeddings) != 2 || got.Embed.Embeddings[0][0] != 1 || got.Embed.Dimensions != 1 || got.Embed.InputTokens != 2 ||
		got.Transcribe.Text != "heard bonjour" || got.Transcribe.DurationSeconds != 3 || got.Transcribe.Segments[0].Text != "fr" ||
		got.OCR.PagesProcessed != 2 || got.OCR.Pages[0].Markdown != "# application/pdf" || got.Refused != "unsupported" {
		t.Fatal(string(raw))
	}
	if api.calls.Load() != before+4 {
		t.Fatal("the SDK's calls did not all reach the host", api.calls.Load()-before)
	}
}
