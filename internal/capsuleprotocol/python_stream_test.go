//go:build linux

package capsuleprotocol

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

func pythonStreamClient(t *testing.T, api PlatformAPI, script string) {
	t.Helper()
	_, id, sock := localStreamBridge(t, api)
	raw, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", `
import json, socket, sys, time
sys.path.insert(0, "../../sdk/python")
from agentcapsule_harness import Identity, OutputStream, Platform, PlatformError
platform = Platform(Identity.from_json(json.loads(sys.argv[1])), sys.argv[2])
`+script, string(raw), sock)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python client: %s: %v", out, err)
	}
}

func TestPythonModelStreaming(t *testing.T) {
	api := &modelStreamFake{finish: make(chan struct{})}
	close(api.finish)
	pythonStreamClient(t, api, `
messages = [{"role":"user", "content":"hello"}]
frames = list(platform.complete_llm_stream("ok","small",messages))
assert [f["type"] for f in frames] == ["start","text","end"] and frames[1]["text"] == "early"
assert frames[-1]["input_tokens"] == 2 and frames[-1]["soft_budget_exceeded"] is False
assert list(platform.complete_llm_stream("cut","small",messages))[-1] == {"type":"end","outcome":"outcome_unknown","seq":2}
native = list(platform.forward_llm_stream("native","small","anthropic",{"stream":True}))
assert native[1]["event"]["data"]["delta"]["text"] == "<x> & 😀"
try:
    list(platform.complete_llm_stream("denied","small",messages))
    raise AssertionError("a refusal must precede the first frame")
except PlatformError as e:
    assert e.code == "quota_exceeded"
`)
}

// A reopened stream starts at the host's last durably appended sequence.
type resumablePythonStream struct{ streamFake }

func (f *resumablePythonStream) OpenOutputStream(ctx context.Context, op string, attempt int) (OutputStream, error) {
	stream, err := f.streamFake.OpenOutputStream(ctx, op, attempt)
	if err != nil {
		return nil, err
	}
	if frames := f.stored(); len(frames) != 0 {
		stream.(*fakeStream).last = frames[len(frames)-1].Seq
	}
	return stream, nil
}

func TestPythonDuplexStreaming(t *testing.T) {
	api := &resumablePythonStream{}
	pythonStreamClient(t, api, `
with OutputStream(platform,"op_python") as stream:
    stream.step("read","started","lecture")
    with stream._updates:
        assert stream._updates.wait_for(lambda: stream._acked == 1, 5)
    stream._socket.shutdown(socket.SHUT_RDWR)
    with stream._updates:
        assert stream._updates.wait_for(lambda: stream._broken, 5)
    stream.delta("résultat")
    stream.step("read","done")
assert stream.reason == "done" and stream.attempt == 1
`)
	if got := api.stored(); len(got) != 3 || got[1].Text != "résultat" || got[2].Seq != 3 {
		t.Fatalf("stored frames: %+v", got)
	}
}
