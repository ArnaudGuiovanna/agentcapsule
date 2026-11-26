//go:build linux

package agentadapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Use the Pi extension's actual wire messages against the production A2A
// handler. The fixture only supplies the host's consent and reply decisions.
func TestPiToolsUseTheAdaptersPeerEndpoint(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js required to exercise the Pi tools")
	}
	mod, err := filepath.Abs("../../examples/pi-agent/peers.mjs")
	if err != nil {
		t.Fatal(err)
	}
	const script = `
import { pathToFileURL } from "node:url";
const [mod, name, id, raw] = process.argv.slice(1);
const {default: register} = await import(pathToFileURL(mod));
const tools = {};
register({registerTool: t => { tools[t.name]=t; }});
try {
  const result=await tools[name].execute(id,JSON.parse(raw));
  process.stdout.write(result.content[0].text);
} catch(err) {
  process.stdout.write(String(err.message));
  process.exitCode=1;
}`
	l := newA2ALab(t, func(ctx context.Context, l *a2aLab, _ Job) string {
		call := func(tool, id, args string, success bool, want string) {
			t.Helper()
			cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", script, mod, tool, id, args)
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_A2A_URL="+l.url)
			b, err := cmd.CombinedOutput()
			if (err == nil) != success || !strings.Contains(string(b), want) {
				t.Errorf("%s: output %q, error %v, want %q (success=%t)", tool, b, err, want, success)
			}
		}
		call("agent_discover", "find", `{"skill":10302}`, true, `"agent_id":"b"`)
		const ask = `{"agent_id":"b","question":"Review the passage."}`
		call("agent_ask", "idempotent", ask, true, `"state":"PENDING_APPROVAL"`)
		call("agent_ask", "idempotent", ask, true, `"request_id":"arq_1"`)
		const status = `{"agent_id":"b","request_id":"arq_1"}`
		l.peers.set("arq_1", "DELIVERING")
		call("agent_request_status", "progress", status, true, `"state":"DELIVERING"`)
		l.peers.replied("arq_1", "the review", "")
		call("agent_request_status", "read", status, true, `"reply":["the review"]`)
		call("agent_ask", "declined", ask, true, `"request_id":"arq_2"`)
		l.peers.set("arq_2", "DECLINED")
		call("agent_request_status", "refusal", `{"agent_id":"b","request_id":"arq_2"}`, true, `"state":"DECLINED"`)
		l.peers.refuse("capability_denied")
		call("agent_ask", "denied", ask, false, "permission denied")
		return "done"
	})
	l.deliver(invocation(t, "pi-1", "Ask for review"))
	l.drain()
	l.peers.mu.Lock()
	defer l.peers.mu.Unlock()
	if len(l.peers.submissions) != 2 {
		t.Fatalf("wrong number of accepted, distinct sends: %d", len(l.peers.submissions))
	}
}
