//go:build linux

package capsuleprotocol

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// localStreamBridge serves the guest's platform bridge in front of a host
// whose streams api keeps, and returns the harness's local client.
func localStreamBridge(t *testing.T, api *streamFake) (*PlatformClient, Identity, string) {
	t.Helper()
	remote, host, _, _ := platformFixtureFor(t, api)
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
	return local, host.Identity, path
}

// The guest's bridge relays the duplex stream frame by frame, both ways:
// the harness's frames reach the host as they come, and the host's
// acknowledgments and its cancellation reach the harness.
func TestGuestBridgeRelaysTheOutputStream(t *testing.T) {
	api := &streamFake{appended: make(chan struct{}, 16)}
	local, _, _ := localStreamBridge(t, api)
	w, err := local.OpenOutputStream(t.Context(), "op_1")
	if err != nil || w.Attempt() != 1 {
		t.Fatal("open through the bridge", err)
	}
	if err = w.Delta("first words"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-api.appended:
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge held the frame back")
	}
	deadline := time.Now().Add(5 * time.Second)
	for w.Acked() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w.Acked() != 1 {
		t.Fatal("the acknowledgment did not come back through the bridge")
	}
	if err = w.Step("check", StepDone, ""); err != nil {
		t.Fatal(err)
	}
	if reason, err := w.Close(t.Context()); err != nil || reason != StreamDone {
		t.Fatal("close through the bridge", reason, err)
	}
	if got := api.stored(); len(got) != 2 || got[1] != (OutputFrame{Type: "step", Seq: 2, Step: "check", State: StepDone}) {
		t.Fatal("stored", got)
	}

	// The cancellation crosses the bridge.
	w, err = local.OpenOutputStream(t.Context(), "op_2")
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	s := api.streams[len(api.streams)-1]
	api.mu.Unlock()
	s.signals <- StreamSignal{Reason: StreamCanceled}
	select {
	case <-w.Canceled():
	case <-time.After(5 * time.Second):
		t.Fatal("the cancellation did not cross the bridge")
	}
	<-w.Done()
	if w.Reason() != StreamTerminal {
		t.Fatal(w.Reason(), w.Err())
	}
}

// The host's refusal reaches the harness as the host gave it; a malformed
// frame from the harness closes the stream invalid at the bridge.
func TestGuestBridgeRefusesAsTheHostDoes(t *testing.T) {
	api := &streamFake{deny: true}
	local, id, path := localStreamBridge(t, api)
	_, err := local.OpenOutputStream(t.Context(), "op_1")
	var refusal *PlatformError
	if !errors.As(err, &refusal) || refusal.Code != "capability_denied" {
		t.Fatal("refusal through the bridge", err)
	}
	api.deny = false
	open, _ := encodeFrame(openFrame{Type: "open", Protocol: Version, Identity: id, OperationID: "op_1"})
	body := string(open) + `{"type":"delta","seq":1,"text":"ok"}` + "\n" + `{"type":"delta","seq":2,"text":"x","forged":true}` + "\n"
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
	resp, err := client.Post("http://harness.local"+OutputStreamPath, ndjsonType, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if resp.StatusCode != 200 || !strings.Contains(lines[0], `"type":"opened"`) || lines[len(lines)-1] != `{"type":"closed","reason":"invalid"}` {
		t.Fatal("a malformed frame at the bridge", resp.StatusCode, lines)
	}
	// A forged identity is refused before the host is asked.
	opened := len(api.opens)
	forged, _ := encodeFrame(openFrame{Type: "open", Protocol: Version, Identity: Identity{Incarnation: 1, AgentID: "other", Generation: 1, VMID: id.VMID}, OperationID: "op_1"})
	resp, err = client.Post("http://harness.local"+OutputStreamPath, ndjsonType, strings.NewReader(string(forged)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(api.opens) != opened {
		t.Fatal("a forged identity crossed the bridge", resp.StatusCode)
	}
}
