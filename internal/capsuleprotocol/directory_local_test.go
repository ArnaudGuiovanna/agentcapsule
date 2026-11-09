//go:build linux

package capsuleprotocol

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A harness's search goes through capsule-init's local bridge to the host
// unchanged; the bridge adds the boot identity, never the harness.
func TestDirectoryFindCrossesTheGuestBridge(t *testing.T) {
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
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()
	local, err := NewLocalPlatformClient(host.Identity, path)
	if err != nil {
		t.Fatal(err)
	}
	calls := api.calls.Load()
	found, err := local.FindAgents(t.Context(), DirectoryQuery{Skills: []int{10302}})
	if err != nil || len(found) != 1 || found[0].AgentID != "b" || api.calls.Load() != calls+1 {
		t.Fatal("search through the bridge", found, err)
	}
	if _, err = local.FindAgents(t.Context(), DirectoryQuery{}); err == nil || api.calls.Load() != calls+1 {
		t.Fatal("an invalid search crossed the bridge", err)
	}
}
