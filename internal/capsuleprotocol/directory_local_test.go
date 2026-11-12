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
	// The reads behind the adapter's A2A endpoint cross it the same way.
	if d, err := local.DescribeAgent(t.Context(), "agt_b"); err != nil || d.AgentID != "agt_b" || d.Description != "Summarizes." || api.calls.Load() != calls+2 {
		t.Fatal("an Agent Card read through the bridge", d, err)
	}
	var pe *PlatformError
	if _, err := local.DescribeAgent(t.Context(), "hidden"); !errors.As(err, &pe) || pe.Code != "not_found" {
		t.Fatal("a hidden agent through the bridge", err)
	}
	if st, err := local.RequestStatus(t.Context(), "arq_1"); err != nil || st.RequestID != "arq_1" || st.State != "PROCESSING" || !st.ExpiresAt.Equal(statusDeadline) {
		t.Fatal("a request state through the bridge", st, err)
	}
	if _, err := local.RequestStatus(t.Context(), "foreign"); !errors.As(err, &pe) || pe.Code != "not_found" {
		t.Fatal("another agent's request through the bridge", err)
	}
}
