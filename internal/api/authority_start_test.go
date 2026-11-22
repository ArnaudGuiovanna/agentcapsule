package api

import (
	"net"
	"os/exec"
	"path/filepath"
	"testing"
)

// FIX-1: startAuthorityService, and a restart, return once the service's API
// socket accepts a connection. Before, they returned once the process had
// started, and a test that reached the socket at once (the API's own start,
// agentcapsule-admin) raced the service's start under load.
func TestTheStartedAuthorityServiceListensAtOnce(t *testing.T) {
	dir := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agentcapsule-admin", "agentcapsule-authority"} {
		build := exec.CommandContext(t.Context(), "go", "build", "-o", filepath.Join(dir, name), "./cmd/"+name)
		build.Dir = root
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
	}
	authority := startAuthorityService(t, dir)
	listens := func(when string) {
		t.Helper()
		conn, err := net.Dial("unix", authority.socket)
		if err != nil {
			t.Fatal("the authority service does not listen", when, err)
		}
		conn.Close()
	}
	listens("after its start")
	authority.stop(t)
	authority.start(t)
	listens("after its restart")
}
