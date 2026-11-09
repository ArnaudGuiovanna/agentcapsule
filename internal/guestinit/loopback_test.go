//go:build linux

package guestinit

import (
	"net"
	"os"
	"os/exec"
	"testing"
)

// In a fresh network namespace the loopback is down and 127.0.0.1 unreachable,
// as in a booting guest; BringLoopbackUp makes it usable.
func TestBringLoopbackUpInAFreshNetworkNamespace(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_LOOPBACK_CHILD") == "1" {
		// Binding works while the interface is down; connecting does not.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			c.Close()
			t.Fatal("loopback already usable in a fresh namespace")
		}
		if err = BringLoopbackUp(); err != nil {
			t.Fatal(err)
		}
		if err = BringLoopbackUp(); err != nil {
			t.Fatal("not idempotent", err)
		}
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare is not installed")
	}
	if exec.Command(unshare, "-rn", "true").Run() != nil {
		t.Skip("unprivileged user and network namespaces are not available")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run=^TestBringLoopbackUpInAFreshNetworkNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_LOOPBACK_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
