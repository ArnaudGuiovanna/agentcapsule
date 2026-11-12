//go:build linux

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSLIMConfigNeedsTwoSocketsAndAnUnprivilegedBridge(t *testing.T) {
	if l, ln, err := (ServiceConfig{}).OpenSLIM(); l != nil || ln != nil || err != nil {
		t.Fatal("a host without SLIM", err)
	}
	dir, err := os.MkdirTemp("", "slim")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	uid := os.Getuid()
	if uid == 0 {
		uid = 65534 // the bridge never runs as root
	}
	good := ServiceSLIM{BridgeSocket: filepath.Join(dir, "bridge.sock"), WorkerSocket: filepath.Join(dir, "worker.sock"), BridgeUID: uid}
	link, ln, err := (ServiceConfig{SLIM: &good}).OpenSLIM()
	if err != nil || link == nil || ln == nil {
		t.Fatal("valid configuration refused", err)
	}
	info, err := os.Stat(good.WorkerSocket)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("worker socket", info, err)
	}
	ln.Close()
	for name, c := range map[string]ServiceSLIM{
		"root bridge":     {BridgeSocket: good.BridgeSocket, WorkerSocket: good.WorkerSocket, BridgeUID: 0},
		"same socket":     {BridgeSocket: good.BridgeSocket, WorkerSocket: good.BridgeSocket, BridgeUID: uid},
		"relative":        {BridgeSocket: "bridge.sock", WorkerSocket: good.WorkerSocket, BridgeUID: uid},
		"unclean":         {BridgeSocket: dir + "/../x/bridge.sock", WorkerSocket: good.WorkerSocket, BridgeUID: uid},
		"too long a path": {BridgeSocket: "/" + strings.Repeat("a", 120), WorkerSocket: good.WorkerSocket, BridgeUID: uid},
	} {
		if _, _, err := (ServiceConfig{SLIM: &c}).OpenSLIM(); !errors.Is(err, ErrSLIMConfig) {
			t.Fatal(name, err)
		}
	}
}
