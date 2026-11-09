package capsuleprotocol

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootArchiveCarriesTheHarnessLaunchOnlyWhenGiven(t *testing.T) {
	_, guest, err := NewBootCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	write := func(h *HarnessLaunch) ([]byte, error) {
		f, err := os.Create(filepath.Join(t.TempDir(), "initrd"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err = AppendBootConfig(f, guest, h); err != nil {
			return nil, err
		}
		return os.ReadFile(f.Name())
	}
	plain, err := write(nil)
	if err != nil || bytes.Contains(plain, []byte("harness.json")) {
		t.Fatal("a built-in harness boot carries a launch file", err)
	}
	withHarness, err := write(&HarnessLaunch{Entrypoint: []string{"/bin/harness", "--serve"}})
	if err != nil || !bytes.Contains(withHarness, []byte("etc/capsule/harness.json")) || !bytes.Contains(withHarness, []byte(`{"entrypoint":["/bin/harness","--serve"]}`)) {
		t.Fatal("launch file missing", err)
	}
	for _, bad := range [][]string{nil, {"bin/harness"}, {"/bin/../harness"}, {"/"}, {"/bin/h", ""}} {
		if _, err = write(&HarnessLaunch{Entrypoint: bad}); err == nil {
			t.Fatal("invalid entrypoint accepted", bad)
		}
	}
}
