//go:build linux

package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Inspect the exact configuration emitted for Firecracker. These directories
// are ordinary test files: kernel enforcement is checked in the KVM campaign.
func TestProvisionedResourcesReachVMConfiguration(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"bin", "volumes", "groups"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"kernel", "initrd"} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte("configuration fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	volume := filepath.Join(root, "volumes", "data")
	if err := os.WriteFile(volume, []byte("configuration fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &FirecrackerHost{root: root, cgroup: filepath.Join(root, "groups")}
	a := &HostAgent{ID: "a", UID: 60000, Volume: volume, Resources: VMResources{VCPUs: 3, MemoryMiB: 768, VolumeMiB: 128}, Run: &VMRun{ID: "0123456789abcdef", Generation: 1, Phase: "STARTING"}}
	if err := h.prepare(a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h.jail(a.Run), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Machine struct {
			CPUs   int `json:"vcpu_count"`
			Memory int `json:"mem_size_mib"`
		} `json:"machine-config"`
	}
	if err = json.Unmarshal(b, &config); err != nil {
		t.Fatal(err)
	}
	if config.Machine.CPUs != 3 || config.Machine.Memory != 768 {
		t.Fatal("reservation resources lost", config)
	}
	for file, want := range map[string]string{"memory.max": "1073741824", "memory.swap.max": "0", "cpu.max": "300000 100000", "pids.max": "32"} {
		b, err := os.ReadFile(filepath.Join(h.group(a.Run), file))
		if err != nil || string(b) != want {
			t.Fatal(file, string(b), err)
		}
	}
}
