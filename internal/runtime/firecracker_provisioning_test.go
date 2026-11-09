//go:build linux

package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestHarnessImagesAreSharedReadOnlyFiles(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "harness.ext4")
	if err := os.WriteFile(img, make([]byte, 128<<10), 0o444); err != nil {
		t.Fatal(err)
	}
	good := &HarnessImage{Path: img, Digest: "sha256:" + strings.Repeat("a", 64), Entrypoint: []string{"/bin/harness"}}
	if err := validHarness(good); err != nil {
		t.Fatal(err)
	}
	if err := validHarness(nil); err != nil {
		t.Fatal("the built-in harness needs no image", err)
	}
	writable := filepath.Join(dir, "writable.ext4")
	if err := os.WriteFile(writable, make([]byte, 128<<10), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil { // past the umask
		t.Fatal(err)
	}
	private := filepath.Join(dir, "private.ext4")
	if err := os.WriteFile(private, make([]byte, 128<<10), 0o400); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]HarnessImage{
		"relative":      {Path: "harness.ext4", Digest: good.Digest, Entrypoint: good.Entrypoint},
		"writable":      {Path: writable, Digest: good.Digest, Entrypoint: good.Entrypoint},
		"unreadable":    {Path: private, Digest: good.Digest, Entrypoint: good.Entrypoint},
		"digest":        {Path: img, Digest: "md5:x", Entrypoint: good.Entrypoint},
		"entrypoint":    {Path: img, Digest: good.Digest, Entrypoint: []string{"bin/harness"}},
		"no entrypoint": {Path: img, Digest: good.Digest},
		"missing":       {Path: filepath.Join(dir, "none"), Digest: good.Digest, Entrypoint: good.Entrypoint},
	} {
		if validHarness(&bad) == nil {
			t.Fatal("accepted:", name)
		}
	}
	if !sameHarness(good, &HarnessImage{Path: img, Digest: good.Digest, Entrypoint: []string{"/bin/harness"}}) || sameHarness(good, nil) {
		t.Fatal("harness identity comparison")
	}
	// Sharing is by hard link: one inode for every agent of the release.
	linked := filepath.Join(dir, "jail.ext4")
	if err := linkOrCopy(img, linked); err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(img)
	b, _ := os.Stat(linked)
	if !os.SameFile(a, b) {
		t.Fatal("the jail got a copy instead of the shared image")
	}
	// A registry harness needs the authenticated guest contract.
	root := t.TempDir()
	for _, d := range []string{"bin", "volumes", "groups"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"kernel", "initrd"} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	volume := filepath.Join(root, "volumes", "data")
	if err := os.WriteFile(volume, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &FirecrackerHost{root: root, cgroup: filepath.Join(root, "groups")}
	agent := &HostAgent{ID: "a", UID: 60000, Volume: volume, Harness: good, Run: &VMRun{ID: "0123456789abcdef", Generation: 1, Phase: "STARTING"}}
	if err := h.prepare(agent); err == nil {
		t.Fatal("a registry harness was prepared without the authenticated contract")
	}
}
