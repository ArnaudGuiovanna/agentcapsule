//go:build linux

package guestinit

import (
	"strconv"
	"strings"
	"testing"
)

// Each memory-backed directory has an explicit size: without one, the kernel
// lets every tmpfs grow to half of the guest's memory, so /tmp and /run
// together could take all of it (product.md §3, "size-limited tmpfs").
func TestBootMountsBoundEveryTmpfs(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range BootMounts() {
		if m.Kind != "tmpfs" {
			continue
		}
		seen[m.Target] = true
		size := ""
		for _, option := range strings.Split(m.Data, ",") {
			if v, ok := strings.CutPrefix(option, "size="); ok {
				size = v
			}
		}
		switch {
		case size == "":
			t.Fatal(m.Target, "has no size:", m.Data)
		case strings.HasSuffix(size, "%"):
			// A share of the guest's memory, which is the agent's memory_mib.
			n, err := strconv.Atoi(strings.TrimSuffix(size, "%"))
			if err != nil || n < 1 || n > 25 {
				t.Fatal(m.Target, "size", size)
			}
		case strings.HasSuffix(size, "m"):
			n, err := strconv.Atoi(strings.TrimSuffix(size, "m"))
			if err != nil || n < 1 || n > 16 {
				t.Fatal(m.Target, "size", size)
			}
		default:
			t.Fatal(m.Target, "size", size)
		}
	}
	if !seen["/tmp"] || !seen["/run"] {
		t.Fatal("tmpfs mounts", seen)
	}
}
