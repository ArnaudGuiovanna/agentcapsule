//go:build linux

package worker

import (
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The KVM tests of hostile guests (product_hostile_integration_test.go) read
// each VMM's cgroup: its directory from /proc/<pid>/cgroup, then files of
// "key value" lines or of one number.
func TestCgroupFilesParse(t *testing.T) {
	keys, err := cgroupKeyed("usage_usec 1234\nuser_usec 1000\nnr_throttled 0\n")
	if err != nil || len(keys) != 3 || keys["usage_usec"] != 1234 || keys["nr_throttled"] != 0 {
		t.Fatal("keyed", keys, err)
	}
	for _, bad := range []string{"usage_usec x\n", "a b c\n", "max\n", "oom -1\n", "oom 1\noom 2\n"} {
		if _, err := cgroupKeyed(bad); err == nil {
			t.Error("keyed accepted", bad)
		}
	}
	for text, want := range map[string]int64{"536870912\n": 512 << 20, "0": 0, "max\n": maxCgroupValue} {
		if got, err := cgroupNumber(text); err != nil || got != want {
			t.Error("number", text, got, err)
		}
	}
	for _, bad := range []string{"", "-1\n", "12 13\n", "x\n"} {
		if _, err := cgroupNumber(bad); err == nil {
			t.Error("number accepted", bad)
		}
	}
	if dir, err := cgroupDir("0::/acp-runtime-0123456789abcdef/vm-1\n"); err != nil || dir != "/sys/fs/cgroup/acp-runtime-0123456789abcdef/vm-1" {
		t.Fatal("cgroup directory", dir, err)
	}
	// Only the unified hierarchy, one line, an absolute path without "..".
	for _, bad := range []string{"", "1:cpu:/x\n0::/y\n", "0::relative\n", "0::/a/../../etc\n", "0::/a\n0::/b\n"} {
		if _, err := cgroupDir(bad); err == nil {
			t.Error("cgroup directory accepted", bad)
		}
	}
}

// A VM's CPU ceiling over a window is its share of each period (cpu.max),
// plus one quota for a window that does not start on a period, and a tenth
// for the skew of the readings.
func TestCPUCeilingOfAWindow(t *testing.T) {
	for _, c := range []struct {
		max     string
		elapsed time.Duration
		want    time.Duration
	}{
		{"200000 100000\n", 10 * time.Second, 22220 * time.Millisecond},
		{"100000 100000", time.Second, 1210 * time.Millisecond},
		{"50000 100000", 2 * time.Second, 1155 * time.Millisecond},
	} {
		if got, err := cpuCeiling(c.max, c.elapsed); err != nil || got != c.want {
			t.Error(c.max, c.elapsed, got, err)
		}
	}
	for _, bad := range []string{"max 100000", "0 100000", "100000 0", "100000", "x y", ""} {
		if _, err := cpuCeiling(bad, time.Second); err == nil {
			t.Error("ceiling of", bad)
		}
	}
}

// maxCgroupValue stands for "max", no limit, in a cgroup file of one number.
const maxCgroupValue = math.MaxInt64

// cgroupKeyed parses a cgroup file of "key value" lines, such as cpu.stat,
// memory.events or pids.events.
func cgroupKeyed(text string) (map[string]int64, error) {
	keys := map[string]int64{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("invalid cgroup line %q", line)
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if _, seen := keys[f[0]]; err != nil || n < 0 || seen {
			return nil, fmt.Errorf("invalid cgroup line %q", line)
		}
		keys[f[0]] = n
	}
	return keys, nil
}

// cgroupNumber parses a cgroup file of one number, such as memory.peak or
// pids.current; "max" is maxCgroupValue.
func cgroupNumber(text string) (int64, error) {
	text = strings.TrimSpace(text)
	if text == "max" {
		return maxCgroupValue, nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid cgroup number %q", text)
	}
	return n, nil
}

// cgroupDir is the directory of a process's cgroup, from its
// /proc/<pid>/cgroup on a host with the unified hierarchy only.
func cgroupDir(text string) (string, error) {
	path, ok := strings.CutPrefix(strings.TrimSuffix(text, "\n"), "0::")
	if !ok || strings.Contains(path, "\n") || !strings.HasPrefix(path, "/") || filepath.Clean(path) != path || strings.Contains(path, "..") {
		return "", fmt.Errorf("not a unified cgroup path: %q", text)
	}
	return filepath.Join("/sys/fs/cgroup", path), nil
}

// cpuCeiling is the most CPU time a cgroup whose cpu.max is "quota period"
// may use in elapsed: its share of every period, plus one quota for a window
// that does not start on a period, plus a tenth for the skew of the readings.
func cpuCeiling(cpuMax string, elapsed time.Duration) (time.Duration, error) {
	f := strings.Fields(cpuMax)
	if len(f) != 2 {
		return 0, fmt.Errorf("invalid cpu.max %q", cpuMax)
	}
	quota, err := strconv.ParseInt(f[0], 10, 64)
	period, err2 := strconv.ParseInt(f[1], 10, 64)
	if err != nil || err2 != nil || quota <= 0 || period <= 0 {
		return 0, fmt.Errorf("cpu.max without a ceiling: %q", cpuMax)
	}
	usec := (quota*elapsed.Microseconds()/period + quota) * 11 / 10
	return time.Duration(usec) * time.Microsecond, nil
}
