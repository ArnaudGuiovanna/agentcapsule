//go:build linux

// Package keymemtest checks, in tests, where key bytes live.
package keymemtest

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// Flags returns the VmFlags of the mapping of this process that holds b's
// first byte, from /proc/self/smaps, between spaces, or "" when none does.
// A buffer of package keymem in use has " lo " (locked) and " dd " (left
// out of core dumps); the Go heap has neither.
func Flags(t testing.TB, b []byte) string {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("no byte to look up")
	}
	return FlagsAt(t, uintptr(unsafe.Pointer(&b[0])))
}

// FlagsAt is Flags for an address kept after its buffer was released.
func FlagsAt(t testing.TB, addr uintptr) string {
	t.Helper()
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	inside := false
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		line := lines.Text()
		if fields := strings.Fields(line); len(fields) > 1 && strings.Contains(fields[0], "-") && !strings.HasSuffix(fields[0], ":") {
			start, end, _ := strings.Cut(fields[0], "-")
			a, err1 := strconv.ParseUint(start, 16, 64)
			b, err2 := strconv.ParseUint(end, 16, 64)
			inside = err1 == nil && err2 == nil && uint64(addr) >= a && uint64(addr) < b
			continue
		}
		if flags, ok := strings.CutPrefix(line, "VmFlags:"); ok && inside {
			return " " + strings.TrimSpace(flags) + " "
		}
	}
	return ""
}

// Locked reports whether b lies in a locked page left out of core dumps.
func Locked(t testing.TB, b []byte) bool {
	t.Helper()
	flags := Flags(t, b)
	return strings.Contains(flags, " lo ") && strings.Contains(flags, " dd ")
}

// Zero reports whether every byte of b is zero.
func Zero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
