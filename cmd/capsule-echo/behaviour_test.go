//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTestBehaviours(t *testing.T) {
	for _, ok := range []struct {
		args []string
		want behaviour
	}{
		{nil, behaviour{}},
		{[]string{"crash-at-boot"}, behaviour{crashAtBoot: true}},
		{[]string{"flood-volume", "4096"}, behaviour{floodChunk: 4096}},
		{[]string{"flood-volume", "1048576"}, behaviour{floodChunk: 1 << 20}},
		{[]string{"fill-tmp", "104857600"}, behaviour{fillTmp: 100 << 20}},
		{[]string{"text-only"}, behaviour{textOnly: true}},
		{[]string{"burn-cpu"}, behaviour{hostile: "burn-cpu"}},
		{[]string{"eat-memory"}, behaviour{hostile: "eat-memory"}},
		{[]string{"fork-bomb"}, behaviour{hostile: "fork-bomb"}},
		{[]string{"never-files"}, behaviour{neverFiles: true}},
	} {
		if got, err := parseBehaviour(ok.args); err != nil || got != ok.want {
			t.Error(ok.args, got, err)
		}
	}
	// A direct write is a whole number of 4 KiB pages.
	for _, bad := range [][]string{{"crash"}, {"crash-at-boot", "now"}, {"flood-volume"}, {"flood-volume", "256"}, {"flood-volume", "3000"},
		{"flood-volume", "512"}, {"flood-volume", "2048"},
		{"flood-volume", "16777216"}, {"flood-volume", "x"}, {"fill-tmp"}, {"fill-tmp", "0"}, {"fill-tmp", "4294967296"},
		{"text-only", "now"}, {"burn-cpu", "2"}, {"eat-memory", "1048576"}, {"fork-bomb", "256"}, {"never-files", "now"},
		{"burn"}, {"hostile"}} {
		if _, err := parseBehaviour(bad); err == nil {
			t.Error("accepted", bad)
		}
	}
}

// The flood rewrites one bounded region until it is stopped.
func TestFloodStaysWithinItsSpan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flood")
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := flood(ctx, path, 1<<20); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 || st.Size() > floodSpan {
		t.Fatal("flood file", st, err)
	}
}

// The flood writes past the guest's page cache (ADR 012): its file is open
// with O_DIRECT, so that each write reaches the drive as one request of its
// size and no flush is needed, and its span is allocated before the first
// write, so that no write allocates.
func TestFloodWritesDirectlyToTheDrive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flood")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- flood(ctx, path, 4096) }()
	flags := -1
	for deadline := time.Now().Add(10 * time.Second); flags < 0; {
		select {
		case err := <-done:
			t.Fatal("the flood stopped", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the flood did not open its file")
		}
		flags = openFlags(t, path)
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if flags&syscall.O_DIRECT == 0 {
		t.Fatalf("the flood writes through the page cache: flags %o", flags)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() != floodSpan {
		t.Fatal("flood span not allocated before the writes", st, err)
	}
}

// openFlags returns the flags of this process's open descriptor of path, or
// -1 if it has none.
func openFlags(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err != nil || target != path {
			continue
		}
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", e.Name()))
		if err != nil {
			continue // closed meanwhile
		}
		for _, line := range strings.Split(string(info), "\n") {
			if value, ok := strings.CutPrefix(line, "flags:"); ok {
				flags, err := strconv.ParseInt(strings.TrimSpace(value), 8, 64)
				if err != nil {
					t.Fatal(line, err)
				}
				return int(flags)
			}
		}
	}
	return -1
}

// A fill that the size of its filesystem does not stop fails the boot: the
// guest's tmpfs is not bounded as it should be. Nothing is left behind.
func TestFillTmpFailsWhenNothingStopsIt(t *testing.T) {
	dir := t.TempDir()
	if err := fillTmp(dir, 1<<20); err != errTmpUnbounded {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("fill file left behind", entries, err)
	}
}
