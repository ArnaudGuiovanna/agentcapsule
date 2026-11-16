//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
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
	} {
		if got, err := parseBehaviour(ok.args); err != nil || got != ok.want {
			t.Error(ok.args, got, err)
		}
	}
	for _, bad := range [][]string{{"crash"}, {"crash-at-boot", "now"}, {"flood-volume"}, {"flood-volume", "256"}, {"flood-volume", "3000"},
		{"flood-volume", "16777216"}, {"flood-volume", "x"}, {"fill-tmp"}, {"fill-tmp", "0"}, {"fill-tmp", "4294967296"},
		{"text-only", "now"}} {
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
