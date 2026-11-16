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
	} {
		if got, err := parseBehaviour(ok.args); err != nil || got != ok.want {
			t.Error(ok.args, got, err)
		}
	}
	for _, bad := range [][]string{{"crash"}, {"crash-at-boot", "now"}, {"flood-volume"}, {"flood-volume", "256"}, {"flood-volume", "3000"},
		{"flood-volume", "16777216"}, {"flood-volume", "x"}} {
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
