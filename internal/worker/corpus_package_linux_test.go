//go:build linux

package worker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// Run the actual debugfs cat under the image-inspection filter. The review
// reader must return the original bytes and must never accept a prefix.
func TestCorpusReviewReadsCompleteFilesWithConfinedDebugfs(t *testing.T) {
	layout := t.TempDir()
	want := []byte("Document index\nCafé\n")
	for _, p := range corpuspkg.RequiredFiles {
		path := filepath.Join(layout, p)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, want, 0644); err != nil {
			t.Fatal(err)
		}
	}
	image := filepath.Join(t.TempDir(), "corpus.ext4")
	if _, err := corpuspkg.BuildImage(t.Context(), layout, image, "11111111-1111-1111-1111-111111111111", 32<<20); err != nil {
		t.Fatal(err)
	}
	debugfs, err := ext4image.Debugfs()
	if err != nil {
		t.Fatal(err)
	}
	var sb sandbox.Options
	if sandbox.AsRoot() {
		sb = sandbox.Options{UID: 61999, GID: 61999}
	}
	got, err := catCorpusFile(t.Context(), sb, debugfs, image, "INDEX.md", len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("complete review", err, len(got))
	}
	if _, err = catCorpusFile(t.Context(), sb, debugfs, image, "INDEX.md", len(want)-1); err == nil {
		t.Fatal("accepted a truncated index")
	}
}
