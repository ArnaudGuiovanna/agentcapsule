//go:build unix

package harnesspkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageTreeRetainsOnlySourceHardlinks(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	original := filepath.Join(src, "tool")
	for _, file := range []string{original, filepath.Join(src, "other")} {
		if err := os.WriteFile(file, []byte("same bytes"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(original, filepath.Join(src, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := stageTree(src, dst); err != nil {
		t.Fatal(err)
	}
	stat := func(path string) os.FileInfo {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	tool := stat(filepath.Join(dst, "tool"))
	if !os.SameFile(tool, stat(filepath.Join(dst, "alias"))) ||
		os.SameFile(tool, stat(original)) || os.SameFile(tool, stat(filepath.Join(dst, "other"))) {
		t.Fatal("expected only the two aliases inside staging to share their inode")
	}
	if tool.Mode().Perm() != stat(original).Mode().Perm() || tool.ModTime().Unix() != 1 {
		t.Fatal("staged executable lost its mode or normalized timestamp")
	}
}
