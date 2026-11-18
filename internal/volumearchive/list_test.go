//go:build linux && cgo

package volumearchive

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// List names the published archives of the root, in order, and nothing else:
// not a capture in progress, a removal in progress, or a stray file.
func TestListNamesOnlyPublishedArchives(t *testing.T) {
	s, a, spec := archiveLab(t)
	if got, err := s.List(); err != nil || len(got) != 0 {
		t.Fatal("an empty root lists something", got, err)
	}
	other := spec
	other.ID = "arc_" + strings.Repeat("0", 32)
	for _, sp := range []Spec{spec, other} {
		if _, err := s.Capture(t.Context(), sp, bytes.NewReader(ciphertext), a); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{pendingPrefix + "x", removedPrefix + "y", "arc_" + strings.Repeat("A", 32)} {
		if err := os.Mkdir(filepath.Join(s.root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.root, "arc_"+strings.Repeat("1", 32)), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil || !slices.Equal(got, []string{other.ID, spec.ID}) {
		t.Fatal("list", got, err)
	}
	if err = s.Remove(spec.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = s.List(); err != nil || !slices.Equal(got, []string{other.ID}) {
		t.Fatal("a removed archive is still listed", got, err)
	}
}
