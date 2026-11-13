//go:build linux && cgo

package volumearchive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func entries(t *testing.T, s *Store) []string {
	t.Helper()
	list, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list))
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

// Manifest tells which agent an archive belongs to without the authority;
// Remove deletes one archive in one step and is idempotent; Sweep deletes
// only what an interrupted capture or removal left behind.
func TestArchiveManifestRemoveAndSweep(t *testing.T) {
	s, a, spec := archiveLab(t)
	other := spec
	other.ID = "arc_" + strings.Repeat("e", 32)
	for _, sp := range []Spec{spec, other} {
		if _, err := s.Capture(t.Context(), sp, bytes.NewReader(ciphertext), a); err != nil {
			t.Fatal(err)
		}
	}
	m, err := s.Manifest(spec.ID)
	if err != nil || m.ID != spec.ID || m.Binding != spec.Binding || m.Size != spec.Size {
		t.Fatal("manifest", m, err)
	}
	if _, err = s.Manifest("arc_" + strings.Repeat("f", 32)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a missing archive is not reported missing", err)
	}
	if _, err = s.Manifest("../" + spec.ID); !errors.Is(err, ErrArchive) {
		t.Fatal("invalid ID accepted", err)
	}

	if err = s.Remove(spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Open(t.Context(), spec.ID, a); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed archive still opens", err)
	}
	if err = s.Remove(spec.ID); err != nil {
		t.Fatal("removing a missing archive failed", err)
	}
	assertArchive(t, s, a, other)
	if got := entries(t, s); !slices.Equal(got, []string{other.ID}) {
		t.Fatal("removal left something behind", got)
	}

	// Leftovers of a crash: an old staging directory, a removal renamed but
	// not deleted. A staging directory written recently is a live capture.
	old, live, removed := filepath.Join(s.root, pendingPrefix+"old"), filepath.Join(s.root, pendingPrefix+"live"), filepath.Join(s.root, removedPrefix+"x")
	for _, dir := range []string{old, live, removed} {
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "volume.luks"), ciphertext, 0600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	for _, path := range []string{filepath.Join(old, "volume.luks"), old} {
		if err = os.Chtimes(path, past, past); err != nil {
			t.Fatal(err)
		}
	}
	// A live capture whose directory is old but whose file is being written.
	if err = os.Chtimes(live, past, past); err != nil {
		t.Fatal(err)
	}
	if err = s.Sweep(time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, s); !slices.Equal(got, []string{pendingPrefix + "live", other.ID}) {
		t.Fatal("sweep", got)
	}
	assertArchive(t, s, a, other)
	if err = s.Sweep(0); !errors.Is(err, ErrArchive) {
		t.Fatal("a sweep of everything accepted", err)
	}
}
