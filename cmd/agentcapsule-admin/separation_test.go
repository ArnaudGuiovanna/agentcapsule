//go:build linux && cgo

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// init-restore-authority runs as the authorities' account and resolves the
// worker's runtime root to keep the authorities outside it. That needs
// search permission on the root's parent: a v0.1.0 worker left
// /var/lib/agentcapsule 0700, and the update's init-restore-authority failed
// with EACCES. Search permission alone is enough: the parent is 0711 now,
// and an update adds o+x (internal/hostops/setup.py, searchable_parent).
// Here the account is this test's, so the owner's bits stand for the
// others' ones.
func TestAuthoritiesResolveARuntimeRootWhoseParentTheyMayOnlyTraverse(t *testing.T) {
	dir := t.TempDir()
	keyRoot, restoreRoot := filepath.Join(dir, "keys"), filepath.Join(dir, "restore")
	keys, err := keyauthority.Initialize(t.Context(), keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "agentcapsule")
	root := filepath.Join(parent, "host")
	for _, d := range []string{restoreRoot, parent, root} {
		if err = os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	check := func() []error {
		return []error{keys.SeparateFrom(root), restoreauthority.CheckSeparation(restoreRoot, root)}
	}
	// Root searches any directory: only the second half applies to it.
	if os.Geteuid() != 0 {
		if err = os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		for _, err := range check() {
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatal("a runtime root under a parent the authorities may not search:", err)
			}
		}
	}
	if err = os.Chmod(parent, 0o100); err != nil {
		t.Fatal(err)
	}
	for _, err := range check() {
		if err != nil {
			t.Fatal("a runtime root under a parent the authorities may traverse:", err)
		}
	}
	// The check stays exact: a root inside an authority is still refused.
	if err = os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if restoreauthority.CheckSeparation(restoreRoot, filepath.Join(restoreRoot, "host")) == nil {
		t.Fatal("a runtime root inside the restore authority")
	}
}
