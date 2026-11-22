//go:build linux && cgo

package volumestore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A registered volume belongs to its VM's user: a worker that is not root
// opens it through its helper (ADR 024), only when it may not open it itself,
// and keeps the same checks.
func TestAVolumeThisProcessMayNotOpenGoesToTheOpener(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("root opens every volume itself")
		return
	}
	dir := t.TempDir()
	own, theirs, other := filepath.Join(dir, "own"), filepath.Join(dir, "theirs"), filepath.Join(dir, "other")
	for path, mode := range map[string]os.FileMode{own: 0o600, theirs: 0o200, other: 0o600} {
		if err := os.WriteFile(path, nil, mode); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{root: dir}
	if _, err := s.volume(theirs); !errors.Is(err, os.ErrPermission) {
		t.Fatal("no opener:", err)
	}
	var asked []string
	s.SetVolumeOpener(func(path string) (*os.File, error) {
		asked = append(asked, path)
		return os.OpenFile(other, os.O_RDWR, 0)
	})
	f, err := s.volume(own)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err = s.volume(theirs); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if len(asked) != 1 || asked[0] != theirs {
		t.Fatal("the opener was asked", asked)
	}
	// The opener's file passes the same checks as one opened here.
	if err = os.Chmod(other, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.volume(theirs); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}
