//go:build linux && cgo

package authorityservice

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// One process at a time holds an authority directory's lock; a missing
// directory has no lock to hold, and is not created.
func TestOwnerLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	keys, restore, missing := filepath.Join(dir, "keys"), filepath.Join(dir, "restore"), filepath.Join(dir, "missing")
	for _, d := range []string{keys, restore} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	owner, err := Own(keys, restore, missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Own created a directory", err)
	}
	for _, d := range []string{keys, restore} {
		// flock locks belong to an open file: a second open in this
		// process stands for a second process.
		if _, err = Own(d); !errors.Is(err, ErrInUse) {
			t.Fatal("a second owner of", d, err)
		}
	}
	// A refused Own releases what it took first.
	free := filepath.Join(dir, "free")
	if err = os.Mkdir(free, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = Own(missing, free, restore); !errors.Is(err, ErrInUse) {
		t.Fatal(err)
	}
	taken, err := Own(free)
	if err != nil {
		t.Fatal("a refused Own kept a lock", err)
	}
	taken.Release()
	owner.Release()
	again, err := Own(keys, restore)
	if err != nil {
		t.Fatal("a released directory is still owned", err)
	}
	again.Release()
	// The lock file is never a link to another file.
	other := filepath.Join(dir, "elsewhere")
	if err = os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dir, "target"), filepath.Join(other, OwnerLock)); err != nil {
		t.Fatal(err)
	}
	if _, err = Own(other); err == nil || errors.Is(err, ErrInUse) {
		t.Fatal("a symbolic link taken as the lock", err)
	}
	if _, err = os.Lstat(filepath.Join(dir, "target")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the link's target was created", err)
	}
}

// Listen replaces a leftover socket, never another file.
func TestListenReplacesOnlyASocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "acs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "worker.sock")
	l, err := Listen(path, 0600)
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close() // a crash leaves the socket
	if l, err = Listen(path, 0600); err != nil {
		t.Fatal("a leftover socket was not replaced", err)
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0600 || st.Mode()&os.ModeSocket == 0 {
		t.Fatal(st, err)
	}
	l.Close()
	if err = os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Listen(path, 0600); err == nil {
		t.Fatal("a file was replaced by the socket")
	}
}
