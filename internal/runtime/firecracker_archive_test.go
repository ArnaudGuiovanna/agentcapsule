//go:build linux

package runtime

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestArchiveReaderRequiresRetiredRegisteredInode(t *testing.T) {
	h := admissionHost(t)
	path := filepath.Join(h.root, "volumes", "a")
	if err := os.WriteFile(path, []byte("encrypted fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents["a"].Device, r.Agents["a"].Inode = uint64(id.Dev), id.Ino
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	read := func(r io.Reader) error {
		called = true
		b, err := io.ReadAll(r)
		if string(b) != "encrypted fixture" {
			t.Error("wrong inode read")
		}
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = h.WithStoppedVolume(t.Context(), "a", 0, uint64(id.Dev), id.Ino, read); !errors.Is(err, ErrVolumeBusy) || called {
		t.Fatal("live writer copied", err)
	}
	f.Close()
	if err = h.WithStoppedVolume(t.Context(), "a", 0, uint64(id.Dev), id.Ino, read); err != nil || !called {
		t.Fatal("retired volume refused", err)
	}
	called = false
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		run := &VMRun{ID: "0123456789abcdef", Phase: "STARTING", Generation: 1, Incarnation: 1}
		run.Socket = filepath.Join(h.jail(run), "vsock")
		r.Agents["a"].Run, r.Agents["a"].Generation = run, 1
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	if err = h.WithStoppedVolume(t.Context(), "a", 1, uint64(id.Dev), id.Ino, read); !errors.Is(err, ErrVolumeBusy) || called {
		t.Fatal("registered VMM ignored", err)
	}
	if err = h.locked(t.Context(), func(r *hostRegistry) error { r.Agents["a"].Run = nil; return h.save(r) }); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(path, path+".alias"); err != nil {
		t.Fatal(err)
	}
	if err = h.WithStoppedVolume(t.Context(), "a", 1, uint64(id.Dev), id.Ino, read); err == nil || called {
		t.Fatal("aliased inode copied", err)
	}
	if err = os.Remove(path + ".alias"); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = h.WithStoppedVolume(t.Context(), "a", 1, uint64(id.Dev), id.Ino, read); err == nil || called {
		t.Fatal("replacement inode copied", err)
	}
}
