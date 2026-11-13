//go:build linux

package runtime

import (
	"bytes"
	"crypto/sha256"
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

// A restored image is written into the registered inode in place, only while
// no VMM is registered and no process holds the volume lock, and only when it
// is exactly the expected bytes. The volume keeps its inode.
func TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage(t *testing.T) {
	h := admissionHost(t)
	path := filepath.Join(h.root, "volumes", "a")
	if err := os.WriteFile(path, []byte("current ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := st.Sys().(*syscall.Stat_t)
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents["a"].Device, r.Agents["a"].Inode, r.Agents["a"].Generation = uint64(id.Dev), id.Ino, 4
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	image := []byte("archived cipher")
	image = append(image, make([]byte, len("current ciphertext")-len(image))...)
	digest := sha256.Sum256(image)
	install := func(generation uint64, data []byte, want [32]byte) error {
		return h.InstallVolume(t.Context(), "a", generation, uint64(id.Dev), id.Ino, bytes.NewReader(data), int64(len(image)), want)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = install(4, image, digest); !errors.Is(err, ErrVolumeBusy) {
		t.Fatal("a live writer's volume was overwritten", err)
	}
	f.Close()
	if err = install(3, image, digest); !errors.Is(err, ErrGeneration) {
		t.Fatal("an older generation installed", err)
	}
	if err = install(4, image[:len(image)-1], digest); !errors.Is(err, ErrVolumeImage) {
		t.Fatal("a short image installed", err)
	}
	if err = install(4, append(append([]byte(nil), image...), 'x'), digest); !errors.Is(err, ErrVolumeImage) {
		t.Fatal("a long image installed", err)
	}
	if err = install(4, image, sha256.Sum256([]byte("other"))); !errors.Is(err, ErrVolumeImage) {
		t.Fatal("an image with another digest installed", err)
	}
	if err = install(4, image, digest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, image) {
		t.Fatal("the volume does not hold the image", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(st, after) {
		t.Fatal("the install replaced the volume's inode", err)
	}
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		run := &VMRun{ID: "0123456789abcdef", Phase: "STARTING", Generation: 4, Incarnation: 1}
		run.Socket = filepath.Join(h.jail(run), "vsock")
		r.Agents["a"].Run = run
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	if err = install(4, image, digest); !errors.Is(err, ErrVolumeBusy) {
		t.Fatal("a registered VMM's volume was overwritten", err)
	}
	if err = h.locked(t.Context(), func(r *hostRegistry) error { r.Agents["a"].Run, r.Agents["a"].Fenced = nil, true; return h.save(r) }); err != nil {
		t.Fatal(err)
	}
	if err = install(4, image, digest); !errors.Is(err, ErrHostFenced) {
		t.Fatal("a fenced agent's volume was overwritten", err)
	}
}
