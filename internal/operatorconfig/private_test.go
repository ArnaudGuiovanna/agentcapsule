//go:build linux

package operatorconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateFilePermissionsSymlinkAndReplay(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "key")
	first := bytes.Repeat([]byte{7}, 32)
	got, err := EnsurePrivate(path, 32, func() []byte { return first })
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("create", err)
	}
	got, err = EnsurePrivate(path, 32, func() []byte { t.Fatal("existing key replaced"); return nil })
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("read", err)
	}
	link := filepath.Join(d, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(link, 32); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(path, 32); err == nil {
		t.Fatal("publicly readable secret accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(path, 31); err == nil {
		t.Fatal("wrong size accepted")
	}
	fifo := filepath.Join(d, "fifo")
	if err = syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(fifo, 32); err == nil {
		t.Fatal("FIFO accepted")
	}
}
