//go:build linux && cgo

package guestinit

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestFilesystemSyncReportsKernelErrors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sync-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write([]byte("durable")); err != nil {
		t.Fatal(err)
	}
	if err = syncFilesystem(f); err != nil {
		t.Fatal("valid filesystem sync", err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = syncFilesystem(f); !errors.Is(err, syscall.EBADF) {
		t.Fatal("kernel sync failure lost", err)
	}
}
