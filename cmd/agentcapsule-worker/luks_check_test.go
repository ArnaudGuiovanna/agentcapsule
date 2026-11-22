//go:build linux && cgo

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

// S-21: a restore test checks the key of an archive's copy confined, as a
// program of the worker's own executable, under the self filter: every
// package the worker links starts there before the check runs. This binary
// links them all, so a package whose start makes a call outside the
// allow-list fails here, not on a host. The check opens the copy with its
// key and refuses another key.
func TestTheWorkerExecutableChecksAContainerConfined(t *testing.T) {
	volumes, err := volumestore.New(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	spec := volumestore.Spec{AgentID: "agt_" + strings.Repeat("a", 32), VolumeID: "vol_" + strings.Repeat("b", 32), SizeMiB: 64}
	c, err := volumes.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(t.TempDir(), "copy.luks")
	if err = os.WriteFile(scratch, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = volumestore.CheckContainer(t.Context(), sandbox.Options{}, scratch, spec.VolumeID, key); err != nil {
		t.Fatal("the volume's key, checked by the worker's executable:", err)
	}
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if err = volumestore.CheckContainer(t.Context(), sandbox.Options{}, scratch, spec.VolumeID, wrong); !errors.Is(err, volumestore.ErrLUKS) {
		t.Fatal("another key:", err)
	}
}
