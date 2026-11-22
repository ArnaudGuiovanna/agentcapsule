//go:build linux && cgo && root_integration

package volumestore

// Run as root: sudo go test -tags root_integration -run AsRoot ./internal/volumestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore/lukstest"
)

// S-21: as root, as the worker runs a restore test, the key check reads a
// copy that only root may read (0600, in a directory only root enters) as
// the dedicated UID, confined: the volume's key opens it, another key and a
// header the guest rewrote do not, and the copy keeps its bytes. Without a
// dedicated UID, or unconfined, nothing is checked.
func TestAsRootTheKeyCheckRunsAsTheInspectionAccount(t *testing.T) {
	if !sandbox.AsRoot() {
		t.Fatal("run as root in the initial user namespace (sudo go test -tags root_integration)")
	}
	scratch, spec, key := scratchCopy(t)
	if err := os.Chmod(filepath.Dir(scratch), 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(scratch)
	if err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{UID: 61999, GID: 61999}
	if err = CheckContainer(t.Context(), sb, scratch, spec.VolumeID, key); err != nil {
		t.Fatal("the volume's key, as the dedicated account:", err)
	}
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if err = CheckContainer(t.Context(), sb, scratch, spec.VolumeID, wrong); !errors.Is(err, ErrLUKS) || errors.Is(err, ErrHeader) {
		t.Fatal("another key:", err)
	}
	for _, o := range []sandbox.Options{{}, {Unconfined: true}} {
		if err = CheckContainer(t.Context(), o, scratch, spec.VolumeID, key); !errors.Is(err, sandbox.ErrUnavailable) {
			t.Errorf("as root with %+v: %v", o, err)
		}
	}
	if after, err := os.ReadFile(scratch); err != nil || !bytes.Equal(after, before) {
		t.Fatal("the check changed the copy", err)
	}
	if err = lukstest.RewriteMetadata(scratch, func(m map[string]any) {
		lukstest.Object(m, "keyslots", "0", "kdf")["memory"] = json.Number("1048576")
	}); err != nil {
		t.Fatal(err)
	}
	if err = CheckContainer(t.Context(), sb, scratch, spec.VolumeID, key); !errors.Is(err, ErrHeader) {
		t.Fatal("a header the guest rewrote:", err)
	}
}
