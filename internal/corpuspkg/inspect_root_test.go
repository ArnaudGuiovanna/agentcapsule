//go:build linux && root_integration

package corpuspkg

// Run as root: sudo go test -tags root_integration -run AsRoot ./internal/corpuspkg

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// P-12: as root, as the worker runs, a corpus image staged read-only in a
// directory only root enters is inspected by debugfs reading its batched
// commands on its standard input, as the dedicated UID; without a dedicated
// UID nothing is inspected.
func TestAsRootCorpusInspectionRunsAsTheDedicatedAccount(t *testing.T) {
	if !sandbox.AsRoot() {
		t.Fatal("run as root in the initial user namespace (sudo go test -tags root_integration)")
	}
	image, _ := built(t)
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, ImageFile)
	if err := os.Rename(image, staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := InspectImage(t.Context(), staged, sandbox.Options{UID: 61999, GID: 61999}); err != nil {
		t.Fatal("as root, the inspection failed:", err)
	}
	if err := InspectImage(t.Context(), staged, sandbox.Options{}); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal("as root without a dedicated UID:", err)
	}
}
