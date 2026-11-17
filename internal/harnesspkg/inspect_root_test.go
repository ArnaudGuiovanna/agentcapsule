//go:build linux && root_integration

package harnesspkg

// Run as root: sudo go test -tags root_integration -run AsRoot ./internal/harnesspkg

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// REG-01: as root, as the worker runs, an image staged read-only (0444) in a
// directory only root enters (0700) is inspected by debugfs running as the
// dedicated UID; without a dedicated UID, or unconfined, nothing is
// inspected.
func TestAsRootInspectionRunsAsTheDedicatedAccount(t *testing.T) {
	if !sandbox.AsRoot() {
		t.Fatal("run as root in the initial user namespace (sudo go test -tags root_integration)")
	}
	image, m := packed(t)
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, RootfsFile)
	if err := os.Rename(image, staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o444); err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{UID: 61999, GID: 61999}
	if err := InspectRootfs(t.Context(), staged, m, sb); err != nil {
		t.Fatal("as root, the inspection failed:", err)
	}
	if err := InspectRootfs(t.Context(), staged, m, sandbox.Options{Unconfined: true}); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal("as root, unconfined:", err)
	}
	if err := CheckInspection(t.Context(), sb); err != nil {
		t.Fatal(err)
	}
	if err := InspectRootfs(t.Context(), staged, m, sandbox.Options{}); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal("as root without a dedicated UID:", err)
	}
}
