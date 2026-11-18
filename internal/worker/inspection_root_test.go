//go:build linux && root_integration

package worker

// Run as root: sudo go test -tags root_integration -run AsRoot ./internal/worker

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// REG-01: a worker run as root opens its importer only with a reserved
// inspection_uid, once debugfs ran confined as it; its preflight says so.
func TestAsRootTheImporterNeedsAnInspectionUID(t *testing.T) {
	if !sandbox.AsRoot() {
		t.Fatal("run as root in the initial user namespace (sudo go test -tags root_integration)")
	}
	c := ServiceConfig{Root: t.TempDir(), Registry: &ServiceRegistry{Rules: []RegistryRule{{Rule: ociregistry.Rule{Host: "ghcr.io", Repositories: []string{"acme/"}}}}},
		Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62999}}
	if _, err := c.OpenRegistry(nil, "w"); !errors.Is(err, ErrInspectionUID) {
		t.Fatal("as root without inspection_uid:", err)
	}
	if r := c.inspectionCheck(t.Context(), true); r.Status != preflight.Fail {
		t.Error("the preflight without inspection_uid:", r)
	}
	// nobody's UID, and -1, which setresuid takes as "unchanged".
	for _, uid := range []uint32{65534, 4294967295} {
		c.Registry.InspectionUID = uid
		if _, err := c.OpenRegistry(nil, "w"); !errors.Is(err, ErrInspectionUID) {
			t.Error("as root with inspection_uid", uid, err)
		}
		if r := c.inspectionCheck(t.Context(), true); r.Status != preflight.Fail {
			t.Error("the preflight with inspection_uid", uid, r)
		}
	}
	c.Registry.InspectionUID = 61999
	// Past the inspection's checks, a missing store is the next refusal.
	if _, err := c.OpenRegistry(nil, "w"); !errors.Is(err, controlplane.ErrInput) {
		t.Fatal("as root with inspection_uid:", err)
	}
	if r := c.inspectionCheck(t.Context(), true); r.Status != preflight.OK || !strings.Contains(r.Detail, "61999") {
		t.Error("the preflight with inspection_uid:", r)
	}
}
