//go:build linux

package worker

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// REG-01: a worker run as root inspects images as registry.inspection_uid,
// which must be reserved: not root, no agent's (outside the provisioning
// range), not the SLIM bridge's. A worker that is not root inspects as
// itself, in a user namespace, and ignores it. The preflight says which, and
// whether debugfs runs confined here.
func TestInspectionRunsAsAReservedUID(t *testing.T) {
	c := ServiceConfig{Registry: &ServiceRegistry{}, Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62999},
		SLIM: &ServiceSLIM{BridgeUID: 990}}
	for _, uid := range []uint32{0, 62000, 62500, 62999, 990} {
		c.Registry.InspectionUID = uid
		if _, err := c.inspection(true); !errors.Is(err, ErrInspectionUID) {
			t.Errorf("as root, inspection_uid %d was accepted: %v", uid, err)
		}
		if sb, err := c.inspection(false); err != nil || sb != (sandbox.Options{}) {
			t.Errorf("not root, inspection_uid %d gave %+v %v", uid, sb, err)
		}
	}
	c.Registry.InspectionUID = 61999
	if sb, err := c.inspection(true); err != nil || sb.UID != 61999 || sb.GID != 61999 {
		t.Errorf("as root, a reserved inspection_uid gave %+v %v", sb, err)
	}

	c.Registry.InspectionUID = 0
	if r := c.inspectionCheck(t.Context(), true); r.Status != preflight.Fail || !strings.Contains(r.Fix, "inspection_uid") {
		t.Errorf("as root without inspection_uid, the preflight said %+v", r)
	}
	if sandbox.AsRoot() {
		t.Fatal("run as an account other than root")
	}
	if r := c.inspectionCheck(t.Context(), false); r.Status != preflight.OK || !strings.Contains(r.Detail, "user namespace") {
		t.Errorf("not root, the preflight said %+v", r)
	}
}
