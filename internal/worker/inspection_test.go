//go:build linux

package worker

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// groupOnly is an ID that a group has and no account: as the inspection's
// GID, it would give the program that group's files (6, disk, on Debian).
func groupOnly(t *testing.T) uint32 {
	t.Helper()
	for id := 1; id < 65534; id++ {
		_, group := user.LookupGroupId(strconv.Itoa(id))
		_, account := user.LookupId(strconv.Itoa(id))
		if group == nil && account != nil {
			return uint32(id)
		}
	}
	t.Fatal("no group on this host has an ID that no account has")
	return 0
}

// REG-01: a worker run as root inspects images as registry.inspection_uid,
// which must be reserved: not root, no agent's (outside the provisioning
// range), not the SLIM bridge's, no other account's, and, as the GID of the
// same number, no group's. 65535 and the values from 2^31-1 up are refused:
// setresuid takes -1 (4294967295) as "unchanged", and some interfaces take
// 65535 the same way. A worker that is not root inspects as itself, in a
// user namespace, and ignores it. The preflight says which, and whether
// debugfs runs confined here.
func TestInspectionRunsAsAReservedUID(t *testing.T) {
	c := ServiceConfig{Registry: &ServiceRegistry{}, Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62999},
		SLIM: &ServiceSLIM{BridgeUID: 990}}
	refused := []uint32{0, 62000, 62500, 62999, 990, 65535, 1<<31 - 1, 1 << 31, 4294967294, 4294967295,
		uint32(os.Getuid()), groupOnly(t)}
	for _, uid := range refused {
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
