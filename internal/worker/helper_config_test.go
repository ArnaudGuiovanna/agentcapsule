//go:build linux

package worker

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
)

// A worker with a helper (ADR 024): the host driver, the inspections and
// the archive fetches go to the helper, and the worker refuses root.
func TestAWorkerWithAHelperDelegatesWhatNeedsRoot(t *testing.T) {
	c, err := decodeServiceConfig(strings.NewReader(`{"version":1,"host_id":"host","boot_timeout":"30s","boot_lease":"2m","poll_interval":"1s",` +
		`"attempt_timeout":"45s","database_max_connections":9,"helper":{"socket":"/run/agentcapsule-worker-helper/worker.sock"},"registry":{"inspection_uid":61999,"rules":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	conns, err := c.DatabaseConnections()
	if err != nil || conns.MaxConns != 9 {
		t.Fatal("database connection limit with helper", conns, err)
	}
	opts, _, _, err := c.Settings()
	if err != nil || opts.Helper == nil || opts.Helper != c.HelperClient() {
		t.Fatal("the host driver does not use the helper", err)
	}
	sb, err := c.inspection(false)
	if err != nil || sb.Delegate == nil || sb.UID != 0 {
		t.Fatal("inspections do not go to the helper", sb, err)
	}
	if err = c.CheckAccount(); (os.Geteuid() == 0) != errors.Is(err, ErrRootWithHelper) {
		t.Fatal(err)
	}
	if err = c.Fetcher("/ignored", t.TempDir())(t.Context(), "ftp", "arc_"+strings.Repeat("0", 32)); !errors.Is(err, controlplane.ErrInput) {
		t.Fatal("a store the shipper does not have was asked", err)
	}
	// The helper does not answer: its preflight check fails, in place of
	// the KVM check the worker cannot make.
	results := c.MandatoryPreflight(t.Context(), preflight.System())
	found := false
	for _, r := range results {
		if r.Check == "kvm" {
			t.Fatal("a worker with a helper checks /dev/kvm itself")
		}
		if r.Check == "worker_helper" {
			found = true
			if r.Status != preflight.Fail {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("no helper check", results)
	}
	// An inspection UID the helper could not use is refused here too.
	c.Registry.InspectionUID = 0
	if _, err = c.inspection(false); !errors.Is(err, ErrInspectionUID) {
		t.Fatal(err)
	}
	c.Helper.Socket = "relative.sock"
	if _, _, _, err = c.Settings(); err == nil {
		t.Fatal("a relative helper socket was accepted")
	}
	// Without a helper, the worker is root and does all itself.
	c.Helper = nil
	if opts, _, _, err = c.Settings(); err != nil || opts.Helper != nil {
		t.Fatal(err)
	}
	if (ServiceConfig{}).HelperClient() != nil || c.CheckAccount() != nil {
		t.Fatal("a worker without a helper has a helper's client, or refuses its account")
	}
	// One client per socket for the process.
	one := ServiceConfig{Helper: &ServiceHelper{Socket: "/run/x.sock"}}
	if one.HelperClient() != one.HelperClient() || one.HelperClient() == (ServiceConfig{Helper: &ServiceHelper{Socket: "/run/y.sock"}}).HelperClient() {
		t.Fatal("helper clients are not one per socket")
	}
}
