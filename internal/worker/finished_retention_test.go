//go:build linux

package worker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// finished_retention keeps finished records 90 days by default, 45 days to
// 10 years, and two weeks past the oldest archive the host keeps: a restore
// from it still finds every event it lost (P-04).
func TestFinishedRetentionOutlivesTheArchives(t *testing.T) {
	parent := t.TempDir()
	base := ServiceConfig{Version: 1, HostID: "local", Root: filepath.Join(parent, "runtime"),
		Authority:    &ServiceAuthority{Socket: "/run/agentcapsule-authority/worker.sock", RestoreAuthorityID: "restoreauth_" + strings.Repeat("a", 32), KeyAuthorityID: "keyauth_" + strings.Repeat("b", 32)},
		Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62009},
		BootTimeout:  "10s", BootLease: "1m", PollInterval: "1s", AttemptTimeout: "20s"}
	retention := func(c ServiceConfig) (time.Duration, error) {
		t.Helper()
		_, _, m, err := c.Settings()
		if err != nil {
			return 0, err
		}
		return m.Dispatch.Retention, nil
	}
	if got, err := retention(base); err != nil || got != 90*24*time.Hour {
		t.Fatal("default", got, err)
	}
	for value, want := range map[string]time.Duration{"1080h": 45 * 24 * time.Hour, "8760h": 365 * 24 * time.Hour} {
		c := base
		c.FinishedRetention = value
		if got, err := retention(c); err != nil || got != want {
			t.Fatal(value, got, err)
		}
	}
	for _, value := range []string{"1079h", "87601h", "90d", "-1h"} {
		c := base
		c.FinishedRetention = value
		if got, err := retention(c); err == nil {
			t.Fatal("accepted", value, got)
		}
	}
	// 30 archives a week apart reach back 210 days.
	c := base
	c.Archives = &ServiceArchives{Root: filepath.Join(parent, "archives"), Every: "168h", Keep: 30}
	if _, err := retention(c); err == nil {
		t.Fatal("a retention shorter than the archives' horizon was accepted")
	}
	c.FinishedRetention = "5400h" // 225 days
	if got, err := retention(c); err != nil || got != 225*24*time.Hour {
		t.Fatal("a retention past the archives' horizon", got, err)
	}
	// A pass accepts the default (zero) and the configured bounds only.
	o := DispatchOptions{Batch: 1, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Second, RetryMax: time.Second}
	for retention, valid := range map[time.Duration]bool{0: true, controlplane.MinFinishedRetention: true, time.Hour: false, controlplane.MaxFinishedRetention + time.Hour: false} {
		o.Retention = retention
		if o.valid() != valid {
			t.Fatal("dispatch options with retention", retention)
		}
	}
}
