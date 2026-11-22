//go:build linux

package worker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// model_call_retention keeps finished model calls 90 days by default, 35
// days to 10 years: longer than the month the usage report reads.
func TestModelCallRetentionOfTheConfiguration(t *testing.T) {
	base := ServiceConfig{Version: 1, HostID: "local", Root: filepath.Join(t.TempDir(), "runtime"),
		Authority:    &ServiceAuthority{Socket: "/run/agentcapsule-authority/worker.sock", RestoreAuthorityID: "restoreauth_" + strings.Repeat("a", 32), KeyAuthorityID: "keyauth_" + strings.Repeat("b", 32)},
		Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62009},
		BootTimeout:  "10s", BootLease: "1m", PollInterval: "1s", AttemptTimeout: "20s"}
	retention := func(c ServiceConfig) (time.Duration, error) {
		t.Helper()
		_, _, m, err := c.Settings()
		if err != nil {
			return 0, err
		}
		return m.Dispatch.ModelCallRetention, nil
	}
	if got, err := retention(base); err != nil || got != 90*24*time.Hour {
		t.Fatal("default", got, err)
	}
	for value, want := range map[string]time.Duration{"840h": 35 * 24 * time.Hour, "8760h": 365 * 24 * time.Hour} {
		c := base
		c.ModelCallRetention = value
		if got, err := retention(c); err != nil || got != want {
			t.Fatal(value, got, err)
		}
	}
	for _, value := range []string{"839h", "87601h", "90d", "-1h"} {
		c := base
		c.ModelCallRetention = value
		if got, err := retention(c); err == nil {
			t.Fatal("accepted", value, got)
		}
	}
	o := DispatchOptions{Batch: 1, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Second, RetryMax: time.Second}
	for d, valid := range map[time.Duration]bool{0: true, controlplane.MinModelCallRetention: true, time.Hour: false, controlplane.MaxModelCallRetention + time.Hour: false} {
		o.ModelCallRetention = d
		if o.valid() != valid {
			t.Fatal("dispatch options with model call retention", d)
		}
	}
}
