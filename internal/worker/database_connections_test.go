//go:build linux

package worker

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// database_max_connections sizes the worker's pool, 16 when absent, 1 to
// 1000; its statements, lock waits and idle transactions keep the worker's
// bounds (P-08).
func TestWorkerDatabaseConnections(t *testing.T) {
	base := ServiceConfig{Version: 1, HostID: "local", Root: filepath.Join(t.TempDir(), "runtime"),
		Authority:    &ServiceAuthority{Socket: "/run/agentcapsule-authority/worker.sock", RestoreAuthorityID: "restoreauth_" + strings.Repeat("a", 32), KeyAuthorityID: "keyauth_" + strings.Repeat("b", 32)},
		Provisioning: &ProvisioningConfig{FirstUID: 62000, LastUID: 62009},
		BootTimeout:  "10s", BootLease: "1m", PollInterval: "1s", AttemptTimeout: "20s"}
	if c, err := base.DatabaseConnections(); err != nil || c != controlplane.WorkerConnections || c.MaxConns != 16 {
		t.Fatal("default", c, err)
	}
	sized := base
	sized.DatabaseMaxConnections = 40
	c, err := sized.DatabaseConnections()
	if err != nil || c.MaxConns != 40 || c.LockTimeout != controlplane.WorkerConnections.LockTimeout {
		t.Fatal("sized", c, err)
	}
	for _, n := range []int32{-1, 1001} {
		bad := base
		bad.DatabaseMaxConnections = n
		if _, err := bad.DatabaseConnections(); err == nil {
			t.Fatal("accepted", n)
		}
		if _, _, _, err := bad.Settings(); err == nil {
			t.Fatal("settings accepted", n)
		}
	}
	decoded, err := decodeServiceConfig(strings.NewReader(`{"version":1,"database_max_connections":8}`))
	if err != nil || decoded.DatabaseMaxConnections != 8 {
		t.Fatal(decoded.DatabaseMaxConnections, err)
	}
}
