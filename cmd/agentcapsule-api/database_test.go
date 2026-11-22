//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// -database-max-connections sizes the API's pool: 1 to 1000, 32 when absent
// (P-08). A value out of range stops the API before anything else.
func TestDatabaseMaxConnectionsFlag(t *testing.T) {
	for _, value := range []string{"0", "1001", "-3", "many"} {
		if _, code := command(t, "-database-max-connections", value); code != 2 {
			t.Errorf("%s: exit %d", value, code)
		}
	}
	// A valid value goes on to the next check: the missing configuration.
	if out, code := command(t, "-database-max-connections", "8"); code != 1 || !strings.HasSuffix(out, "configuration_required\n") {
		t.Errorf("8: %d %q", code, out)
	}
	var n int32
	if parseConnections("1000", &n) != nil || n != 1000 || controlplane.APIConnections.MaxConns != 32 {
		t.Error(n, controlplane.APIConnections.MaxConns)
	}
}
