//go:build linux

package worker

import (
	"strings"
	"testing"
)

// dispatch_concurrency bounds the jobs a pass runs at once: 4 by default, 1
// to MaxDispatchConcurrency; vm_serial_console is off unless set (S-02, S-20).
func TestDispatchConcurrencyAndSerialConsoleConfiguration(t *testing.T) {
	c := ServiceConfig{Version: 1, HostID: "host", BootTimeout: "30s", BootLease: "2m", PollInterval: "1s", AttemptTimeout: "45s"}
	opts, _, m, err := c.Settings()
	if err != nil || m.Dispatch.Concurrency != DefaultDispatchConcurrency || opts.SerialConsole {
		t.Fatal("defaults", m.Dispatch, opts.SerialConsole, err)
	}
	c.DispatchConcurrency, c.VMSerialConsole = 16, true
	if opts, _, m, err = c.Settings(); err != nil || m.Dispatch.Concurrency != 16 || !opts.SerialConsole {
		t.Fatal("configured", m.Dispatch, opts.SerialConsole, err)
	}
	for _, bad := range []int{-1, MaxDispatchConcurrency + 1} {
		c.DispatchConcurrency = bad
		if _, _, _, err = c.Settings(); err == nil {
			t.Fatal("accepted dispatch_concurrency", bad)
		}
	}
	if _, err = decodeServiceConfig(strings.NewReader(`{"dispatch_concurrency":2,"vm_serial_console":true}`)); err != nil {
		t.Fatal(err)
	}
}
