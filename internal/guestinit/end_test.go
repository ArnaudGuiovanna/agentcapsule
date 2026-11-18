//go:build linux

package guestinit

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"syscall"
	"testing"
)

// A guest ends with a restart, whatever ended its supervisor: its kernel,
// booted with reboot=k, resets the CPU through the keyboard controller, and
// Firecracker exits on that reset, so the worker finds the VMM gone (ADR
// 012, question 6). A power-off would only halt the guest and leave its VMM
// running. The restart comes after the supervisor's own cleanup (its harness
// stopped, its store synchronized, unmounted and closed) and after a sync of
// what is left, since reboot(2) does not write back the page cache.
func TestTheGuestEndsWithARestartAfterItsCleanup(t *testing.T) {
	if EndCommand != syscall.LINUX_REBOOT_CMD_RESTART {
		t.Errorf("the guest ends with reboot(2) command %#x, not a restart (%#x)", EndCommand, syscall.LINUX_REBOOT_CMD_RESTART)
	}
	refused := errors.New("reboot refused")
	for _, c := range []struct {
		name    string
		err     error
		console string
	}{
		{"the harness exited and the store was closed", nil, ""},
		{"the supervisor failed", ErrGuest, "CAPSULE_INIT_FAILED\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var steps []string
			var console bytes.Buffer
			run := func() error {
				steps = append(steps, "harness stopped", "store closed")
				return c.err
			}
			sync := func() { steps = append(steps, "sync") }
			reboot := func(cmd int) error {
				steps = append(steps, fmt.Sprintf("reboot %#x", cmd))
				return refused
			}
			if err := End(run, &console, sync, reboot); !errors.Is(err, refused) {
				t.Fatal("End did not return what reboot(2) returned", err)
			}
			want := []string{"harness stopped", "store closed", "sync", fmt.Sprintf("reboot %#x", syscall.LINUX_REBOOT_CMD_RESTART)}
			if !slices.Equal(steps, want) {
				t.Fatalf("steps %q, want %q", steps, want)
			}
			if console.String() != c.console {
				t.Fatalf("console %q, want %q", console.String(), c.console)
			}
		})
	}
}
