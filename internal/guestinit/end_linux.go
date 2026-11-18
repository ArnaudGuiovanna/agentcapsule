//go:build linux

package guestinit

import (
	"fmt"
	"io"
	"syscall"
)

// EndCommand is the reboot(2) command that ends a guest, whatever ended its
// supervisor: its harness exited or died, before the guest was ready (a
// failed boot) or after (a crash), or the supervisor itself failed. It
// restarts the guest. The guest's kernel is booted with reboot=k
// (internal/runtime), so it restarts by resetting the CPU through the i8042
// keyboard controller, and Firecracker exits on that reset. The worker then
// finds the VMM gone and counts a failed boot or a crash against the agent's
// restart budget (ADR 012, question 6). A power-off would only halt the
// guest: Firecracker gives its kernel no way to power the VM off, so the VMM
// would keep running, with the agent's VM slot and memory.
//
// A stop the platform asks for (sleep, eviction) does not come here: the
// guest quiesces, stays up to acknowledge it, and the host removes the VMM.
const EndCommand = syscall.LINUX_REBOOT_CMD_RESTART

// End runs the supervisor (run), then ends the guest. run returns only after
// its own cleanup: the harness is stopped and, once its processes are
// confirmed gone, the agent's store is synchronized (syncfs), unmounted and
// closed (dm-crypt) (StopHarnessAndCloseStore). A failed run is reported on
// the console. reboot(2) does not write back what the page cache still
// holds, so End synchronizes every filesystem first; it matters only when
// the store could not be closed. End returns only if reboot fails.
func End(run func() error, console io.Writer, sync func(), reboot func(cmd int) error) error {
	if run() != nil {
		_, _ = fmt.Fprintln(console, "CAPSULE_INIT_FAILED")
	}
	sync()
	return reboot(EndCommand)
}
