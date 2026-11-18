//go:build linux

package guestinit

import (
	"context"
	"errors"
)

// StopHarnessAndCloseStore ends a boot's harness (p, if it started), then
// closes its store (closeStore, if it opened: syncfs, unmounts, dm-crypt).
// The store is closed once the harness's processes are confirmed gone
// (Process.Gone), whatever the harness's exit status: one killed by the
// guest's kernel for taking all its memory, or one that exited with an
// error, still leaves its store closed, and its error is reported with the
// store's. If they cannot be confirmed gone (Stop could not drain its
// cgroup), the store stays as it is: nothing is unmounted under a writer
// that may still live. The guest then ends, after a sync (End).
func StopHarnessAndCloseStore(ctx context.Context, p *Process, closeStore func(context.Context) error) error {
	var stopped error
	if p != nil {
		if stopped = p.Stop(ctx); stopped != nil && !p.Gone() {
			return stopped
		}
	}
	if closeStore == nil {
		return stopped
	}
	return errors.Join(stopped, closeStore(ctx))
}
