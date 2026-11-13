//go:build linux

package worker

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
)

// Why work waits, as metrics and events report it. A pass joins the errors of
// its jobs: an organization's wake budget is named first.
func TestRetryReasons(t *testing.T) {
	away := &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}
	for want, err := range map[string]error{
		"wake_budget":      fmt.Errorf("deliver: %w", controlplane.ErrWakeBudget),
		"slim_unavailable": errors.Join(away),
		"capacity":         fmt.Errorf("start: %w", runtime.ErrCapacity),
		"error":            errors.New("database unavailable"),
	} {
		if got := RetryReason(err); got != want {
			t.Error(want, got)
		}
	}
	if got := RetryReason(&slimlink.BridgeError{Status: 503, Code: slimlink.CodeUnavailable}); got != "slim_unavailable" {
		t.Error("a bridge's refusal", got)
	}
	if got := RetryReason(errors.Join(errors.New("other"), controlplane.ErrWakeBudget)); got != "wake_budget" {
		t.Error("joined", got)
	}
	if got := RetryReason(&net.OpError{Op: "dial", Net: "vsock", Err: syscall.ECONNREFUSED}); got != "error" {
		t.Error("a VM's control channel is not SLIM", got)
	}
}
