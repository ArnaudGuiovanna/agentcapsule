//go:build linux && cgo

package restoreauthority

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// failingLink answers every exchange with err.
type failingLink struct{ err error }

func (l failingLink) Sync(context.Context, authoritylog.Request) (authoritylog.Position, error) {
	return authoritylog.Position{}, l.err
}

// refused is a dial that the standby's host refused.
var refused = &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

// stallingLink answers a write's exchange nothing until its caller's
// deadline ends, then returns that context's error, as an exchange cut
// before it reached the standby (waiting for the client's connection) does.
// The monitor, whose context has no deadline, finds the standby refused.
type stallingLink struct{ released chan struct{} }

func (l stallingLink) Sync(ctx context.Context, _ authoritylog.Request) (authoritylog.Position, error) {
	if _, ok := ctx.Deadline(); !ok {
		return authoritylog.Position{}, refused
	}
	select {
	case <-ctx.Done():
		return authoritylog.Position{}, ctx.Err()
	case <-l.released:
		return authoritylog.Position{}, errors.New("released")
	}
}

// The kind of the last replication error is the standby's: refused, it is
// unreachable; silent past the request's deadline, a timeout. An exchange
// that its caller's deadline ended before the standby answered anything
// says nothing of the standby, and keeps the last kind: a loaded host whose
// write gave up sooner than its exchange must not turn a dead standby into a
// slow one (TestTwoProcessesOverMutualTLS saw it).
func TestTheLastReplicationErrorIsTheStandbys(t *testing.T) {
	p := replicated(t)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	kind := func() string {
		t.Helper()
		var out strings.Builder
		registry.WriteTo(&out)
		for _, k := range authoritylog.ErrorKinds() {
			if strings.Contains(out.String(), `agentcapsule_authority_replication_last_error{kind="`+k+`"} 1`) {
				return k
			}
		}
		return ""
	}
	write := func(id string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		if err := p.catalog.RecordOutcome(ctx, b, Outcome{ID: id, Digest: digest(id)}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("a write returned without the standby", err)
		}
	}
	p.link.point(failingLink{refused})
	write("refused")
	if k := kind(); k != authoritylog.ErrorUnreachable {
		t.Fatal("a refused standby:", k)
	}
	stalling := stallingLink{make(chan struct{})}
	t.Cleanup(func() { close(stalling.released) })
	p.link.point(stalling)
	write("stalled")
	if k := kind(); k != authoritylog.ErrorUnreachable {
		t.Fatal("an exchange its caller gave up on changed the kind:", k)
	}
	p.link.point(failingLink{&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}})
	write("silent")
	if k := kind(); k != authoritylog.ErrorTimeout {
		t.Fatal("a standby silent past the deadline:", k)
	}
}
