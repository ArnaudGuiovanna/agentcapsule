//go:build linux && cgo

package restoreauthority

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// giveUpDuringCommit commits an outcome whose caller's deadline ends during
// the commit, while another exchange holds the link (the monitor or the
// heartbeat reading the log's tail): its wait for the standby ends before it
// tries the standby once.
func giveUpDuringCommit(t *testing.T, p *pair, b Binding, id string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := p.catalog.repl
	held := false
	p.catalog.hook = func(boundary string) {
		if boundary == "after_commit" {
			r.lock <- struct{}{}
			held = true
			cancel()
		}
	}
	err := p.catalog.RecordOutcome(ctx, b, Outcome{ID: id, Digest: digest(id)})
	p.catalog.hook = nil
	if held {
		<-r.lock
	}
	if !held || !errors.Is(err, ErrUnavailable) {
		t.Fatal("the write did not give up after its commit", held, err)
	}
}

// A write whose caller gives up during its commit counts as a failed
// exchange (ADR 006, "Changes after the v0.1.0 audit", FIX-1): the degraded
// delay starts, and the monitor keeps reaching the standby. Before, the wait
// could return on the caller's deadline without one exchange: nothing was
// recorded, the delay never started, and the committed record stayed on the
// primary until another write.
func TestAWriteGivenUpDuringItsCommitStartsTheDegradedDelay(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	p.link.set(true)
	giveUpDuringCommit(t, p, b, "event-given-up")
	k.advance(authoritylog.DefaultDegradedAfter)
	eventually(t, "degraded mode", func() bool { return isDegraded(p.catalog) })
}

// The give-up says nothing of the standby, which the write never tried: the
// last error kind stays the standby's (TestTheLastReplicationErrorIsTheStandbys).
func TestARecordGivenUpDuringItsCommitReachesTheStandby(t *testing.T) {
	p := replicated(t)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	none := `agentcapsule_authority_replication_last_error{kind="` + authoritylog.ErrorNone + `"} 1`
	if !strings.Contains(scrape(registry), none) {
		t.Fatal("no successful exchange before the write")
	}
	giveUpDuringCommit(t, p, b, "event-given-up")
	last := committed(t, p.catalog)
	eventually(t, "the standby holds the record", func() bool { return applied(t, p) == last })
	if !strings.Contains(scrape(registry), none) {
		t.Fatal("a give-up before any exchange changed the last error kind")
	}
}
