//go:build linux && cgo

package authorityclient

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The link to the standby, its monitor, degraded mode and the barrier run in
// the service: clients see degraded mode through status and through the
// errors of the writes that wait (ErrWaitsForReplica), and its metrics are
// the service's.
func TestServiceRunsDegradedMode(t *testing.T) {
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = catalog.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	link := &tap{target: replica}
	if err = svc.LinkTo(t.Context(), catalog, keys, link, authoritylog.MinDegradedAfter); err != nil {
		t.Fatal(err)
	}
	l := serve(t, keys, catalog)
	catalog.ObserveReplication(authoritylog.NewMetrics(l.registry))
	c := l.client(t)
	ctx := t.Context()
	b, _ := fenced(t, c, "store-a", "volume-a")
	link.set(true)
	if err = c.RecordOutcome(within(t, 500*time.Millisecond), b, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")}); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a write returned without the replica, before degraded mode", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, err := c.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status.Mode == restoreauthority.ModeDegraded && status.DegradedSince > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no degraded mode", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = c.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal("an outcome waited in degraded mode", err)
	}
	if _, err = c.ReserveIncarnation(within(t, 500*time.Millisecond), b, "restore"); !errors.Is(err, restoreauthority.ErrWaitsForReplica) ||
		!errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a reservation ran in degraded mode", err)
	}
	metrics := l.scrape(t)
	for _, line := range []string{`agentcapsule_authority_replication_enabled 1`,
		`agentcapsule_authority_replication_degraded_refused_total{kind="reservation"} 1`} {
		if !strings.Contains(metrics, line) {
			t.Fatal("missing", line)
		}
	}
	// The standby returns: the degraded write reaches it, degraded mode
	// ends, and the reservation runs.
	link.set(false)
	if _, err = c.ReserveIncarnation(ctx, b, "restore"); err != nil {
		t.Fatal(err)
	}
	if status, err := c.Status(ctx); err != nil || status.Mode != restoreauthority.ModeSynchronous || status.DegradedSince != 0 {
		t.Fatal(status, err)
	}
}
