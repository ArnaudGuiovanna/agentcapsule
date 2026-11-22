//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

// The host's locks on real VMs (S-02, S-03, P-09, S-20): what one agent does
// for long never makes another agent wait. Each test bounds the other agent's
// work well under what the long operation takes.

const otherAgentBound = 3 * time.Second

func echo(t *testing.T, w *Placements, ctx context.Context, target, id string) {
	t.Helper()
	if _, err := w.Send(ctx, target, harnessstore.Event{ID: id, Subjects: []string{"agent/" + target, "event/" + id}, Body: []byte("local")}); err != nil {
		t.Fatal(target, id, err)
	}
}

// A delivery holds its recipient's exclusive turn through its guest RPC: a
// delivery to a, whose guest answered and whose turn the callback then keeps
// for long, as a slow harness would, does not delay a delivery to b.
func TestKVMSlowDeliveryDoesNotDelayAnotherAgent(t *testing.T) {
	w, _, _, options := lab(t, true)
	t.Cleanup(w.Close)
	provisionAgent(t, w, options.Root, "b", 61302)
	t.Cleanup(func() { retireLab(t, w, "b") })
	for _, id := range []string{"a", "b"} {
		if _, err := w.Start(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	slow, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- w.WithPreparedDelivery(ctx, "a", func(ctx context.Context) error {
			echo(t, w, ctx, "a", "slow-delivery")
			close(slow)
			select {
			case <-release:
				return nil
			case <-time.After(15 * time.Second):
				return fmt.Errorf("the other agent's delivery did not end")
			}
		})
	}()
	<-slow
	started := time.Now()
	if err := w.WithPreparedDelivery(ctx, "b", func(ctx context.Context) error {
		echo(t, w, ctx, "b", "fast-delivery")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > otherAgentBound {
		t.Fatalf("the delivery to b waited %s behind a's", took)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A long boot of b, held at its SQL confirmation, holds b's lock only: a's
// guest calls the platform, and its delivery and its control session run,
// meanwhile (S-03; the accept check reads the registry without host.lock).
func TestKVMLongBootDoesNotFailAnotherAgentsPlatformCalls(t *testing.T) {
	w, db, schema, options := lab(t, true)
	t.Cleanup(w.Close)
	provisionAgent(t, w, options.Root, "b", 61312)
	t.Cleanup(func() { retireLab(t, w, "b") })
	if _, err := w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// b's boot claims its placement, then waits at its confirmation, which
	// this transaction's row lock holds.
	gate, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(context.Background())
	var armed atomic.Bool
	held := make(chan error, 1)
	w.afterClaim = func() {
		if armed.CompareAndSwap(true, false) {
			_, err := gate.Exec(ctx, "SELECT agent_id FROM "+pgx.Identifier{schema, "agent_placements"}.Sanitize()+" WHERE agent_id='b' FOR UPDATE")
			held <- err
		}
	}
	armed.Store(true)
	booted := make(chan error, 1)
	go func() { _, err := w.Start(ctx, "b"); booted <- err }()
	if err = <-held; err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%agent_placements%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting
	})
	started := time.Now()
	result := platformJob(t, w, "a", "during-a-long-boot", map[string]string{"fixture_op": "platform_health"})
	if result.Code != "" || !result.Done {
		t.Fatalf("a's platform call failed during b's boot: %+v", result)
	}
	if took := time.Since(started); took > otherAgentBound {
		t.Fatalf("a's platform call waited %s for b's boot", took)
	}
	if err = gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-booted; err != nil {
		t.Fatal(err)
	}
}

// A volume copy of b (an archive, a restore) holds b's volume only: a's
// deliveries and the census run meanwhile (S-03).
func TestKVMVolumeCopyDoesNotBlockAnotherAgent(t *testing.T) {
	w, _, _, options := lab(t, true)
	t.Cleanup(w.Close)
	provisionAgent(t, w, options.Root, "b", 61322)
	t.Cleanup(func() { retireLab(t, w, "b") })
	if _, err := w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(options.Root, "volumes", "b.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	s := st.Sys().(*syscall.Stat_t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	copying, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- w.host.WithStoppedVolume(ctx, "b", 0, uint64(s.Dev), s.Ino, func(r io.Reader) error {
			close(copying)
			<-release
			_, err := io.Copy(io.Discard, r)
			return err
		})
	}()
	<-copying
	started := time.Now()
	echo(t, w, ctx, "a", "during-a-copy")
	if _, err = w.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > otherAgentBound {
		t.Fatalf("a waited %s for b's volume copy", took)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

// Deliveries and platform calls to a running VM that changes nothing do not
// write the host registry (P-09).
func TestKVMUsingARunningVMDoesNotRewriteTheRegistry(t *testing.T) {
	w, _, _, options := lab(t, true)
	t.Cleanup(w.Close)
	if _, err := w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(options.Root, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		echo(t, w, t.Context(), "a", fmt.Sprintf("unchanged-%d", i))
	}
	if result := platformJob(t, w, "a", "unchanged-platform", map[string]string{"fixture_op": "platform_health"}); result.Code != "" {
		t.Fatal(result)
	}
	if _, err = w.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(options.Root, "registry.json"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("the registry was rewritten while nothing changed", err)
	}
}

// In production the guest has no serial console; the VMM's log is cut at its
// limit while the VM runs, and goes with the run (S-20).
func TestKVMVMMLogIsBoundedAndGoesWithItsRun(t *testing.T) {
	w, _, _, options := lab(t, true)
	t.Cleanup(w.Close)
	w.Close()
	options.SerialConsole = false
	production, err := NewPlacements(w.store, "host", "production-worker", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(production.Close)
	run, err := production.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(options.Root, "jails", "firecracker", run.ID, "root", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var boot struct {
		Source struct {
			Args string `json:"boot_args"`
		} `json:"boot-source"`
	}
	if err = json.Unmarshal(raw, &boot); err != nil || strings.Contains(boot.Source.Args, "console=ttyS0") {
		t.Fatal("the guest has a serial console:", boot.Source.Args, err)
	}
	logPath := filepath.Join(options.Root, "logs", run.ID+".log")
	flood, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = flood.Write([]byte(strings.Repeat("flood of a VMM\n", 200_000)))
	flood.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		st, err := os.Stat(logPath)
		return err == nil && st.Size() <= 1<<20
	})
	echo(t, production, t.Context(), "a", "after-the-cut")
	if err = production.Stop(t.Context(), "a", run.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("the log outlived its run:", err)
	}
}

func retireLab(t *testing.T, w *Placements, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := w.host.Retire(ctx, id, 1000); err != nil {
		t.Error(err)
	}
}
