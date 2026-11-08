//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
)

func sealLab(t *testing.T) (*Placements, string, runtime.FirecrackerOptions) {
	t.Helper()
	w, _, schema, options := lab(t, true)
	t.Cleanup(w.Close)
	for i, id := range []string{"b", "c"} {
		provisionAgent(t, w, options.Root, id, uint32(61212+i))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := w.host.Retire(ctx, id, 1000); err != nil {
				t.Error(err)
			}
		})
	}
	return w, schema, options
}

func TestSealedStoreAllowsLaterRevocationAndClosure(t *testing.T) {
	w, schema, options := sealLab(t)
	_, db := database(t, schema, false)
	if err := w.SealDeletedStore(t.Context(), "a"); !errors.Is(err, controlplane.ErrPendingFences) {
		t.Fatal(err)
	}
	run, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	old, err := w.host.Control(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err = w.store.ReconcileRevocation(t.Context(), "a", w); err != nil {
		t.Fatal(err)
	}
	if err = w.SealDeletedStore(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	if err = old.Health(t.Context()); err == nil {
		t.Fatal("sealed VMM still serves")
	}
	if _, err = w.host.Start(t.Context(), "a", run.Generation+100); !errors.Is(err, runtime.ErrHostFenced) {
		t.Fatal("sealed volume restarted:", err)
	}
	lockedVolume(t, options.Root, false)
	// A closure unrelated to A must still acknowledge A's registered store.
	if _, err = db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET inbound_mode='auto',discoverable=true WHERE id IN ('b','c')"); err != nil {
		t.Fatal(err)
	}
	mandate, err := w.store.GrantMandate(t.Context(), "user-b", "b", "instruction", 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.store.Submit(t.Context(), "b", "one", controlplane.Submission{RecipientAgentID: "c", MandateID: mandate, PayloadRef: "opaque", PayloadHash: sha256.Sum256([]byte("input")), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.RequestCancellation(t.Context(), "user-b", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = w.store.ReconcileRequestClosure(t.Context(), r.RequestID, w); err != nil {
		t.Fatal(err)
	}
	var closureAck bool
	if err = db.QueryRow(t.Context(), "SELECT acknowledged FROM "+pgx.Identifier{schema, "request_closure_targets"}.Sanitize()+" WHERE request_id=$1 AND store_agent_id='a'", r.RequestID).Scan(&closureAck); err != nil || !closureAck {
		t.Fatal(closureAck, err)
	}
	// A remembered SQL receipt must never turn absence/unavailability into ACK.
	if err = w.store.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	volume := filepath.Join(options.Root, "volumes", "a.ext4")
	if err = os.Rename(volume, volume+".offline"); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(volume+".offline", volume)
	if err = w.store.ReconcileRevocation(t.Context(), "b", w); err == nil {
		t.Fatal("missing sealed volume acknowledged")
	}
	var acknowledged bool
	if err = db.QueryRow(t.Context(), "SELECT acknowledged FROM "+pgx.Identifier{schema, "deletion_targets"}.Sanitize()+" WHERE agent_id='b' AND store_agent_id='a'").Scan(&acknowledged); err != nil || acknowledged {
		t.Fatal(acknowledged, err)
	}
	if err = os.Rename(volume+".offline", volume); err != nil {
		t.Fatal(err)
	}
	busy, err := os.OpenFile(volume, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(busy.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		busy.Close()
		t.Fatal(err)
	}
	err = w.store.ReconcileRevocation(t.Context(), "b", w)
	busy.Close()
	if !errors.Is(err, runtime.ErrVolumeBusy) {
		t.Fatal("writer ignored by sealed-store check:", err)
	}
	w.Close()
	next, err := NewPlacements(w.store, "host", "seal-replacement", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	if err = next.store.ReconcileRevocation(t.Context(), "b", next); err != nil {
		t.Fatal(err)
	}
	if err = next.SealDeletedStore(t.Context(), "b"); err != nil {
		t.Fatal(err)
	}
	if err = next.store.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	if err = next.store.ReconcileRevocation(t.Context(), "c", next); err != nil {
		t.Fatal(err)
	}
	if err = next.SealDeletedStore(t.Context(), "c"); err != nil {
		t.Fatal(err)
	}
	var seals, tombstones, acks int
	if err = db.QueryRow(t.Context(), fmt.Sprintf("SELECT (SELECT count(*) FROM %s),(SELECT count(*) FROM %s WHERE phase='DELETING'),(SELECT count(*) FROM %s WHERE acknowledged)", pgx.Identifier{schema, "store_seals"}.Sanitize(), pgx.Identifier{schema, "agents"}.Sanitize(), pgx.Identifier{schema, "deletion_targets"}.Sanitize())).Scan(&seals, &tombstones, &acks); err != nil || seals != 3 || tombstones != 3 || acks != 9 {
		t.Fatal(seals, tombstones, acks, err)
	}
}

func TestStoreSealWorkerCrashBeforeDatabaseReceipt(t *testing.T) {
	w, schema, options := sealLab(t)
	_, db := database(t, schema, false)
	if _, err := w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.ReconcileRevocation(t.Context(), "a", w); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStoreSealWorkerChild$", "-test.v")
	cmd.Env = append(os.Environ(), "AC_SEAL_CHILD_SCHEMA="+schema, "AC_SEAL_CHILD_ROOT="+options.Root)
	log, err := os.Create(filepath.Join(options.Root, "logs", "seal-worker.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for {
		if _, err = os.Stat(filepath.Join(options.Root, "logs", "sealed-before-sql")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal(err)
	}
	var n int
	if err = db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "store_seals"}.Sanitize()).Scan(&n); err != nil || n != 0 {
		t.Fatal("premature SQL seal:", n, err)
	}
	lockedVolume(t, options.Root, false)
	if _, err = w.host.Start(t.Context(), "a", 100); !errors.Is(err, runtime.ErrHostFenced) {
		t.Fatal(err)
	}
	if err = w.Fence(t.Context(), "a", "request/later"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "store_seals"}.Sanitize()).Scan(&n); err != nil || n != 1 {
		t.Fatal("receipt not recovered:", n, err)
	}
}

func TestStoreSealWorkerChild(t *testing.T) {
	schema := os.Getenv("AC_SEAL_CHILD_SCHEMA")
	if schema == "" {
		return
	}
	root := os.Getenv("AC_SEAL_CHILD_ROOT")
	s, _ := database(t, schema, false)
	options := opts(t, root)
	options.AuthenticatedControl = true
	options.MaxActive = 3
	options.Initrd = config(t).ControlInitrd
	options.InitrdSHA256 = digest(t, options.Initrd)
	w, err := NewPlacements(s, "host", "seal-child", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	w.afterSeal = func() {
		if err := os.WriteFile(filepath.Join(root, "logs", "sealed-before-sql"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if err = w.SealDeletedStore(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	t.Fatal("seal crash boundary not reached")
}
