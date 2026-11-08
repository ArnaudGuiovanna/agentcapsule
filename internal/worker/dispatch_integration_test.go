//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func provisionDispatchPeers(t *testing.T, w *Placements, root string) {
	t.Helper()
	for i, id := range []string{"b", "c"} {
		provisionAgent(t, w, root, id, uint32(61212+i))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := w.host.Retire(ctx, id, 1000); err != nil {
				t.Error(err)
			}
		})
	}
}
func dispatchSubmission(t *testing.T, w *Placements, db *pgxpool.Pool, schema, key string) controlplane.Receipt {
	t.Helper()
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET inbound_mode='auto',discoverable=true"); err != nil {
		t.Fatal(err)
	}
	mandate, err := w.store.GrantMandate(t.Context(), "user-a", "a", "instruction-"+key, 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.store.Submit(t.Context(), "a", key, controlplane.Submission{RecipientAgentID: "b", MandateID: mandate, PayloadRef: "opaque-reference", PayloadHash: sha256.Sum256([]byte("payload")), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func dispatchState(t *testing.T, db *pgxpool.Pool, schema, id string) (string, bool) {
	t.Helper()
	var state string
	var notified bool
	if err := db.QueryRow(t.Context(), "SELECT state,sender_notified FROM "+pgx.Identifier{schema, "agent_requests"}.Sanitize()+" WHERE id=$1", id).Scan(&state, &notified); err != nil {
		t.Fatal(err)
	}
	return state, notified
}
func dispatchOptions() DispatchOptions {
	return DispatchOptions{Batch: 8, WorkLease: time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 5 * time.Second}
}

func TestDispatchServiceRequestReplyAndNotification(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 2, true)
	t.Cleanup(w.Close)
	provisionDispatchPeers(t, w, options.Root)
	r := dispatchSubmission(t, w, db, schema, "round-trip")
	w.Close()
	_, stop := serviceProcess(t, options, schema)
	w, err := NewPlacements(w.store, "host", "round-trip-observer", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	waitMaintenance(t, func() bool { state, _ := dispatchState(t, db, schema, r.RequestID); return state == "PROCESSING" })
	// Only the guest initiates the reply; service discovery delivers its outbox.
	reply := capsuleprotocol.Reply{Outcome: "completed", PayloadRef: "opaque-reply", PayloadHash: sha256.Sum256([]byte("reply"))}
	answered := platformJob(t, w, "b", "answer", map[string]any{"fixture_op": "platform_reply", "key": "reply", "request_id": r.RequestID, "reply": reply})
	if answered.Code != "" || answered.Receipt == nil || answered.Receipt.State != "REPLIED" {
		t.Fatal(answered)
	}
	waitMaintenance(t, func() bool {
		state, notified := dispatchState(t, db, schema, r.RequestID)
		return state == "REPLIED" && notified
	})
	stop()
	var n, attempts int
	if err := db.QueryRow(t.Context(), "SELECT count(*),sum(attempts) FROM "+pgx.Identifier{schema, "agent_mailboxes"}.Sanitize()+" WHERE ref_id=$1 AND delivery_state='DELIVERED'", r.RequestID).Scan(&n, &attempts); err != nil || n != 2 || attempts != 2 {
		t.Fatal(n, attempts, err)
	}
}

func TestDispatchPreparationAndOneSlotCapacity(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	// A partial provisioning record is discoverable but not runnable.
	if err := w.store.RegisterPlacement(t.Context(), "b", "host"); err != nil {
		t.Fatal(err)
	}
	r := dispatchSubmission(t, w, db, schema, "capacity")
	if err := w.DispatchPass(t.Context(), dispatchOptions(), 20*time.Second); err == nil {
		t.Fatal("unprovisioned target accepted")
	}
	var attempts int
	if err := db.QueryRow(t.Context(), "SELECT attempts FROM "+pgx.Identifier{schema, "agent_mailboxes"}.Sanitize()+" WHERE ref_id=$1", r.RequestID).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal("preparation consumed RPC attempt", attempts, err)
	}
	provisionDispatchPeers(t, w, options.Root)
	resident, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "worker_jobs"}.Sanitize()+" SET available_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err = w.DispatchPass(t.Context(), dispatchOptions(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	state, _ := dispatchState(t, db, schema, r.RequestID)
	if state != "PROCESSING" {
		t.Fatal(state)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || len(runs) != 1 || runs["b"].ID == "" || registryRun(t, options.Root, "a").ID == resident.ID {
		t.Fatal(runs, err)
	}
	if err = db.QueryRow(t.Context(), "SELECT attempts FROM "+pgx.Identifier{schema, "agent_mailboxes"}.Sanitize()+" WHERE ref_id=$1", r.RequestID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal(attempts, err)
	}
}

func TestDispatchServiceClosureExpirationAndDeletion(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	provisionDispatchPeers(t, w, options.Root)
	r := dispatchSubmission(t, w, db, schema, "cancel")
	if err := w.store.RequestCancellation(t.Context(), "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	w.Close()
	_, stop := serviceProcess(t, options, schema)
	waitMaintenance(t, func() bool {
		state, notified := dispatchState(t, db, schema, r.RequestID)
		return state == "CANCELED" && notified
	})
	expired := dispatchSubmission(t, w, db, schema, "expire")
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agent_requests"}.Sanitize()+" SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", expired.RequestID); err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		state, notified := dispatchState(t, db, schema, expired.RequestID)
		return state == "EXPIRED" && notified
	})
	if err := w.store.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		var n int
		if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "store_seals"}.Sanitize()+" WHERE agent_id='c'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	})
	stop()
	var n int
	if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "request_closure_targets"}.Sanitize()+" WHERE acknowledged").Scan(&n); err != nil || n != 6 {
		t.Fatal("closure barrier census", n, err)
	}
	if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "deletion_targets"}.Sanitize()+" WHERE acknowledged").Scan(&n); err != nil || n != 3 {
		t.Fatal("deletion barrier census", n, err)
	}
}

func TestDispatchWorkerCrashRecovery(t *testing.T) {
	for _, stage := range []string{"claimed", "completed"} {
		t.Run(stage, func(t *testing.T) {
			w, db, schema, options := labWithCapacity(t, 1, true)
			t.Cleanup(w.Close)
			provisionDispatchPeers(t, w, options.Root)
			r := dispatchSubmission(t, w, db, schema, "crash")
			w.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestDispatchWorkerChild$", "-test.v")
			cmd.Env = append(os.Environ(), "AC_DISPATCH_SCHEMA="+schema, "AC_DISPATCH_ROOT="+options.Root, "AC_DISPATCH_STAGE="+stage)
			log, err := os.Create(filepath.Join(options.Root, "logs", "dispatch-crash.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout, cmd.Stderr = log, log
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			waitMaintenance(t, func() bool {
				_, err := os.Stat(filepath.Join(options.Root, "logs", "dispatch-boundary"))
				return err == nil
			})
			before := registryRun(t, options.Root, "b")
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal(err)
			}
			// Advance only the SQL coordination lease after actual death. This never
			// substitutes for physical VMM retirement or delivery-effect fencing.
			if _, err = db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "worker_jobs"}.Sanitize()+" SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
				t.Fatal(err)
			}
			_, stop := serviceProcess(t, options, schema)
			waitMaintenance(t, func() bool {
				state, _ := dispatchState(t, db, schema, r.RequestID)
				var n int
				if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "worker_jobs"}.Sanitize()).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return state == "PROCESSING" && n == 0
			})
			stop()
			if stage == "completed" && registryRun(t, options.Root, "b").ID != before.ID {
				t.Fatal("completed delivery restarted its VMM")
			}
			w, err = NewPlacements(w.store, "host", "recovery-observer", time.Minute, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(w.Close)
			probe := harnessstore.Event{ID: "after-recovery", Subjects: []string{"agent/b", "event/after-recovery"}, Body: []byte("probe")}
			got, err := w.Send(t.Context(), "b", probe)
			if err != nil || string(got.Result) != `{"effects":2}` {
				t.Fatal("recovered job lost or duplicated local effect", got, err)
			}
		})
	}
}

func TestDispatchWorkerChild(t *testing.T) {
	schema := os.Getenv("AC_DISPATCH_SCHEMA")
	if schema == "" {
		return
	}
	root := os.Getenv("AC_DISPATCH_ROOT")
	s, _ := database(t, schema, false)
	options := opts(t, root)
	options.AuthenticatedControl, options.MaxActive = true, 1
	options.Initrd = config(t).ControlInitrd
	options.InitrdSHA256 = digest(t, options.Initrd)
	w, err := NewPlacements(s, "host", "dispatch-child", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	boundary := func(controlplane.WorkerJob) {
		if err := os.WriteFile(filepath.Join(root, "logs", "dispatch-boundary"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if os.Getenv("AC_DISPATCH_STAGE") == "claimed" {
		w.afterWorkClaim = boundary
	} else {
		w.afterWork = boundary
	}
	if err = w.DispatchPass(t.Context(), dispatchOptions(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary not reached")
}
