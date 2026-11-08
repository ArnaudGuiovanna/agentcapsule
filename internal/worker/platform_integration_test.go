//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

// The listener's lifetime lock belongs to the worker process, independently of
// the VMM's volume lock. SIGKILL must release the former while preserving the VM.
func TestPlatformListenerOwnerSIGKILL(t *testing.T) {
	w, _, schema, options := lab(t, true)
	t.Cleanup(w.Close)
	run, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPlatformListenerChild$", "-test.v")
	cmd.Env = append(os.Environ(), "AC_PLATFORM_CHILD_SCHEMA="+schema, "AC_PLATFORM_CHILD_ROOT="+options.Root)
	log, err := os.Create(filepath.Join(options.Root, "logs", "platform-child.log"))
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
		_, err := os.Stat(filepath.Join(options.Root, "logs", "platform-child-ready"))
		return err == nil
	})
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal(err)
	}
	if syscall.Kill(run.PID, 0) != nil {
		t.Fatal("listener death killed the VMM")
	}
	next, err := NewPlacements(w.store, "host", "listener-successor", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	adopted, err := next.Start(ctx, "a")
	if err != nil || adopted.ID != run.ID || adopted.Generation != run.Generation || adopted.PID != run.PID {
		t.Fatalf("listener recovery replaced VM: %+v %v", adopted, err)
	}
	result := platformJob(t, next, "a", "after-listener-sigkill", map[string]string{"fixture_op": "platform_health"})
	if result.Code != "" || !result.Done {
		t.Fatalf("reverse channel was not recovered: %+v", result)
	}
}

func TestPlatformListenerChild(t *testing.T) {
	schema := os.Getenv("AC_PLATFORM_CHILD_SCHEMA")
	if schema == "" {
		return
	}
	root := os.Getenv("AC_PLATFORM_CHILD_ROOT")
	s, _ := database(t, schema, false)
	options := opts(t, root)
	options.AuthenticatedControl = true
	options.MaxActive = 3
	options.Initrd = config(t).ControlInitrd
	options.InitrdSHA256 = digest(t, options.Initrd)
	w, err := NewPlacements(s, "host", "listener-child", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	result := platformJob(t, w, "a", "listener-child-health", map[string]string{"fixture_op": "platform_health"})
	if result.Code != "" {
		t.Fatalf("child did not own a working reverse listener: %+v", result)
	}
	if err = os.WriteFile(filepath.Join(root, "logs", "platform-child-ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

// Exercise the post-authentication API callback with a deliberately independent
// context. A real HTTP disconnect may instead cancel/roll back this transaction;
// the SQL authority contract must remain correct in either case.
func TestPlatformAdmittedTransactionAcrossPhysicalDeath(t *testing.T) {
	w, db, schema, _ := lab(t, true)
	t.Cleanup(w.Close)
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET inbound_mode='auto',discoverable=true"); err != nil {
		t.Fatal(err)
	}
	mandate, err := w.store.GrantMandate(t.Context(), "user-a", "a", "authority-race", 2, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	run, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	caller := controlplane.VMCaller{AgentID: "a", HostID: "host", VMID: run.ID, Generation: run.Generation}
	api := platformAPI{store: w.store, host: w.host, caller: caller, incarnation: run.Incarnation}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	gate, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(context.Background())
	var gatePID int
	if err = gate.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&gatePID); err != nil {
		t.Fatal(err)
	}
	if _, err = gate.Exec(ctx, "SELECT id FROM "+pgx.Identifier{schema, "mandates"}.Sanitize()+" WHERE id=$1 FOR UPDATE", mandate); err != nil {
		t.Fatal(err)
	}
	input := capsuleprotocol.Submission{RecipientAgentID: "b", MandateID: mandate, PayloadRef: "authority-race-ref", PayloadHash: sha256.Sum256([]byte("authority-race")), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	done := make(chan error, 1)
	go func() { _, err := api.Submit(ctx, "admitted-before-crash", input); done <- err }()
	waitMaintenance(t, func() bool {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%UPDATE mandates SET remaining=remaining-1%')`, gatePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting
	})
	if err = syscall.Kill(run.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", run.PID))
		if os.IsNotExist(err) {
			return true
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+1:])
		return len(fields) > 0 && fields[0] == "Z"
	})
	stopped := make(chan error, 1)
	go func() { stopped <- w.store.BeginPlacementStop(ctx, "a", "host", run.Generation) }()
	// Both operations hold/wait for actual PostgreSQL row locks. Physical death
	// does not release the platform transaction's authority lock.
	waitMaintenance(t, func() bool {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM agents WHERE id = ANY%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		return waiting
	})
	if err = gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal("admitted SQL transaction failed:", err)
	}
	if err = <-stopped; err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"admitted-before-crash", "new-after-stop"} {
		if _, err = api.Submit(ctx, key, input); err == nil {
			t.Fatal("retired SQL authority accepted replay/new work")
		}
		var rejected *capsuleprotocol.PlatformError
		if !errors.As(err, &rejected) || rejected.Code != "unauthorized" {
			t.Fatal(err)
		}
	}
	if _, err = w.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	var n, budget int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{schema, "agent_requests"}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, "SELECT remaining FROM "+pgx.Identifier{schema, "mandates"}.Sanitize()+" WHERE id=$1", mandate).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	if n != 1 || budget != 1 {
		t.Fatalf("authority race duplicated/lost commit: requests=%d budget=%d", n, budget)
	}
	placements, err := w.store.Placements(ctx, "host")
	if err != nil || len(placements) != 1 || placements[0].State != "STOPPED" || !placements[0].UncleanStop {
		t.Fatal(placements, err)
	}
}

type guestPlatformResult struct {
	Done    bool                             `json:"done"`
	Receipt *capsuleprotocol.PlatformReceipt `json:"receipt,omitempty"`
	Agents  []string                         `json:"agents,omitempty"`
	Code    string                           `json:"code,omitempty"`
}

func platformJob(t *testing.T, w *Placements, target, id string, command any) guestPlatformResult {
	t.Helper()
	body, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
	defer cancel()
	if _, err = w.Send(ctx, target, harnessstore.Event{ID: id, Subjects: []string{"agent/" + target, "event/" + id}, Body: body}); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		poll := fmt.Sprintf("poll-%s-%d", id, i)
		body, _ = json.Marshal(map[string]string{"fixture_op": "platform_result", "job_id": id})
		receipt, err := w.Send(ctx, target, harnessstore.Event{ID: poll, Subjects: []string{"agent/" + target, "event/" + poll}, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		var result guestPlatformResult
		if err = json.Unmarshal(receipt.Result, &result); err != nil {
			t.Fatal(err)
		}
		if result.Done {
			return result
		}
		select {
		case <-ctx.Done():
			t.Fatal("guest platform job did not finish:", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Read only the disposable boot archive to exercise a hostile HOST process
// with otherwise valid guest credentials. The bytes are never logged/archived.
func guestCredentials(t *testing.T, initrd string) capsuleprotocol.Credentials {
	t.Helper()
	data, err := os.ReadFile(initrd)
	if err != nil {
		t.Fatal(err)
	}
	align := func(n int) int { return (n + 3) &^ 3 }
	for offset := 0; offset < len(data); {
		for offset < len(data) && data[offset] == 0 {
			offset++
		}
		if offset+110 > len(data) || string(data[offset:offset+6]) != "070701" {
			t.Fatal("invalid disposable initramfs")
		}
		field := func(index int) int {
			n, err := strconv.ParseUint(string(data[offset+6+8*index:offset+14+8*index]), 16, 32)
			if err != nil {
				t.Fatal("invalid cpio field")
			}
			return int(n)
		}
		size, namesize := field(6), field(11)
		if namesize < 1 || offset+110+namesize > len(data) {
			t.Fatal("invalid cpio name")
		}
		name := string(data[offset+110 : offset+110+namesize-1])
		start := align(offset + 110 + namesize)
		if start+size > len(data) {
			t.Fatal("invalid cpio data")
		}
		if name == "etc/capsule/boot.json" {
			var c capsuleprotocol.Credentials
			if json.Unmarshal(data[start:start+size], &c) != nil {
				t.Fatal("invalid boot credentials")
			}
			return c
		}
		offset = align(start + size)
	}
	t.Fatal("boot configuration absent")
	return capsuleprotocol.Credentials{}
}

func TestPlatformVMIdentityMandatesRepliesAndWorkerHandover(t *testing.T) {
	w, db, schema, options := lab(t, true)
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
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET inbound_mode='auto',discoverable=(id<>'c')"); err != nil {
		t.Fatal(err)
	}
	mandate, err := w.store.GrantMandate(t.Context(), "user-a", "a", "instruction-a", 5, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mandateB, err := w.store.GrantMandate(t.Context(), "user-b", "b", "instruction-b", 3, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	input := capsuleprotocol.Submission{RecipientAgentID: "b", MandateID: mandate, PayloadRef: "transit-reference", PayloadHash: sha256.Sum256([]byte("private input")), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	first := platformJob(t, w, "a", "submit-one", map[string]any{"fixture_op": "platform_submit", "key": "one", "submission": input})
	if first.Code != "" || first.Receipt == nil || first.Receipt.State != "DELIVERING" || first.Receipt.Replayed {
		t.Fatalf("guest submission: %+v", first)
	}
	requestID := first.Receipt.RequestID
	replayed := platformJob(t, w, "a", "submit-replay", map[string]any{"fixture_op": "platform_submit", "key": "one", "submission": input})
	if replayed.Receipt == nil || !replayed.Receipt.Replayed || replayed.Receipt.RequestID != requestID {
		t.Fatalf("guest replay: %+v", replayed)
	}
	foreign := input
	foreign.MandateID = mandateB
	denied := platformJob(t, w, "a", "foreign-mandate", map[string]any{"fixture_op": "platform_submit", "key": "wrong-owner", "submission": foreign})
	if denied.Code != "mandate" {
		t.Fatalf("guest used another agent's mandate: %+v", denied)
	}
	var sender, recipient string
	var budget int
	if err = db.QueryRow(t.Context(), "SELECT sender_agent_id,recipient_agent_id FROM "+pgx.Identifier{schema, "agent_requests"}.Sanitize()+" WHERE id=$1", requestID).Scan(&sender, &recipient); err != nil || sender != "a" || recipient != "b" {
		t.Fatalf("caller not derived from channel: %s %s %v", sender, recipient, err)
	}
	if err = db.QueryRow(t.Context(), "SELECT remaining FROM "+pgx.Identifier{schema, "mandates"}.Sanitize()+" WHERE id=$1", mandate).Scan(&budget); err != nil || budget != 4 {
		t.Fatalf("retry refilled/consumed budget: %d %v", budget, err)
	}
	search := platformJob(t, w, "a", "search", map[string]any{"fixture_op": "platform_search", "candidates": []string{"a", "b", "c", "missing"}})
	if search.Code != "" || !reflect.DeepEqual(search.Agents, []string{"b"}) {
		t.Fatalf("directory postcheck: %+v", search)
	}
	if err = w.store.DispatchOne(t.Context(), "b", time.Minute, w); err != nil {
		t.Fatal(err)
	}
	reply := capsuleprotocol.Reply{Outcome: "completed", PayloadRef: "reply-reference", PayloadHash: sha256.Sum256([]byte("private reply"))}
	denied = platformJob(t, w, "a", "wrong-replier", map[string]any{"fixture_op": "platform_reply", "key": "reply", "request_id": requestID, "reply": reply})
	if denied.Code != "not_found" {
		t.Fatalf("sender impersonated recipient: %+v", denied)
	}
	answered := platformJob(t, w, "b", "reply-one", map[string]any{"fixture_op": "platform_reply", "key": "reply", "request_id": requestID, "reply": reply})
	if answered.Code != "" || answered.Receipt == nil || answered.Receipt.State != "REPLIED" {
		t.Fatalf("guest reply: %+v", answered)
	}
	if err = w.store.DispatchOne(t.Context(), "a", time.Minute, w); err != nil {
		t.Fatal(err)
	}
	var notified bool
	if err = db.QueryRow(t.Context(), "SELECT sender_notified FROM "+pgx.Identifier{schema, "agent_requests"}.Sanitize()+" WHERE id=$1", requestID).Scan(&notified); err != nil || !notified {
		t.Fatalf("reply not delivered: %v %v", notified, err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	old := runs["a"]
	boot := guestCredentials(t, filepath.Join(options.Root, "jails", "firecracker", old.ID, "root", "initrd"))
	if boot.Platform == nil {
		t.Fatal("no guest platform credentials")
	}
	socket := fmt.Sprintf("%s_%d", old.Socket, capsuleprotocol.PlatformPort)
	attacker, err := capsuleprotocol.NewPlatformClient(*boot.Platform, func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", socket) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	err = attacker.Health(ctx)
	cancel()
	if err == nil {
		t.Fatal("host process with copied guest credentials bypassed VMM PID/UID binding")
	}
	// Release worker-owned listeners, retain the VMMs, then rebuild listeners
	// from durable credentials in a replacement worker. The guest keeps its key.
	w.Close()
	next, err := NewPlacements(w.store, "host", "replacement-worker", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	adopted, err := next.Reconcile(t.Context())
	if err != nil || adopted["a"] != old {
		t.Fatalf("handover changed VM: %+v %v", adopted, err)
	}
	health := platformJob(t, next, "a", "after-handover", map[string]string{"fixture_op": "platform_health"})
	if health.Code != "" {
		t.Fatalf("guest could not reconnect to replacement worker: %+v", health)
	}
	if err = next.Stop(t.Context(), "a", old.Generation); err != nil {
		t.Fatal(err)
	}
	newBoot, err := next.Start(t.Context(), "a")
	if err != nil || newBoot.Generation != old.Generation+1 {
		t.Fatalf("new boot: %+v %v", newBoot, err)
	}
	afterRestart := platformJob(t, next, "a", "after-restart", map[string]any{"fixture_op": "platform_submit", "key": "one", "submission": input})
	if afterRestart.Code != "" || afterRestart.Receipt == nil || !afterRestart.Receipt.Replayed || afterRestart.Receipt.RequestID != requestID {
		t.Fatalf("new boot lost business idempotency: %+v", afterRestart)
	}
}
