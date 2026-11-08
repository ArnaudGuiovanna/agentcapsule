//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

func TestControlVMDeliveryAndRevocation(t *testing.T) {
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
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET inbound_mode='auto',discoverable=true"); err != nil {
		t.Fatal(err)
	}
	mandate, err := w.store.GrantMandate(t.Context(), "user-a", "a", "owner-instruction", 5, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	input := controlplane.Submission{RecipientAgentID: "b", MandateID: mandate, PayloadRef: "transit-reference", PayloadHash: sha256.Sum256([]byte("private content")), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	req, err := w.store.Submit(t.Context(), "a", "one", input)
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := w.store.HeadDelivery(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := w.store.ClaimDelivery(t.Context(), mailbox, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.AuthorizeDispatch(t.Context(), attempt.ID, attempt.Token); err != nil {
		t.Fatal(err)
	}
	// The target starts through the real PostgreSQL placement worker. ACK loss
	// here is at the control-plane boundary: keep the SQLite commit, omit its PG ACK.
	receipt, err := w.Send(t.Context(), "b", attempt.Envelope)
	if err != nil || receipt.Replayed || string(receipt.Result) != `{"effects":1}` {
		t.Fatalf("first delivery: %+v %v", receipt, err)
	}
	if _, err = db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agent_mailboxes"}.Sanitize()+" SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", attempt.ID); err != nil {
		t.Fatal(err)
	}
	retry, err := w.store.ClaimDelivery(t.Context(), mailbox, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.AuthorizeDispatch(t.Context(), retry.ID, retry.Token); err != nil {
		t.Fatal(err)
	}
	r, err := w.Send(t.Context(), "b", retry.Envelope)
	if err != nil || !r.Replayed || !bytes.Equal(r.Result, receipt.Result) {
		t.Fatalf("retry duplicated effect: %+v %v", r, err)
	}
	if err = w.store.AcknowledgeDelivery(t.Context(), attempt.ID, attempt.Token); !errors.Is(err, controlplane.ErrLeaseLost) {
		t.Fatalf("old worker ACK accepted: %v", err)
	}
	if err = w.store.AcknowledgeDelivery(t.Context(), retry.ID, retry.Token); err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	first := runs["b"]
	oldClient, err := w.host.Control(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.RequestCancellation(t.Context(), "user-a", req.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = w.store.ReconcileRequestClosure(t.Context(), req.RequestID, w); err != nil {
		t.Fatal(err)
	}
	// All three real guest stores acknowledged the request barrier before PG closed it.
	var acked int
	if err = db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "request_closure_targets"}.Sanitize()+" WHERE request_id=$1 AND acknowledged", req.RequestID).Scan(&acked); err != nil || acked != 3 {
		t.Fatalf("barrier census: %d %v", acked, err)
	}
	if _, err = oldClient.Send(t.Context(), attempt.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("late/replayed request escaped barrier: %v", err)
	}
	if err = w.store.DispatchOne(t.Context(), "a", time.Minute, w); err != nil {
		t.Fatal(err)
	}
	var notified bool
	if err = db.QueryRow(t.Context(), "SELECT sender_notified FROM "+pgx.Identifier{schema, "agent_requests"}.Sanitize()+" WHERE id=$1", req.RequestID).Scan(&notified); err != nil || !notified {
		t.Fatalf("final status not delivered: %v %v", notified, err)
	}
	// Preserve old host credentials solely for this adversarial test; cleanup must
	// remove the on-disk copy at stop. Never print/archive their contents.
	b, err := os.ReadFile(filepath.Join(options.Root, "credentials", first.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var oldCredentials capsuleprotocol.Credentials
	if err = json.Unmarshal(b, &oldCredentials); err != nil {
		t.Fatal(err)
	}
	if err = w.Stop(t.Context(), "b", first.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(options.Root, "credentials", first.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old host credentials retained: %v", err)
	}
	second, err := w.Start(t.Context(), "b")
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatalf("restart: %+v %v", second, err)
	}
	stale, err := capsuleprotocol.NewClient(oldCredentials, func(ctx context.Context) (net.Conn, error) { return capsuleprotocol.DialControl(ctx, second.Socket) })
	if err != nil {
		t.Fatal(err)
	}
	if err = stale.Health(t.Context()); err == nil {
		t.Fatal("old boot credentials accepted by replacement")
	}
	current, err := w.host.Control(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = current.Send(t.Context(), attempt.Envelope); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("request barrier lost on VM restart: %v", err)
	}
	// A's authenticated channel cannot impersonate B, even when deliberately
	// connected to B's socket instead of the placement-derived endpoint.
	runs, err = w.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(options.Root, "credentials", runs["a"].ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var foreign capsuleprotocol.Credentials
	if err = json.Unmarshal(b, &foreign); err != nil {
		t.Fatal(err)
	}
	wrong, err := capsuleprotocol.NewClient(foreign, func(ctx context.Context) (net.Conn, error) { return capsuleprotocol.DialControl(ctx, second.Socket) })
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.Health(t.Context()); err == nil {
		t.Fatal("cross-agent host credentials accepted")
	}
	if err = w.store.RequestDeletion(t.Context(), "user-b", "b"); err != nil {
		t.Fatal(err)
	}
	if err = w.store.ReconcileRevocation(t.Context(), "b", w); err != nil {
		t.Fatal(err)
	}
	if _, err = current.Send(t.Context(), harnessstore.Event{ID: "after-deletion", Subjects: []string{"agent/b", "event/after-deletion"}, Body: []byte("late")}); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("late agent work escaped barrier: %v", err)
	}
	// Root-owned credentials/initrd are intentionally absent from diagnostics.
	entries, err := os.ReadDir(filepath.Join(options.Root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		log, err := os.ReadFile(filepath.Join(options.Root, "logs", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(log, oldCredentials.PrivateKey) || bytes.Contains(log, []byte("private content")) {
			t.Fatal("private material appeared in VMM log")
		}
	}
}

func TestControlVMStoppedDeletionUsesFenceOnlyBoot(t *testing.T) {
	w, _, _, options := lab(t, true)
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
	if err := w.store.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	// Wake the stopped QUIESCING store for an unrelated barrier. Its own agent
	// fence has not arrived, so refusal below must come from the boot's scope.
	// Keep an explicitly started barrier guest alive for this scope inspection;
	// Fence now retires any temporary boot it owns after its RPC.
	if _, err := w.start(t.Context(), "a", true); err != nil {
		t.Fatal(err)
	}
	if err := w.Fence(t.Context(), "a", "request/unrelated"); err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || !runs["a"].FenceOnly {
		t.Fatalf("unrestricted boot: %+v %v", runs, err)
	}
	client, err := w.host.Control(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Send(t.Context(), harnessstore.Event{ID: "forbidden", Subjects: []string{"agent/a", "event/forbidden"}, Body: []byte("work")}); !errors.Is(err, capsuleprotocol.ErrFenceOnly) {
		t.Fatalf("quiescing guest accepted work: %v", err)
	}
	if _, err = w.Start(t.Context(), "a"); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatalf("normal start accepted: %v", err)
	}
	if err = w.store.ReconcileRevocation(t.Context(), "a", w); err != nil {
		t.Fatal(err)
	}
	placements, err := w.store.Placements(t.Context(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if len(placements) != 3 || !placements[0].FenceOnly {
		t.Fatalf("barrier-only purpose lost: %+v", placements)
	}
	if _, err = w.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	lockedVolume(t, options.Root, false)
}
