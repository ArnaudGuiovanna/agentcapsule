//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// Real reservation -> durable queue -> encrypted volume -> restricted guest ->
// SQL activation -> owner HTTP wake/instruction/result/sleep/deletion. No volume,
// placement, readiness or business result row is seeded. Inter-agent exchange
// remains a separate milestone.
func TestProductWorkerProvisioningAndEncryptedWake(t *testing.T) {
	configuration := config(t)
	b := newBootReservation(t, false, "sha256:"+digest(t, configuration.Initrd))
	root, err := os.MkdirTemp(configuration.RootParent, "product-worker-")
	if err != nil {
		t.Fatal(err)
	}
	options := opts(t, root)
	options.AuthenticatedControl = true
	options.Ready = nil
	options.BootTimeout = time.Minute
	keys := b.keys.Provider.(*keyauthority.Files)
	authorityRoot := filepath.Join(t.TempDir(), "restore-authority")
	authority, err := restoreauthority.Initialize(t.Context(), authorityRoot, keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	w, err := NewProvisioningPlacements(b.w.store, b.e.HostID, "product-installer", 2*time.Minute, options, keys, authority, ProvisioningConfig{FirstUID: 62200, LastUID: 62209})
	if err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(w.store, "test", map[string][]byte{"test": bytes.Repeat([]byte{0x48}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit setup of this test installation's transit authority.
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = w.EnableTransit(t.Context(), transit); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := w.host.Retire(ctx, b.e.AgentID, ^uint64(0)); err != nil {
			t.Error(err)
		}
		w.Close()
	})
	// Refuse an unavailable release before allocating a secret/container.
	w.provisioning.digest = "sha256:unavailable"
	job := controlplane.WorkerJob{HostID: b.e.HostID, AgentID: b.e.AgentID, ID: b.e.OperationID, Kind: "provision"}
	if err = w.provision(t.Context(), job); !errors.Is(err, controlplane.ErrRelease) {
		t.Fatal(err)
	}
	if err = keys.WithKey(t.Context(), b.e.AgentID, b.e.VolumeID, func([]byte) error { t.Error("unsupported release allocated key"); return nil }); err == nil {
		t.Fatal("key exists before provisioning")
	}
	w.provisioning.digest = b.e.HarnessDigest
	dispatch := DispatchOptions{Batch: 1, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
	if err = w.DispatchPass(t.Context(), dispatch, 90*time.Second); err != nil {
		t.Fatal("physical provisioning", err)
	}
	e, err := w.store.ProvisioningTarget(t.Context(), b.e.AgentID, b.e.HostID, b.e.OperationID)
	if err != nil || e.Stage != "READY" || !e.Initialized {
		t.Fatal("activation missing", e, err)
	}
	if _, err = w.store.ClaimWork(t.Context(), b.e.HostID, time.Minute); !errors.Is(err, controlplane.ErrNoWork) {
		t.Fatal("provisioning job not completed", err)
	}
	if err = w.provision(t.Context(), job); err != nil {
		t.Fatal("lost activation ACK replay", err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || len(runs) != 0 {
		t.Fatal("restricted VM survived activation", runs, err)
	}
	event := harnessstore.Event{ID: "wake-persistence", Subjects: []string{"agent/" + b.e.AgentID}, Body: []byte("durable private content")}
	handler, err := api.NewForHostWithTransit(w.store, b.accounts, b.e.HostID, transit)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	issued, err := b.accounts.IssueUserToken(t.Context(), b.admin, b.owner.ID, "http-owner", controlplane.IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var token controlplane.TokenResponse
	if err = json.Unmarshal(issued.Body, &token); err != nil {
		t.Fatal(err)
	}
	requestBody := func(method, path, key, body string, code int, out any) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token.Token)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != code {
			t.Fatal("owner HTTP", method, path, response.StatusCode)
		}
		if err = json.NewDecoder(response.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	request := func(method, path, key string, code int, out any) {
		t.Helper()
		requestBody(method, path, key, "{}", code, out)
	}
	command := func(kind string, attempt int) {
		t.Helper()
		path := "/v1/agents/" + b.e.AgentID + "/" + kind
		key := fmt.Sprintf("%s-%d", kind, attempt)
		var accepted controlplane.AgentCreation
		request("POST", path, key, 202, &accepted)
		if err := w.DispatchPass(t.Context(), dispatch, 90*time.Second); err != nil {
			t.Fatal(kind, err)
		}
		var operation controlplane.PlatformOperation
		request("GET", "/v1/operations/"+accepted.OperationID, "", 200, &operation)
		if operation.Status != "SUCCEEDED" || operation.Kind != kind {
			t.Fatal("operation unfinished", operation)
		}
		if kind == "sleep" && (operation.UncleanStop == nil || *operation.UncleanStop) {
			t.Fatal("product guest failed to confirm clean shutdown")
		}
		var replay controlplane.AgentCreation
		request("POST", path, key, 202, &replay)
		if replay != accepted {
			t.Fatal("HTTP command replay changed")
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		command("wake", attempt)
		runs, err := w.Reconcile(t.Context())
		if err != nil || len(runs) != 1 || runs[b.e.AgentID].FenceOnly {
			t.Fatal("ordinary HTTP wake", runs, err)
		}
		client, err := w.host.Control(t.Context(), b.e.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		health, err := client.HealthStatus(t.Context())
		// The first ordinary boot follows retirement of the validation boot;
		// the second follows the product guest's acknowledged clean sleep.
		if err != nil || (attempt == 1 && health.PreviousShutdown != capsuleprotocol.ShutdownClean) {
			t.Fatal("clean shutdown observation not propagated", health, err)
		}
		receipt, err := client.Send(t.Context(), event)
		if err != nil || receipt.Replayed != (attempt == 1) {
			t.Fatal("persistent effect replay", receipt, err)
		}
		input := fmt.Sprintf(`{"content":[{"type":"text","text":"private instruction %d"}]}`, attempt)
		var instruction controlplane.AgentCreation
		requestBody("POST", "/v1/agents/"+b.e.AgentID+"/messages", fmt.Sprintf("instruction-%d", attempt), input, 202, &instruction)
		if err = w.DispatchPass(t.Context(), dispatch, 90*time.Second); err != nil {
			t.Fatal("physical instruction delivery", err)
		}
		var result controlplane.OwnerInstruction
		request("GET", "/v1/operations/"+instruction.OperationID+"/result", "", 200, &result)
		if len(result.Content) != 1 || result.Content[0].Text != fmt.Sprintf("private instruction %d", attempt) {
			t.Fatal("guest result mismatch")
		}
		command("sleep", attempt)
		runs, err = w.Reconcile(t.Context())
		if err != nil || len(runs) != 0 {
			t.Fatal("HTTP sleep retained VM", runs, err)
		}
	}
	command("wake", 2)
	runs, err = w.Reconcile(t.Context())
	if err != nil || len(runs) != 1 {
		t.Fatal("pre-crash boot missing", runs, err)
	}
	// Deliberately retire the actual VMM without guest quiescence. Reconciliation
	// must record this as unclean before the next authenticated boot preparation.
	if err = w.host.Retire(t.Context(), e.AgentID, runs[e.AgentID].Generation); err != nil {
		t.Fatal("forced VMM retirement", err)
	}
	if _, err = w.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	command("wake", 3)
	client, err := w.host.Control(t.Context(), e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	health, err := client.HealthStatus(t.Context())
	if err != nil || health.PreviousShutdown != capsuleprotocol.ShutdownUnclean {
		t.Fatal("forced shutdown observation not propagated", health, err)
	}
	if receipt, err := client.Send(t.Context(), event); err != nil || !receipt.Replayed {
		t.Fatal("forced restart lost durable deduplication", receipt, err)
	}
	command("sleep", 3)
	var deletion controlplane.AgentCreation
	request("DELETE", "/v1/agents/"+e.AgentID, "delete", 202, &deletion)
	// Actual host seal succeeds, but the independent catalogue goes offline
	// before it can acknowledge retirement. SQL must not publish its receipt.
	w.afterSeal = func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	}
	if err = w.DispatchPass(t.Context(), dispatch, 90*time.Second); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("missing root accepted physical seal", err)
	}
	var sealRows int
	if err = b.db.QueryRow(t.Context(), "SELECT count(*) FROM store_seals WHERE agent_id=$1", e.AgentID).Scan(&sealRows); err != nil || sealRows != 0 {
		t.Fatal("SQL sealed without independent record", sealRows, err)
	}
	authority, err = restoreauthority.Open(t.Context(), authorityRoot, authority.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	w.authority, w.afterSeal = authority, nil
	lost := errors.New("injected loss after physical cleanup before SQL receipt")
	w.afterRemoval = func() error { return lost }
	if err = w.RemoveDeletedStore(t.Context(), e.AgentID); !errors.Is(err, lost) {
		t.Fatal("deletion did not reach physical cleanup", err)
	}
	var deleting controlplane.PlatformOperation
	request("GET", "/v1/operations/"+deletion.OperationID, "", 200, &deleting)
	if deleting.Status != "RUNNING" || deleting.DeletionPhase != "CLEANUP_PENDING" {
		t.Fatal("uncertain completion published success", deleting)
	}
	if err = keys.WithKey(t.Context(), e.AgentID, e.VolumeID, func([]byte) error { t.Error("revoked key delivered"); return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), e.AgentID, e.VolumeID); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("deleted identity regenerated a key", err)
	}
	if _, err = os.Lstat(filepath.Join(options.Root, "volumes", e.VolumeID+".luks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("physical volume retained", err)
	}
	sealedBinding, err := authority.Lookup(t.Context(), e.AgentID)
	if !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal("physical deletion lost independent seal", err)
	}
	if _, err = authority.ReserveIncarnation(t.Context(), sealedBinding, "revive-deleted"); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal("sealed identity restored", err)
	}
	w.afterRemoval = nil
	if err = w.RemoveDeletedStore(t.Context(), e.AgentID); err != nil {
		t.Fatal("cleanup replay after unknown outcome", err)
	}
	var removed controlplane.PlatformOperation
	request("GET", "/v1/operations/"+deletion.OperationID, "", 200, &removed)
	if removed.Status != "SUCCEEDED" || removed.DeletionPhase != "COMPLETE" {
		t.Fatal("deletion incomplete", removed)
	}
	var agent controlplane.AgentView
	request("GET", "/v1/agents/"+e.AgentID, "", 200, &agent)
	if agent.State != "DELETED" {
		t.Fatal("agent not deleted", agent.State)
	}
	if _, err = w.Start(t.Context(), e.AgentID); err == nil {
		t.Fatal("deleted VM restarted")
	}
	if err = w.Fence(t.Context(), e.AgentID, "agent/another-revocation"); err != nil {
		t.Fatal("removed store cannot acknowledge future barrier", err)
	}
	var replay controlplane.AgentCreation
	request("DELETE", "/v1/agents/"+e.AgentID, "delete", 202, &replay)
	if replay != deletion {
		t.Fatal("deletion HTTP receipt changed")
	}
}
