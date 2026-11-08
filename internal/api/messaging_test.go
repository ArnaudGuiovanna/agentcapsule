package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// Physical provisioning observations stand for the VM here. All accounts,
// instructions, mandates, requests, contents, consent and results use real APIs.
func messagingAgentFixture(t *testing.T, s *Server, store *controlplane.Store, token string, inode uint64) controlplane.VMCaller {
	t.Helper()
	r := call(t, s, "POST", "/v1/agents", token, "create", agentInput)
	if r.Code != 202 {
		t.Fatal(r.Code)
	}
	var accepted controlplane.AgentCreation
	if err := json.Unmarshal(r.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil {
		t.Fatal(err)
	}
	var e controlplane.Enrollment
	for _, job := range jobs {
		if job.AgentID == accepted.AgentID {
			e = job
		}
	}
	if e.AgentID == "" {
		t.Fatal("provisioning operation missing")
	}
	if err = store.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: inode}); err != nil {
		t.Fatal(err)
	}
	p, err := store.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", inode)
	if err = store.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: vm}); err != nil {
		t.Fatal(err)
	}
	if err = store.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = store.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if err = store.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	p, err = store.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm = fmt.Sprintf("%016x", inode+1000)
	if err = store.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "fixture", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return controlplane.VMCaller{AgentID: e.AgentID, HostID: e.HostID, Generation: p.Generation, VMID: vm}
}

type messagingRuntime struct {
	*vmruntime.MockRuntime
	grant string
}

func (r *messagingRuntime) Invoke(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	in, err := capsuleprotocol.DecodeInvocation(event, target)
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	r.grant = in.Mandate.ID
	return r.Send(ctx, target, event)
}

func TestOwnerHTTPConsentInboxAndPrivatePeerContent(t *testing.T) {
	s, store, admin, _ := apiLab(t)
	tr, err := controlplane.NewTransit(store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x64}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err = NewForHostWithTransit(store, s.accounts, "local", tr)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureHostStorage(t.Context(), "local", 512); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	ownerA, tokenA := apiOwner(t, s, admin, "A")
	_, tokenB := apiOwner(t, s, admin, "B")
	_, foreign := apiOwner(t, s, admin, "C")
	a := messagingAgentFixture(t, s, store, tokenA, 101)
	b := messagingAgentFixture(t, s, store, tokenB, 102)
	mock, err := vmruntime.NewMock(t.Context(), t.TempDir(), a.AgentID, b.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()
	mock.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		var kind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(event.Body, &kind); err != nil {
			return nil, err
		}
		if kind.Kind == "message.user" {
			if _, err := capsuleprotocol.DecodeInvocation(event, target); err != nil {
				return nil, err
			}
		} else if _, err := capsuleprotocol.DecodePeerEvent(event, target); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects(event TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO effects VALUES(?)", event.ID)
		return []byte(`{"received":true}`), err
	})
	rt := &messagingRuntime{MockRuntime: mock}
	if r := call(t, s, "POST", "/v1/agents/"+a.AgentID+"/messages", tokenA, "instruction", `{"content":[{"type":"text","text":"Ask my peer"}]}`); r.Code != 202 {
		t.Fatal(r.Code)
	}
	head, err := store.HeadDelivery(t.Context(), a.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	in := capsuleprotocol.Submission{RecipientAgentID: b.AgentID, MandateID: rt.grant, Subject: "Private project", ExpiresAt: time.Now().Add(time.Hour), Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private question"}}}}
	if _, err = tr.SubmitFromVM(t.Context(), a, "hidden", in); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatal("hidden recipient contacted", err)
	}
	settingsPath := "/v1/me/messaging-settings"
	if r := call(t, s, "GET", settingsPath, tokenB, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"discoverable":false`) {
		t.Fatal("initial settings", r.Code)
	}
	for _, invalid := range []string{`{}`, `{"discoverable":true}`, `{"discoverable":true,"inbound_mode":"invalid"}`, `{"discoverable":true,"inbound_mode":"manual","owner":"A"}`} {
		if r := call(t, s, "PUT", settingsPath, tokenB, "", invalid); r.Code != 400 {
			t.Fatal("invalid settings", r.Code)
		}
	}
	if r := call(t, s, "PUT", settingsPath, admin, "", `{"discoverable":true,"inbound_mode":"manual"}`); r.Code != 403 {
		t.Fatal("admin altered user consent", r.Code)
	}
	if r := call(t, s, "PUT", settingsPath, tokenB, "", `{"discoverable":true,"inbound_mode":"manual"}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	req, err := tr.SubmitFromVM(t.Context(), a, "request", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.HeadDelivery(t.Context(), b.AgentID); !errors.Is(err, controlplane.ErrNoDelivery) {
		t.Fatal("delivery before consent", err)
	}
	r := call(t, s, "GET", "/v1/me/inbox?state=PENDING_APPROVAL", tokenB, "", "")
	var page struct {
		Items []controlplane.InboxItem `json:"items"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].RequestID != req.RequestID || strings.Contains(r.Body.String(), "private question") {
		t.Fatal("inbox metadata", r.Code)
	}
	if r = call(t, s, "GET", "/v1/me/inbox?after="+page.Items[0].ID, tokenB, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"items":[]`) {
		t.Fatal("inbox cursor", r.Code)
	}
	path := "/v1/agent-requests/" + req.RequestID
	for _, test := range []struct {
		token string
		code  int
	}{{tokenA, 200}, {tokenB, 200}, {foreign, 404}, {admin, 403}} {
		r = call(t, s, "GET", path, test.token, "", "")
		if r.Code != test.code {
			t.Fatal("private request access", r.Code, test.code)
		}
		if r.Code == 200 && !strings.Contains(r.Body.String(), "private question") {
			t.Fatal("owner preview missing")
		}
	}
	decision := "/v1/me/inbox/requests/" + req.RequestID + "/accept"
	for _, test := range []struct {
		token string
		code  int
	}{{tokenA, 404}, {foreign, 404}, {admin, 403}} {
		if r = call(t, s, "POST", decision, test.token, "consent", "{}"); r.Code != test.code {
			t.Fatal("foreign consent", r.Code)
		}
	}
	r = call(t, s, "POST", decision, tokenB, "consent", "{}")
	if r.Code != 200 {
		t.Fatal("acceptance", r.Code)
	}
	if replay := call(t, s, "POST", decision, tokenB, "consent", "{}"); replay.Code != 200 || replay.Body.String() != r.Body.String() || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("consent replay")
	}
	head, err = store.HeadDelivery(t.Context(), b.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private answer"}}}}
	if _, err = tr.ReplyFromVM(t.Context(), b, req.RequestID, "reply", answer); err != nil {
		t.Fatal(err)
	}
	head, err = store.HeadDelivery(t.Context(), a.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if r = call(t, s, "GET", path, tokenA, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), "private answer") {
		t.Fatal("reply unavailable to owner", r.Code)
	}
	second, err := tr.SubmitFromVM(t.Context(), a, "second", in)
	if err != nil {
		t.Fatal(err)
	}
	decline := "/v1/me/inbox/requests/" + second.RequestID + "/decline"
	if r = call(t, s, "POST", decline, tokenB, "decline", "{}"); r.Code != 200 || !strings.Contains(r.Body.String(), "DECLINED") {
		t.Fatal("decline", r.Code)
	}
	if r = call(t, s, "POST", "/v1/me/inbox/requests/"+second.RequestID+"/accept", tokenB, "late", "{}"); r.Code != 409 {
		t.Fatal("terminal request accepted", r.Code)
	}
	if r = call(t, s, "POST", "/v1/agent-requests/"+req.RequestID+"/cancel", tokenA, "too-late", `{}`); r.Code != 409 {
		t.Fatal("completed reply canceled", r.Code)
	}
	third, err := tr.SubmitFromVM(t.Context(), a, "third", in)
	if err != nil {
		t.Fatal(err)
	}
	cancelPath := "/v1/agent-requests/" + third.RequestID + "/cancel"
	for _, denied := range []struct {
		token string
		code  int
	}{{tokenB, 404}, {foreign, 404}, {admin, 403}} {
		if r = call(t, s, "POST", cancelPath, denied.token, "cancel", `{}`); r.Code != denied.code {
			t.Fatal("foreign cancellation", r.Code)
		}
	}
	r = call(t, s, "POST", cancelPath, tokenA, "cancel", `{}`)
	if r.Code != 202 {
		t.Fatal("cancel intent", r.Code)
	}
	initialCancel := r.Body.String()
	readPath := "/v1/agent-requests/" + third.RequestID
	check := func(state, closure string) {
		t.Helper()
		r := call(t, s, "GET", readPath, tokenA, "", "")
		var v controlplane.RequestView
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.State != state || v.ClosureState != closure {
			t.Fatal("cancellation progress", r.Code, v.State, v.ClosureState)
		}
	}
	check("PENDING_APPROVAL", "FENCING")
	lost := true
	rt.SetFenceHook(func(stage, target, subject string) error {
		if stage == "after_commit" && lost {
			lost = false
			return capsuleprotocol.ErrTransport
		}
		return nil
	})
	if err = store.ReconcileRequestClosure(t.Context(), third.RequestID, rt); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("lost barrier receipt", err)
	}
	check("PENDING_APPROVAL", "FENCING")
	rt.SetFenceHook(nil)
	if err = store.ReconcileRequestClosure(t.Context(), third.RequestID, rt); err != nil {
		t.Fatal(err)
	}
	check("CANCELED", "COMMITTED")
	if r = call(t, s, "POST", cancelPath, tokenA, "cancel", `{}`); r.Code != 202 || r.Body.String() != initialCancel || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("cancel receipt changed after completion", r.Code)
	}
	principal, err := store.Authenticate(t.Context(), tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeToken(t.Context(), principal, principal.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.catalog.DecideRequest(t.Context(), principal, req.RequestID, "consent", true); !errors.Is(err, controlplane.ErrAuthentication) {
		t.Fatal("cached revoked principal replay", err)
	}
	if _, err = s.catalog.Request(t.Context(), principal, req.RequestID); !errors.Is(err, controlplane.ErrAuthentication) {
		t.Fatal("cached revoked principal read", err)
	}
	if r = call(t, s, "GET", "/v1/me/inbox", tokenB, "", ""); r.Code != 401 {
		t.Fatal("revoked inbox access", r.Code)
	}
	if err = store.RequestDeletion(t.Context(), ownerA.ID, a.AgentID); err != nil {
		t.Fatal(err)
	}
	r = call(t, s, "GET", path, tokenA, "", "")
	if r.Code != 200 || strings.Contains(r.Body.String(), "private answer") || strings.Contains(r.Body.String(), "private question") {
		t.Fatal("deletion exposed peer content", r.Code)
	}
}
