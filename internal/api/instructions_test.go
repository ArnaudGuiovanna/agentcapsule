package api

import (
	"bytes"
	"encoding/json"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"strings"
	"testing"
	"time"
)

func TestHTTPInstructionsOwnerOnlyAndDurableReceipt(t *testing.T) {
	s, store, admin, _ := apiLab(t)
	transit, err := controlplane.NewTransit(store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err = NewForHostWithTransit(store, s.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	owner, token := apiOwner(t, s, admin, "owner")
	_, foreign := apiOwner(t, s, admin, "other")
	if r := call(t, s, "POST", "/v1/agents", token, "create", agentInput); r.Code != 202 {
		t.Fatal(r.Code)
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(err)
	}
	e := jobs[0]
	path := "/v1/agents/" + e.AgentID + "/messages"
	input := `{"content":[{"type":"text","text":"private instruction"}]}`
	if r := call(t, s, "POST", path, token, "early", input); r.Code != 409 {
		t.Fatal("instruction before provisioning", r.Code)
	}
	// Explicit SQL fixture for the HTTP boundary; no physical VM is asserted.
	if err = store.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
		t.Fatal(err)
	}
	p, err := store.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: "0123456789abcdef"}); err != nil {
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
	for _, test := range []struct {
		token string
		want  int
	}{{foreign, 404}, {admin, 403}, {"", 401}} {
		if r := call(t, s, "POST", path, test.token, "denied", input); r.Code != test.want {
			t.Fatal("instruction access", r.Code, test.want)
		}
	}
	for _, invalid := range []string{`{}`, `{"content":[]}`, `{"content":[{"type":"image","text":"x"}]}`, `{"content":[{"type":"text","text":" "}]}`, `{"content":[{"type":"text","text":"x"}],"mandate_id":"forged"}`} {
		if r := call(t, s, "POST", path, token, "invalid", invalid); r.Code != 400 {
			t.Fatal("untrusted instruction parameters accepted", r.Code)
		}
	}
	r := call(t, s, "POST", path, token, "send", input)
	if r.Code != 202 || strings.Contains(r.Body.String(), "private instruction") {
		t.Fatal("instruction admission", r.Code)
	}
	var op controlplane.AgentCreation
	if err = json.Unmarshal(r.Body.Bytes(), &op); err != nil {
		t.Fatal(err)
	}
	replayed := call(t, s, "POST", path, token, "send", input)
	if replayed.Code != 202 || replayed.Body.String() != r.Body.String() || replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("HTTP replay diverged")
	}
	if r := call(t, s, "POST", path, token, "send", strings.Replace(input, "private instruction", "changed", 1)); r.Code != 422 {
		t.Fatal("changed idempotency body accepted", r.Code)
	}
	result := "/v1/operations/" + op.OperationID + "/result"
	for _, test := range []struct {
		token string
		want  int
	}{{token, 404}, {foreign, 404}, {admin, 403}} {
		if r := call(t, s, "GET", result, test.token, "", ""); r.Code != test.want {
			t.Fatal("private result boundary", r.Code, test.want)
		}
	}
	if err = store.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if r := call(t, s, "POST", path, token, "new", input); r.Code != 409 {
		t.Fatal("new instruction accepted after deletion", r.Code)
	}
}
