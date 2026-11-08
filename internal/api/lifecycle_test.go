package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// The physical observations here test the HTTP/SQL boundary only. The product
// worker KVM test executes the actual start/stop before completing its commands.
func TestHTTPLifecycleCommandsArePrivateAndRemainObservable(t *testing.T) {
	s, store, admin, _ := apiLab(t)
	if err := store.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	owner, token := apiOwner(t, s, admin, "owner")
	_, foreign := apiOwner(t, s, admin, "foreign")
	r := call(t, s, "POST", "/v1/agents", token, "create", agentInput)
	if r.Code != 202 {
		t.Fatal(r.Code)
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	e := jobs[0]
	wakePath := "/v1/agents/" + e.AgentID + "/wake"
	sleepPath := "/v1/agents/" + e.AgentID + "/sleep"
	if r := call(t, s, "POST", wakePath, token, "early", "{}"); r.Code != 409 {
		t.Fatal("unprovisioned wake accepted", r.Code)
	}
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
	var commands []controlplane.AgentCreation
	for _, path := range []string{wakePath, sleepPath} {
		if r := call(t, s, "POST", path, foreign, "foreign", "{}"); r.Code != 404 {
			t.Fatal("foreign command accepted", r.Code)
		}
		if r := call(t, s, "POST", path, token, "bad", `{"generation":0}`); r.Code != 400 {
			t.Fatal("caller selected generation", r.Code)
		}
		if r := call(t, s, "POST", path, token, "", "{}"); r.Code != 400 {
			t.Fatal("command without replay key", r.Code)
		}
		r := call(t, s, "POST", path, token, "command", "{}")
		if r.Code != 202 {
			t.Fatal(r.Code, r.Body.String())
		}
		var command controlplane.AgentCreation
		if err = json.Unmarshal(r.Body.Bytes(), &command); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
		replay := call(t, s, "POST", path, token, "command", "{}")
		if replay.Body.String() != r.Body.String() || replay.Header().Get("Idempotency-Replayed") != "true" {
			t.Fatal("command replay changed")
		}
	}
	if commands[0].OperationID == commands[1].OperationID {
		t.Fatal("wake and sleep share receipt scope")
	}
	if err = store.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		r := call(t, s, "GET", "/v1/operations/"+command.OperationID, token, "", "")
		var op controlplane.PlatformOperation
		if err = json.Unmarshal(r.Body.Bytes(), &op); err != nil {
			t.Fatal(err)
		}
		if r.Code != 200 || op.Status != "CANCELED" || op.ErrorCode != "agent_unavailable" {
			t.Fatal("canceled operation unobservable", op)
		}
		if r := call(t, s, "GET", "/v1/operations/"+command.OperationID, foreign, "", ""); r.Code != 404 {
			t.Fatal("foreign operation exposed")
		}
	}
	if r := call(t, s, "POST", wakePath, token, "new", "{}"); r.Code != 409 {
		t.Fatal("deleted agent revived", r.Code)
	}
}
