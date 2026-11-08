package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func apiOwner(t *testing.T, s *Server, admin, name string) (controlplane.User, string) {
	t.Helper()
	r := call(t, s, "POST", "/v1/users", admin, "owner/"+name, fmt.Sprintf(`{"display_name":%q}`, name))
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	var u controlplane.User
	if err := json.Unmarshal(r.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	r = call(t, s, "POST", "/v1/users/"+u.ID+"/tokens", admin, "token/"+name, fmt.Sprintf(`{"expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)))
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	var token controlplane.TokenResponse
	if err := json.Unmarshal(r.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	return u, token.Token
}

const agentInput = `{"name":"Companion","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128},"auto_start":false}`

func TestHTTPAgentReservationsAndOwnerIsolation(t *testing.T) {
	s, store, admin, _ := apiLab(t)
	if err := store.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	one, first := apiOwner(t, s, admin, "one")
	_, second := apiOwner(t, s, admin, "two")
	created := call(t, s, "POST", "/v1/agents", first, "create", agentInput)
	if created.Code != 202 {
		t.Fatal(created.Code, created.Body.String())
	}
	var agent controlplane.AgentCreation
	if err := json.Unmarshal(created.Body.Bytes(), &agent); err != nil {
		t.Fatal(err)
	}
	if agent.Status != "PENDING" {
		t.Fatal("unprovisioned agent advertised ready")
	}
	replayed := call(t, s, "POST", "/v1/agents", first, "create", agentInput)
	if replayed.Code != 202 || replayed.Body.String() != created.Body.String() || replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("creation replay changed")
	}
	if r := call(t, s, "POST", "/v1/agents", first, "other-key", agentInput); r.Code != 409 {
		t.Fatal("duplicate companion accepted", r.Code)
	}
	for _, path := range []string{"/v1/agents/" + agent.AgentID, "/v1/operations/" + agent.OperationID} {
		for _, token := range []string{first, admin} {
			if r := call(t, s, "GET", path, token, "", ""); r.Code != 200 {
				t.Fatal(path, r.Code)
			}
		}
		if r := call(t, s, "GET", path, second, "", ""); r.Code != 404 {
			t.Fatal("foreign resource exposed", path, r.Code)
		}
	}
	if r := call(t, s, "GET", "/v1/agents/"+agent.AgentID, first, "", ""); !strings.Contains(r.Body.String(), `"state":"PROVISIONING"`) {
		t.Fatal("pending state absent", r.Body.String())
	}
	if r := call(t, s, "GET", "/v1/agents", second, "", ""); r.Code != 200 || r.Body.String() != "{\"items\":[]}\n" {
		t.Fatal("foreign agent listed", r.Body.String())
	}
	other := call(t, s, "POST", "/v1/agents", second, "create", agentInput)
	if other.Code != 202 {
		t.Fatal(other.Code, other.Body.String())
	}
	for _, token := range []string{first, second, admin} {
		r := call(t, s, "GET", "/v1/agents", token, "", "")
		var out struct {
			Items []controlplane.AgentView `json:"items"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		want := 1
		if token == admin {
			want = 2
		}
		if r.Code != 200 || len(out.Items) != want {
			t.Fatal("list isolation", r.Code, len(out.Items))
		}
	}
	for _, input := range []string{
		strings.Replace(agentInput, `"name":"Companion"`, `"name":"Companion","host_id":"foreign"`, 1),
		strings.Replace(agentInput, `"name":"Companion"`, `"name":"Companion","volume_path":"/tmp/other"`, 1),
		strings.Replace(agentInput, `"vcpus":1`, `"vcpus":0`, 1),
	} {
		if r := call(t, s, "POST", "/v1/agents", second, "bad", input); r.Code != 400 {
			t.Fatal("privileged/invalid creation accepted", r.Code)
		}
	}
	foreign := strings.Replace(agentInput, `"name":"Companion"`, fmt.Sprintf(`"name":"Companion","owner_user_id":%q`, one.ID), 1)
	if r := call(t, s, "POST", "/v1/agents", second, "foreign", foreign); r.Code != 404 {
		t.Fatal("owner impersonation", r.Code)
	}
	if r := call(t, s, "GET", "/v1/agents?limit=1000", first, "", ""); r.Code != 400 {
		t.Fatal("unbounded list", r.Code)
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 2 {
		t.Fatal("HTTP reservation not discoverable by worker", jobs, err)
	}
}

func TestHTTPConcurrentCreationHasOneDurableOperation(t *testing.T) {
	s, store, admin, _ := apiLab(t)
	if err := store.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	_, owner := apiOwner(t, s, admin, "owner")
	var wg sync.WaitGroup
	results := make(chan int, 6)
	for i := range 6 {
		wg.Go(func() { r := call(t, s, "POST", "/v1/agents", owner, fmt.Sprint(i), agentInput); results <- r.Code })
	}
	wg.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 202 {
			success++
		} else if status != 409 {
			t.Fatal("concurrent creation", status)
		}
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || success != 1 || len(jobs) != 1 {
		t.Fatal("duplicate durable operations", success, len(jobs), err)
	}
}
