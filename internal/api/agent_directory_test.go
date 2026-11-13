package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHTTPAgentDirectoryProfile(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	id := apiActiveTenantAgent(t, l, owner, "summarizer")
	apiAddMember(t, l, owner, "bob", "agent_user")
	member := l.sign(t, at, "bob-all", "bob", allAgentScopes)
	path := "/v1/agents/" + id + "/directory"

	r := call(t, l.server, "GET", path, owner, "", "")
	var e controlplane.DirectoryEntry
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &e) != nil || e.Publication != "unpublished" || e.Visible {
		t.Fatal("an undescribed agent", r.Code, r.Body.String())
	}
	body := `{"visible":true,"description":"Summarizes documents.","skills":[10302],"domains":[111]}`
	if r = call(t, l.server, "PUT", path, member, "member", body); r.Code != 403 {
		t.Fatal("a plain member described an agent", r.Code)
	}
	if r = call(t, l.server, "PUT", path, owner, "", body); r.Code != 400 {
		t.Fatal("a description without idempotency key", r.Code)
	}
	if r = call(t, l.server, "PUT", path, owner, "unknown-field", `{"visible":true,"description":"d","skills":[1],"owner":"x"}`); r.Code != 400 {
		t.Fatal("an unknown field", r.Code)
	}
	if r = call(t, l.server, "PUT", path, owner, "no-skill", `{"visible":true,"description":"d","skills":[]}`); r.Code != 400 {
		t.Fatal("no skill", r.Code)
	}
	r = call(t, l.server, "PUT", path, owner, "describe", body)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &e) != nil || !e.Visible || e.Publication != "pending" || e.Description != "Summarizes documents." {
		t.Fatal("describe", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "PUT", path, owner, "describe", body); r.Code != 200 {
		t.Fatal("replay", r.Code)
	}
	if r = call(t, l.server, "POST", path, owner, "post", body); r.Code != 405 {
		t.Fatal("method", r.Code)
	}
	// Another domain does not see the agent at all.
	if r = call(t, l.server, "GET", path, l.legacy, "", ""); r.Code != 404 && r.Code != 400 {
		t.Fatal("the legacy domain reads an organization agent's description", r.Code)
	}
	if r = call(t, l.server, "GET", "/v1/agents/agt_unknown/directory", owner, "", ""); r.Code != 404 {
		t.Fatal("unknown agent", r.Code)
	}
}

func TestHTTPAgentInboundPolicy(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	id := apiActiveTenantAgent(t, l, owner, "recipient")
	apiAddMember(t, l, owner, "bob", "agent_user")
	member := l.sign(t, at, "bob-all", "bob", allAgentScopes)
	path := "/v1/agents/" + id + "/inbound"

	var p controlplane.InboundPolicy
	r := call(t, l.server, "GET", path, owner, "", "")
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &p) != nil || p != (controlplane.InboundPolicy{AgentID: id, Mode: "manual"}) {
		t.Fatal("default", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "PUT", path, member, "member", `{"mode":"auto"}`); r.Code != 403 {
		t.Fatal("a plain member opened an agent", r.Code)
	}
	if r = call(t, l.server, "PUT", path, owner, "", `{"mode":"auto"}`); r.Code != 400 {
		t.Fatal("no idempotency key", r.Code)
	}
	for _, body := range []string{`{"mode":"open"}`, `{}`, `{"mode":"auto","discoverable":true}`} {
		if r = call(t, l.server, "PUT", path, owner, "bad", body); r.Code != 400 {
			t.Fatal(body, r.Code)
		}
	}
	r = call(t, l.server, "PUT", path, owner, "open", `{"mode":"auto"}`)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &p) != nil || p.Mode != "auto" {
		t.Fatal("open", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "PUT", path, owner, "open", `{"mode":"manual"}`); r.Code != 422 {
		t.Fatal("the same key for another policy", r.Code)
	}
	if r = call(t, l.server, "GET", path, owner, "", ""); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &p) != nil || p.Mode != "auto" {
		t.Fatal("read", r.Code, r.Body.String())
	}
	// A member without any right to the agent learns nothing about it.
	if r = call(t, l.server, "GET", path, member, "", ""); r.Code != 404 {
		t.Fatal("read by a member who has no assignment", r.Code)
	}
	if r = call(t, l.server, "POST", path, owner, "post", `{"mode":"auto"}`); r.Code != 405 {
		t.Fatal("method", r.Code)
	}
	if r = call(t, l.server, "GET", path, l.legacy, "", ""); r.Code != 404 && r.Code != 400 {
		t.Fatal("the legacy domain reads an organization agent's policy", r.Code)
	}
	if r = call(t, l.server, "GET", "/v1/agents/agt_unknown/inbound", owner, "", ""); r.Code != 404 {
		t.Fatal("unknown agent", r.Code)
	}
}

// A request held by an organization agent's manual inbound policy is listed
// and decided over HTTP by whoever may configure the agent or is assigned to it
// with invoke; others are refused, and the content never appears.
func TestHTTPHeldRequests(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	sender := apiActiveTenantAgent(t, l, owner, "sender")
	recipient := apiActiveTenantAgent(t, l, owner, "recipient")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	apiAddMember(t, l, owner, "carol", "agent_user")
	assignment := `{"principal_id":"` + bob.PrincipalID + `","permissions":["invoke"]}`
	if r := call(t, l.server, "POST", "/v1/agents/"+recipient+"/assignments", owner, "asg", assignment); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	bobToken := l.sign(t, at, "bob-all", "bob", allAgentScopes)
	carolToken := l.sign(t, at, "carol-all", "carol", allAgentScopes)
	db, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(t.Context(), `UPDATE agents SET discoverable=true WHERE id=$1;`, recipient); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(t.Context(), `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('mandate-sender',$1,'evt-sender',3,3,clock_timestamp()+interval '1 hour')`, sender); err != nil {
		t.Fatal(err)
	}
	held := func(key string) string {
		t.Helper()
		r, err := l.store.Submit(t.Context(), sender, key, controlplane.Submission{RecipientAgentID: recipient, MandateID: "mandate-sender",
			PayloadRef: "payload-" + key, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil || r.State != controlplane.PendingApproval {
			t.Fatal("held request", r, err)
		}
		return r.RequestID
	}
	first, second := held("first"), held("second")
	list := "/v1/agents/" + recipient + "/held-requests"

	var page struct {
		Items []controlplane.HeldRequest `json:"items"`
	}
	r := call(t, l.server, "GET", list, bobToken, "", "")
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || len(page.Items) != 2 || page.Items[0].SenderAgentID != sender {
		t.Fatal("list", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", list+"?limit=x", bobToken, "", ""); r.Code != 400 {
		t.Fatal("limit", r.Code)
	}
	if r = call(t, l.server, "GET", list, carolToken, "", ""); r.Code != 404 {
		t.Fatal("a member without any right to the agent", r.Code)
	}
	if r = call(t, l.server, "POST", list, owner, "k", "{}"); r.Code != 405 {
		t.Fatal("method", r.Code)
	}

	accept := list + "/" + first + "/accept"
	if r = call(t, l.server, "POST", accept, carolToken, "c", "{}"); r.Code != 404 {
		t.Fatal("carol accepted", r.Code)
	}
	if r = call(t, l.server, "POST", accept, bobToken, "", "{}"); r.Code != 400 {
		t.Fatal("no idempotency key", r.Code)
	}
	if r = call(t, l.server, "POST", accept, bobToken, "yes", `{"note":"x"}`); r.Code != 400 {
		t.Fatal("unknown field", r.Code)
	}
	r = call(t, l.server, "POST", accept, bobToken, "yes", "{}")
	var out controlplane.HeldRequestDecision
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil || out != (controlplane.HeldRequestDecision{RequestID: first, State: controlplane.Delivering}) {
		t.Fatal("accept", r.Code, r.Body.String())
	}
	if replay := call(t, l.server, "POST", accept, bobToken, "yes", "{}"); replay.Code != 200 || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay", replay.Code)
	}
	if r = call(t, l.server, "POST", accept, owner, "again", "{}"); r.Code != 409 {
		t.Fatal("accepted twice", r.Code)
	}
	if r = call(t, l.server, "POST", list+"/"+second+"/decline", owner, "no", "{}"); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil || out.State != "DECLINED" {
		t.Fatal("decline", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "GET", list, owner, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"items":[]`) {
		t.Fatal("decided requests are still listed", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/agents/"+sender+"/held-requests/"+second+"/accept", owner, "elsewhere", "{}"); r.Code != 404 {
		t.Fatal("a request through another agent", r.Code)
	}
}
