package api

import (
	"encoding/json"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
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
