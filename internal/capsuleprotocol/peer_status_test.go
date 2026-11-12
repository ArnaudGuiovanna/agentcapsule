package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var statusDeadline = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func (a *platformFake) DescribeAgent(_ context.Context, id string) (DirectoryAgent, error) {
	a.calls.Add(1)
	switch id {
	case "hidden":
		return DirectoryAgent{}, &PlatformError{Code: "not_found"}
	case "broken":
		return DirectoryAgent{}, errors.New("row lock on agents at 10.0.0.7")
	}
	return DirectoryAgent{AgentID: id, Description: "Summarizes.", Skills: []int{10302}, Domains: []int{111}}, nil
}

func (a *platformFake) RequestStatus(_ context.Context, id string) (RequestStatus, error) {
	a.calls.Add(1)
	if id == "foreign" {
		return RequestStatus{}, &PlatformError{Code: "not_found"}
	}
	return RequestStatus{RequestID: id, RecipientAgentID: "b", State: "PROCESSING", ExpiresAt: statusDeadline}, nil
}

// The two reads behind the guest's A2A endpoint carry only an agent ID or a
// request ID, and answer with typed outcomes.
func TestPeerReadsCarryOnlyTheirIDAndTypedOutcomes(t *testing.T) {
	c, _, _, api, _ := platformFixture(t)
	d, err := c.DescribeAgent(t.Context(), "agt_b")
	if err != nil || d.AgentID != "agt_b" || d.Description != "Summarizes." || len(d.Skills) != 1 {
		t.Fatal(d, err)
	}
	var pe *PlatformError
	if _, err = c.DescribeAgent(t.Context(), "hidden"); !errors.As(err, &pe) || pe.Code != "not_found" {
		t.Fatal(err)
	}
	if _, err = c.DescribeAgent(t.Context(), "broken"); !errors.As(err, &pe) || pe.Code != "unavailable" || bytes.Contains([]byte(err.Error()), []byte("10.0.0.7")) {
		t.Fatal("an adapter error crossed the channel", err)
	}
	s, err := c.RequestStatus(t.Context(), "arq_1")
	if err != nil || s != (RequestStatus{RequestID: "arq_1", RecipientAgentID: "b", State: "PROCESSING", ExpiresAt: statusDeadline}) {
		t.Fatal(s, err)
	}
	if _, err = c.RequestStatus(t.Context(), "foreign"); !errors.As(err, &pe) || pe.Code != "not_found" {
		t.Fatal(err)
	}

	calls := api.calls.Load()
	for _, bad := range []string{"", "a/b", "a b", string(make([]byte, 101))} {
		if _, err = c.DescribeAgent(t.Context(), bad); err == nil {
			t.Fatalf("agent ID %q accepted", bad)
		}
	}
	// Fields of other routes never ride on these reads, and the agent ID rides
	// on no other route.
	for _, bad := range []struct {
		path string
		in   platformRequest
	}{
		{"/v1/directory/agent", platformRequest{AgentID: "b", Key: "k"}},
		{"/v1/directory/agent", platformRequest{AgentID: "b", RequestID: "arq_1"}},
		{"/v1/directory/agent", platformRequest{AgentID: "b", Query: &DirectoryQuery{Skills: []int{10302}}}},
		{"/v1/directory/agent", platformRequest{AgentID: "../b"}},
		{"/v1/agent-requests/arq_1/status", platformRequest{RequestID: "arq_2"}},
		{"/v1/agent-requests/arq_1/status", platformRequest{RequestID: "arq_1", Key: "k"}},
		{"/v1/agent-requests/arq_1/status", platformRequest{RequestID: "arq_1", AgentID: "b"}},
		{"/v1/agent-requests/arq_1/status", platformRequest{RequestID: "arq_1", Reply: &Reply{Outcome: "declined"}}},
		{"/v1/directory/find", platformRequest{AgentID: "b", Query: &DirectoryQuery{Skills: []int{10302}}}},
		{"/v1/agent-requests", platformRequest{AgentID: "b", Key: "k", Submission: &Submission{RecipientAgentID: "b"}}},
	} {
		in := bad.in
		if _, err = c.call(t.Context(), bad.path, &in); err == nil {
			t.Fatal("accepted", bad.path, bad.in)
		}
	}
	if api.calls.Load() != calls {
		t.Fatal("a refused read reached the adapter")
	}
}

func TestPeerReadsWithoutThePeerAPIAreUnavailable(t *testing.T) {
	id := Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	h := &platformHandler{id: id, api: minimalPlatform{}, slots: make(chan struct{}, 1), localAuth: func(*http.Request) bool { return true }}
	for path, in := range map[string]platformRequest{
		"/v1/directory/agent":             {Protocol: Version, Identity: id, AgentID: "b"},
		"/v1/agent-requests/arq_1/status": {Protocol: Version, Identity: id, RequestID: "arq_1"},
	} {
		body, _ := json.Marshal(in)
		rec := httptest.NewRecorder()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body)))
		cancel()
		var out platformResponse
		if rec.Code != http.StatusServiceUnavailable || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Code != "unavailable" {
			t.Fatal(path, rec.Code, rec.Body.String())
		}
	}
}
