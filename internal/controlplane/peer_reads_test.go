package controlplane

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// An Agent Card is served only for an agent the caller could send a request
// to: of its organization, discoverable, live, not itself. Its description and
// skills are the ones the organization published; anything else is the same
// "not found".
func TestDescribeAgentFromAVMFollowsTheRecipientRules(t *testing.T) {
	l, c, owner := agentLab(t)
	caller := activateTenantAgent(t, l, c, owner, "caller")
	summarizer := activateTenantAgent(t, l, c, owner, "summarizer")
	plain := activateTenantAgent(t, l, c, owner, "plain")
	hidden := activateTenantAgent(t, l, c, owner, "hidden")
	setProfile(t, c, owner, summarizer, "describe", directoryProfile("Summarizes long documents.", true, 10302, 10301))
	// Agents are hidden until the organization makes them discoverable; plain
	// is discoverable but was never described.
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=(id=$1) WHERE id IN ($1,$2)", plain, hidden); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO organizations(id,name) VALUES ('org-other','Other');
        INSERT INTO agents(id,tenant_id,phase,discoverable) VALUES ('agt-other','org-other','LIVE',true)`); err != nil {
		t.Fatal(err)
	}
	vm := tenantCaller(t, l.s, caller)
	d, err := l.s.DescribeAgentFromVM(t.Context(), vm, summarizer)
	if err != nil || !reflect.DeepEqual(d, DirectoryAgent{AgentID: summarizer, Description: "Summarizes long documents.", Skills: []int{10301, 10302}, Domains: []int{111}}) {
		t.Fatalf("described %+v %v", d, err)
	}
	// Never described: the card has no description and no skill.
	d, err = l.s.DescribeAgentFromVM(t.Context(), vm, plain)
	if err != nil || !reflect.DeepEqual(d, DirectoryAgent{AgentID: plain, Skills: []int{}, Domains: []int{}}) {
		t.Fatalf("undescribed %+v %v", d, err)
	}
	for _, id := range []string{hidden, "agt-other", caller, "agt-missing", ""} {
		if _, err = l.s.DescribeAgentFromVM(t.Context(), vm, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%q described: %v", id, err)
		}
	}
	// A stopped boot generation can no longer read.
	if err = l.s.BeginPlacementStop(t.Context(), caller, "local", vm.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.DescribeAgentFromVM(t.Context(), vm, summarizer); err == nil {
		t.Fatal("a stopping VM read an Agent Card")
	}
}

// The sender, and only the sender, reads a request's state as it moves from
// consent to delivery to its reply.
func TestRequestStateFromAVMIsTheSendersOnly(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	tr := peerTransit(t, s)
	a := confirmedCaller(t, s, "a")
	b := confirmedCaller(t, s, "b")
	c := confirmedCaller(t, s, "c")
	in := peerSubmission("a question")
	r, err := tr.SubmitFromVM(t.Context(), a, "request", in)
	if err != nil {
		t.Fatal(err)
	}
	state := func(want string) {
		t.Helper()
		got, err := s.RequestStateFromVM(t.Context(), a, r.RequestID)
		if err != nil || got.State != want || got.RecipientAgentID != "b" || got.RequestID != r.RequestID || !got.ExpiresAt.Equal(in.ExpiresAt) {
			t.Fatalf("state %+v %v, want %s", got, err, want)
		}
	}
	state("PENDING_APPROVAL")
	for _, vm := range []VMCaller{b, c} {
		if _, err = s.RequestStateFromVM(t.Context(), vm, r.RequestID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s read another agent's request: %v", vm.AgentID, err)
		}
	}
	if _, err = s.RequestStateFromVM(t.Context(), a, "arq_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = s.Accept(t.Context(), "user-b", r.RequestID, "accept"); err != nil {
		t.Fatal(err)
	}
	state("DELIVERING")
	rt := peerRuntimeLab(t)
	if err = tr.DispatchMailbox(t.Context(), mailboxFor(t, s, r.RequestID, "request"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	state("PROCESSING")
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "an answer"}}}}
	if _, err = tr.ReplyFromVM(t.Context(), b, r.RequestID, "reply", answer); err != nil {
		t.Fatal(err)
	}
	state("REPLIED")
	if err = s.BeginPlacementStop(t.Context(), "a", "host", a.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RequestStateFromVM(t.Context(), a, r.RequestID); err == nil {
		t.Fatal("a stopping VM read a request")
	}
}
