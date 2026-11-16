package controlplane

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// deadReplyLab is a request from a's VM to b's that b answered, with real
// owners for a and b: the reply waits in a's mailbox (ADR 007).
type deadReplyLab struct {
	s       *Store
	tr      *Transit
	catalog *AgentCatalog
	owners  [2]Principal
	a, b, c VMCaller
	rt      *peerRuntime
	request string
	reply   string
}

func newDeadReplyLab(t *testing.T) *deadReplyLab {
	t.Helper()
	s, _ := freshStore(t, "auto", 3)
	accounts, err := NewAccounts(s, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "dead-reply-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	l := &deadReplyLab{s: s, tr: peerTransit(t, s), rt: peerRuntimeLab(t)}
	for i, id := range []string{"a", "b"} {
		u := createAccount(t, accounts, admin, "owner-"+id, "Owner "+id)
		token := issueAccountToken(t, accounts, admin, u, "token-"+id)
		if l.owners[i], err = s.Authenticate(t.Context(), token.Token); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "UPDATE agents SET owner_user_id=$2 WHERE id=$1", id, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if l.catalog, err = NewAgentCatalogWithTransit(accounts, "host", l.tr); err != nil {
		t.Fatal(err)
	}
	l.a, l.b, l.c = confirmedCaller(t, s, "a"), confirmedCaller(t, s, "b"), confirmedCaller(t, s, "c")
	r, err := l.tr.SubmitFromVM(t.Context(), l.a, "request", peerSubmission("a question"))
	if err != nil {
		t.Fatal(err)
	}
	l.request = r.RequestID
	if err = l.tr.DispatchMailbox(t.Context(), mailboxFor(t, s, l.request, "request"), time.Minute, l.rt); err != nil {
		t.Fatal(err)
	}
	answer := capsuleprotocol.Reply{Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "the answer"}}}}
	if _, err = l.tr.ReplyFromVM(t.Context(), l.b, l.request, "reply", answer); err != nil {
		t.Fatal(err)
	}
	l.reply = mailboxFor(t, s, l.request, "reply")
	return l
}

// unreachable loses every send before it reaches the agent's store.
type unreachable struct{ *peerRuntime }

func (unreachable) Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
}

// killReply makes the reply's three attempts fail, then retires it.
func (l *deadReplyLab) killReply(t *testing.T) {
	t.Helper()
	down := unreachable{l.rt}
	for range 3 {
		if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("a failed attempt", err)
		}
		expireLease(t, l.s, l.reply)
	}
	if err := l.tr.DispatchMailbox(t.Context(), l.reply, time.Minute, down); err != nil {
		t.Fatal(err)
	}
	l.deliveryState(t, "DEAD")
}

func (l *deadReplyLab) deliveryState(t *testing.T, want string) {
	t.Helper()
	var got string
	if err := l.s.pool.QueryRow(t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", l.reply).Scan(&got); err != nil || got != want {
		t.Fatalf("reply delivery %s, want %s (%v)", got, want, err)
	}
}

// purgeLater moves the reply's retention to its end, as time would.
func (l *deadReplyLab) purgeLater(t *testing.T) {
	t.Helper()
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second'
        WHERE id=(SELECT reply_ref FROM agent_requests WHERE id=$1) AND purge_after IS NOT NULL`, l.request); err != nil {
		t.Fatal(err)
	}
	if _, err := l.tr.PurgeExpired(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}

// A reply whose delivery dies is kept for the transit retention from its
// death, as a delivered reply is from its delivery, then purged.
func TestDeadReplyStartsRetention(t *testing.T) {
	l := newDeadReplyLab(t)
	l.killReply(t)
	var after time.Duration
	if err := l.s.pool.QueryRow(t.Context(), `SELECT coalesce(extract(epoch FROM p.purge_after-clock_timestamp()),0)*interval '1 second'
        FROM transit_payloads p JOIN agent_requests r ON r.reply_ref=p.id WHERE r.id=$1`, l.request).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after < 7*24*time.Hour-time.Minute || after > 7*24*time.Hour {
		t.Fatalf("the dead reply is kept %v from now, want 7 days", after)
	}
	view, err := l.catalog.Request(t.Context(), l.owners[0], l.request)
	if err != nil || view.State != "REPLIED" || view.Reply == nil || view.Reply.Content[0].Text != "the answer" {
		t.Fatal("the sender's owner cannot read the kept reply", view, err)
	}
	l.purgeLater(t)
	var purged bool
	if err = l.s.pool.QueryRow(t.Context(), `SELECT p.purged_at IS NOT NULL AND p.ciphertext IS NULL
        FROM transit_payloads p JOIN agent_requests r ON r.reply_ref=p.id WHERE r.id=$1`, l.request).Scan(&purged); err != nil || !purged {
		t.Fatal("the dead reply outlived its retention", err)
	}
	for _, owner := range l.owners {
		view, err = l.catalog.Request(t.Context(), owner, l.request)
		if err != nil || view.State != "REPLIED" || view.Reply != nil {
			t.Fatal("a purged reply is still readable", view, err)
		}
	}
}
