package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// redeliveryLab is two agents of two persons, each with an enrolled volume
// on host local, that exchange private requests through the transit: a
// sends, b answers. Either can be restored (ADR 008).
type redeliveryLab struct {
	s        *Store
	tr       *Transit
	catalog  *AgentCatalog
	a, b     string
	owners   map[string]Principal
	vms      map[string]VMCaller
	rt       *redeliveryRuntime
	restores int
	keys     int
}

// redeliveryRuntime records the ID of every event it sends. Its stores are
// not restored, so an event sent again is deduplicated there: the control
// plane still sees it acknowledged.
type redeliveryRuntime struct {
	*vmruntime.MockRuntime
	sent []string
}

func (r *redeliveryRuntime) Invoke(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, errors.New("an agent-to-agent event never invokes")
}

func (r *redeliveryRuntime) Send(ctx context.Context, target string, event harnessstore.Event) (harnessstore.Receipt, error) {
	r.sent = append(r.sent, event.ID)
	return r.MockRuntime.Send(ctx, target, event)
}

func newRedeliveryLab(t *testing.T) *redeliveryLab {
	t.Helper()
	s, accounts, base, admin, _, first := catalogLab(t)
	u := createAccount(t, accounts, admin, "second-owner", "Second owner")
	second, err := s.Authenticate(t.Context(), issueAccountToken(t, accounts, admin, u, "second-token").Token)
	if err != nil {
		t.Fatal(err)
	}
	l := &redeliveryLab{s: s, tr: peerTransit(t, s), owners: map[string]Principal{}, vms: map[string]VMCaller{}}
	for i, owner := range []Principal{first, second} {
		e := reserveEnrollment(t, s, base, owner, false)
		if err = s.RecordProvisionedVolume(t.Context(), ProvisionedVolume{AgentID: e.AgentID, OperationID: e.OperationID, VolumeID: e.VolumeID,
			HostID: e.HostID, Device: 1, Inode: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, s, enrollmentBoot(t, s, e))
		if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		l.owners[e.AgentID] = owner
		if i == 0 {
			l.a = e.AgentID
		} else {
			l.b = e.AgentID
		}
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id IN ($1,$2)", l.a, l.b); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('mandate-sender',$1,'owner-instruction',10,10,clock_timestamp()+interval '1 hour')`, l.a); err != nil {
		t.Fatal(err)
	}
	if l.catalog, err = NewAgentCatalogWithTransit(accounts, "local", l.tr); err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), l.a, l.b)
	m.SetHandler(func(ctx context.Context, _ string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS peer_effects(id TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO peer_effects VALUES(?)", event.ID)
		return []byte(`{"received":true}`), err
	})
	l.rt = &redeliveryRuntime{MockRuntime: m}
	l.boot(t, l.a)
	l.boot(t, l.b)
	return l
}

// boot stands for an ordinary VM of the agent's current incarnation.
func (l *redeliveryLab) boot(t *testing.T, id string) {
	t.Helper()
	p, err := l.s.ClaimPlacement(t.Context(), id, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", p.Generation)
	if err = l.s.ConfirmPlacement(t.Context(), id, "local", "worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	l.vms[id] = VMCaller{AgentID: id, HostID: "local", VMID: vm, Generation: p.Generation}
}

func (l *redeliveryLab) key() string {
	l.keys++
	return fmt.Sprintf("key-%d", l.keys)
}

// ask sends a request from a to b; b's inbound mode is auto.
func (l *redeliveryLab) ask(t *testing.T, text string) string {
	t.Helper()
	in := peerSubmission(text)
	in.RecipientAgentID, in.MandateID = l.b, "mandate-sender"
	r, err := l.tr.SubmitFromVM(t.Context(), l.vms[l.a], l.key(), in)
	if err != nil || r.State != Delivering {
		t.Fatal("submit", r, err)
	}
	return r.RequestID
}

func (l *redeliveryLab) deliver(t *testing.T, mailbox string) {
	t.Helper()
	if err := l.tr.DispatchMailbox(t.Context(), mailbox, time.Minute, l.rt); err != nil {
		t.Fatal("dispatch", mailbox, err)
	}
}

func (l *redeliveryLab) answer(t *testing.T, request, outcome string) {
	t.Helper()
	in := capsuleprotocol.Reply{Outcome: outcome}
	if outcome == "completed" {
		in.Payload = &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "the answer"}}}
	}
	if _, err := l.tr.ReplyFromVM(t.Context(), l.vms[l.b], request, l.key(), in); err != nil {
		t.Fatal("reply", err)
	}
}

// replied is a request b answered and whose reply reached a.
func (l *redeliveryLab) replied(t *testing.T, text string) string {
	t.Helper()
	r := l.ask(t, text)
	l.deliver(t, mailboxFor(t, l.s, r, "request"))
	l.answer(t, r, "completed")
	l.deliver(t, mailboxFor(t, l.s, r, "reply"))
	return r
}

// restore restores agent id from an archive that lacks the outcomes of these
// mailboxes, as the worker does, and boots it again at its new incarnation.
// It returns the restore's losses, by mailbox.
func (l *redeliveryLab) restore(t *testing.T, id string, mailboxes ...string) map[string]RestoreLoss {
	t.Helper()
	vm := l.vms[id]
	retireEnrollmentBoot(t, l.s, Placement{AgentID: id, HostID: vm.HostID, Generation: vm.Generation})
	l.restores++
	activateRestore(t, l.s, id, l.restores)
	ids := make([]string, len(mailboxes))
	for i, m := range mailboxes {
		var err error
		if ids[i], err = outcomeID(id, m); err != nil {
			t.Fatal(err)
		}
	}
	losses, err := l.s.CompleteVolumeRestore(t.Context(), restoreID(l.restores), "local", declared(ids...))
	if err != nil || len(losses) != len(mailboxes) {
		t.Fatal("complete the restore", losses, err)
	}
	l.boot(t, id)
	byMailbox := map[string]RestoreLoss{}
	for _, loss := range losses {
		byMailbox[loss.MailboxID] = loss
	}
	return byMailbox
}

type mailboxState struct {
	State           string
	Attempts        int
	Reached, Outbox bool
	Window          time.Duration // from now to the delivery's deadline
}

func (l *redeliveryLab) mailbox(t *testing.T, id string) mailboxState {
	t.Helper()
	var m mailboxState
	var window float64
	if err := l.s.pool.QueryRow(t.Context(), `SELECT delivery_state,attempts,may_have_reached,
            EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=m.id),extract(epoch FROM expires_at-clock_timestamp())
        FROM agent_mailboxes m WHERE id=$1`, id).Scan(&m.State, &m.Attempts, &m.Reached, &m.Outbox, &window); err != nil {
		t.Fatal(err)
	}
	m.Window = time.Duration(window * float64(time.Second))
	return m
}

func (l *redeliveryLab) senderNotified(t *testing.T, request string) bool {
	t.Helper()
	var notified bool
	if err := l.s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", request).Scan(&notified); err != nil {
		t.Fatal(err)
	}
	return notified
}

// held reports whether the request's or the reply's content waits for a
// delivery: no retention runs, and it is not purged.
func (l *redeliveryLab) held(t *testing.T, request, column string) bool {
	t.Helper()
	var held bool
	if err := l.s.pool.QueryRow(t.Context(), `SELECT p.purge_after IS NULL AND p.delivered_at IS NULL AND p.purged_at IS NULL
        FROM transit_payloads p JOIN agent_requests r ON p.id=r.`+column+` WHERE r.id=$1`, request).Scan(&held); err != nil {
		t.Fatal(err)
	}
	return held
}

func wantDecision(t *testing.T, loss RestoreLoss, rerun, reason string) {
	t.Helper()
	if loss.InvocationID != "" || loss.Rerun != rerun || loss.SkipReason != reason {
		t.Fatalf("decision for %s: %q %q, want %q %q", loss.MailboxID, loss.Rerun, loss.SkipReason, rerun, reason)
	}
}

// A request that its recipient lost while it worked on it is delivered to
// it again (ADR 008): the same mailbox ID at its place, fresh attempts, the
// request's own deadline, its content held. The request goes back to
// DELIVERING, which its sender reads, then to PROCESSING once delivered, and
// the recipient answers it at its new incarnation. The sender's owner sees
// lost_at. Repeating the restore's last step decides nothing again.
func TestRestoreRedeliversALostRequest(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.ask(t, "a question b loses")
	request := mailboxFor(t, l.s, r, "request")
	l.deliver(t, request)
	assertRequestState(t, l.s, r, "PROCESSING")
	if l.held(t, r, "payload_ref") {
		t.Fatal("a delivered request's content has no retention")
	}
	losses := l.restore(t, l.b, request)
	wantDecision(t, losses[request], "queued", "")
	assertRequestState(t, l.s, r, "DELIVERING")
	m := l.mailbox(t, request)
	if m.State != "PENDING" || m.Attempts != 0 || m.Reached || !m.Outbox {
		t.Fatal("the request is not queued again", m)
	}
	var deadline bool
	if err := l.s.pool.QueryRow(t.Context(), `SELECT m.expires_at=r.expires_at FROM agent_mailboxes m JOIN agent_requests r ON r.id=m.ref_id
        WHERE m.id=$1`, request).Scan(&deadline); err != nil || !deadline {
		t.Fatal("the redelivery does not keep the request's deadline", err)
	}
	if !l.held(t, r, "payload_ref") {
		t.Fatal("the request's content is not held for its redelivery")
	}
	if st, err := l.tr.RequestStateFromVM(t.Context(), l.vms[l.a], r); err != nil || st.State != "DELIVERING" {
		t.Fatal("the sender's read", st, err)
	}
	view, err := l.catalog.Request(t.Context(), l.owners[l.a], r)
	body, _ := json.Marshal(view)
	if err != nil || view.State != "DELIVERING" || !strings.Contains(string(body), `"lost_at"`) {
		t.Fatal("the owner's read of a redelivered request", string(body), err)
	}

	sent := len(l.rt.sent)
	l.deliver(t, request)
	if len(l.rt.sent) != sent+1 || l.rt.sent[sent] != request {
		t.Fatal("the request was not sent again under its event ID", l.rt.sent[sent:])
	}
	assertRequestState(t, l.s, r, "PROCESSING")
	if l.held(t, r, "payload_ref") {
		t.Fatal("the redelivered request's retention did not start again")
	}
	l.answer(t, r, "completed")
	l.deliver(t, mailboxFor(t, l.s, r, "reply"))
	assertRequestState(t, l.s, r, "REPLIED")

	again, err := l.s.CompleteVolumeRestore(t.Context(), restoreID(l.restores), "local", nil)
	if err != nil || len(again) != 1 || again[0].Rerun != "queued" {
		t.Fatal("repeating the step", again, err)
	}
	assertRequestState(t, l.s, r, "REPLIED")
	if m = l.mailbox(t, request); m.State != "DELIVERED" {
		t.Fatal("repeating the step queued the request again", m)
	}
}

// A request in a final state never reopens (ADR 008): one its recipient
// answered, one that expired, and one past its deadline whose closure has
// not begun. Their lost request events are recorded with request_closed and
// are not sent again.
func TestRestoreDoesNotReopenAFinalRequest(t *testing.T) {
	l := newRedeliveryLab(t)
	answered := l.replied(t, "answered before the restore")
	expired := l.ask(t, "expired before the restore")
	l.deliver(t, mailboxFor(t, l.s, expired, "request"))
	late := l.ask(t, "past its deadline")
	l.deliver(t, mailboxFor(t, l.s, late, "request"))
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id IN ($1,$2)", expired, late); err != nil {
		t.Fatal(err)
	}
	if err := l.s.RequestExpiration(t.Context(), expired); err != nil {
		t.Fatal(err)
	}
	if err := l.s.ReconcileRequestClosure(t.Context(), expired, l.rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, l.s, expired, "EXPIRED")
	mailboxes := []string{mailboxFor(t, l.s, answered, "request"), mailboxFor(t, l.s, expired, "request"), mailboxFor(t, l.s, late, "request")}
	losses := l.restore(t, l.b, mailboxes...)
	for _, m := range mailboxes {
		wantDecision(t, losses[m], "skipped", "request_closed")
		if got := l.mailbox(t, m); got.State != "DELIVERED" || got.Outbox {
			t.Fatal("a final request's event was queued again", got)
		}
	}
	assertRequestState(t, l.s, answered, "REPLIED")
	assertRequestState(t, l.s, expired, "EXPIRED")
	assertRequestState(t, l.s, late, "PROCESSING")
}

// The sender lost a reply and a status (ADR 008): both are delivered to it
// again under their mailbox IDs, with a fresh delivery window. The requests
// keep their final states; sender_notified is false until each arrives
// again. The reply's content is held, then kept for the transit retention
// from its new delivery.
func TestRestoreRedeliversALostReplyAndStatus(t *testing.T) {
	l := newRedeliveryLab(t)
	answered := l.replied(t, "answered")
	declined := l.ask(t, "declined")
	l.deliver(t, mailboxFor(t, l.s, declined, "request"))
	l.answer(t, declined, "declined")
	status := mailboxFor(t, l.s, declined, "status")
	l.deliver(t, status)
	reply := mailboxFor(t, l.s, answered, "reply")
	if !l.senderNotified(t, answered) || !l.senderNotified(t, declined) {
		t.Fatal("the sender was not notified before the restore")
	}
	losses := l.restore(t, l.a, reply, status)
	wantDecision(t, losses[reply], "queued", "")
	wantDecision(t, losses[status], "queued", "")
	assertRequestState(t, l.s, answered, "REPLIED")
	assertRequestState(t, l.s, declined, "DECLINED")
	for _, id := range []string{reply, status} {
		m := l.mailbox(t, id)
		if m.State != "PENDING" || m.Attempts != 0 || m.Reached || !m.Outbox || m.Window < 7*24*time.Hour-time.Minute || m.Window > 7*24*time.Hour {
			t.Fatal("not queued again with a fresh window", id, m)
		}
	}
	if l.senderNotified(t, answered) || l.senderNotified(t, declined) {
		t.Fatal("the sender's store no longer holds them, but they count as received")
	}
	if !l.held(t, answered, "reply_ref") {
		t.Fatal("the reply's content is not held for its redelivery")
	}
	st, err := l.tr.RequestStateFromVM(t.Context(), l.vms[l.a], answered)
	if err != nil || st.State != "REPLIED" || st.Reply == nil || st.Reply.Content[0].Text != "the answer" {
		t.Fatal("the sender's read of its reply", st, err)
	}
	sent := len(l.rt.sent)
	l.deliver(t, reply)
	l.deliver(t, status)
	if got := l.rt.sent[sent:]; len(got) != 2 || got[0] != reply || got[1] != status {
		t.Fatal("not sent again under their event IDs", got)
	}
	if !l.senderNotified(t, answered) || !l.senderNotified(t, declined) || l.held(t, answered, "reply_ref") {
		t.Fatal("after the redeliveries")
	}
}

// When the requester can no longer invoke the sender, or the request's
// content is gone, the recipient does not get the request again: the request
// fails at once (lost_in_restore) and its sender is told. A reply whose
// content is purged is not delivered again; its sender reads why. Nothing is
// delivered again while the other agent is being deleted.
func TestRedeliveryIsSkippedWithAReason(t *testing.T) {
	t.Run("requester revoked", func(t *testing.T) {
		l := newRedeliveryLab(t)
		r := l.ask(t, "asked for a person who leaves")
		request := mailboxFor(t, l.s, r, "request")
		l.deliver(t, request)
		if _, err := l.s.pool.Exec(t.Context(), "UPDATE users SET status='disabled' WHERE id=$1", l.owners[l.a].ID); err != nil {
			t.Fatal(err)
		}
		losses := l.restore(t, l.b, request)
		wantDecision(t, losses[request], "skipped", "requester_revoked")
		l.failsAtOnce(t, r, request)
	})
	t.Run("request content purged", func(t *testing.T) {
		l := newRedeliveryLab(t)
		r := l.ask(t, "purged before the restore")
		request := mailboxFor(t, l.s, r, "request")
		l.deliver(t, request)
		l.purge(t, r, "payload_ref")
		losses := l.restore(t, l.b, request)
		wantDecision(t, losses[request], "skipped", "content_purged")
		l.failsAtOnce(t, r, request)
	})
	t.Run("reply content purged", func(t *testing.T) {
		l := newRedeliveryLab(t)
		r := l.replied(t, "a reply purged before the restore")
		reply := mailboxFor(t, l.s, r, "reply")
		l.purge(t, r, "reply_ref")
		losses := l.restore(t, l.a, reply)
		wantDecision(t, losses[reply], "skipped", "content_purged")
		if m := l.mailbox(t, reply); m.State != "DELIVERED" || m.Outbox {
			t.Fatal("a purged reply was queued again", m)
		}
		st, err := l.tr.RequestStateFromVM(t.Context(), l.vms[l.a], r)
		if err != nil || st.State != "REPLIED" || st.Reply != nil || st.Reason != "content_purged" {
			t.Fatal("the sender's read of a purged reply", st, err)
		}
	})
	t.Run("other agent being deleted", func(t *testing.T) {
		l := newRedeliveryLab(t)
		r := l.replied(t, "answered by an agent on its way out")
		reply := mailboxFor(t, l.s, r, "reply")
		if err := l.s.RequestDeletion(t.Context(), l.owners[l.b].ID, l.b); err != nil {
			t.Fatal(err)
		}
		losses := l.restore(t, l.a, reply)
		wantDecision(t, losses[reply], "skipped", "agent_unavailable")
		if m := l.mailbox(t, reply); m.State != "DELIVERED" || m.Outbox {
			t.Fatal("a reply whose author is being deleted was queued again", m)
		}
	})
}

// purge ends the retention of the request's or reply's content and purges it.
func (l *redeliveryLab) purge(t *testing.T, request, column string) {
	t.Helper()
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second'
        WHERE id=(SELECT `+column+` FROM agent_requests WHERE id=$1)`, request); err != nil {
		t.Fatal(err)
	}
	if _, err := l.tr.PurgeExpired(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}

// failsAtOnce checks that a request its recipient lost for good is closed as
// failed, without being delivered again, and that its sender is told.
func (l *redeliveryLab) failsAtOnce(t *testing.T, request, mailbox string) {
	t.Helper()
	if m := l.mailbox(t, mailbox); m.State != "DELIVERED" || m.Outbox {
		t.Fatal("the request was queued again", m)
	}
	var final, reason string
	if err := l.s.pool.QueryRow(t.Context(), "SELECT final_state,reason FROM request_closures WHERE request_id=$1", request).Scan(&final, &reason); err != nil ||
		final != "FAILED" || reason != "lost_in_restore" {
		t.Fatal("the request's closure", final, reason, err)
	}
	if err := l.s.ReconcileRequestClosure(t.Context(), request, l.rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, l.s, request, "FAILED")
	l.deliver(t, mailboxFor(t, l.s, request, "status"))
}

// The sender's owner cancels a redelivered request like any active request:
// the redelivery never reaches the recipient, and the sender is told.
func TestARedeliveredRequestCanBeCanceled(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.ask(t, "canceled while queued again")
	request := mailboxFor(t, l.s, r, "request")
	l.deliver(t, request)
	wantDecision(t, l.restore(t, l.b, request)[request], "queued", "")
	if err := l.s.RequestCancellation(t.Context(), l.owners[l.a].ID, r); err != nil {
		t.Fatal(err)
	}
	if err := l.s.ReconcileRequestClosure(t.Context(), r, l.rt); err != nil {
		t.Fatal(err)
	}
	assertRequestState(t, l.s, r, "CANCELED")
	if m := l.mailbox(t, request); m.State != "CANCELED" || m.Outbox {
		t.Fatal("the canceled redelivery", m)
	}
	sent := len(l.rt.sent)
	l.deliver(t, mailboxFor(t, l.s, r, "status"))
	if got := l.rt.sent[sent:]; len(got) != 1 || got[0] == request {
		t.Fatal("the recipient got the canceled request", got)
	}
}

// Both parties restored from archives older than an answered exchange, one
// after the other (ADR 008): the recipient does not get the final request
// again, and the sender gets its reply again.
func TestBothPartiesRestored(t *testing.T) {
	l := newRedeliveryLab(t)
	r := l.replied(t, "answered before both restores")
	request, reply := mailboxFor(t, l.s, r, "request"), mailboxFor(t, l.s, r, "reply")
	wantDecision(t, l.restore(t, l.b, request)[request], "skipped", "request_closed")
	wantDecision(t, l.restore(t, l.a, reply)[reply], "queued", "")
	assertRequestState(t, l.s, r, "REPLIED")
	sent := len(l.rt.sent)
	l.deliver(t, reply)
	if got := l.rt.sent[sent:]; len(got) != 1 || got[0] != reply || !l.senderNotified(t, r) {
		t.Fatal("the sender did not get its reply again", got)
	}
	if m := l.mailbox(t, request); m.State != "DELIVERED" {
		t.Fatal("the recipient's final request was queued again", m)
	}
}
