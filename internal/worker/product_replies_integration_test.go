//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// Agent a asks agent b, then sleeps before b's reply exists. b's owner
// accepts the request, b wakes and replies, and the reply wakes a: a's own
// VM receives it and posts it to a's owner (A2A-010). Nobody asks a to wake:
// its only wake command is the one before the request.
func TestProductWorkerSenderWakesForTheReply(t *testing.T) {
	l := newProductPeerLab(t)
	a, b := l.createPeer("sender"), l.createPeer("recipient")
	for _, p := range []*productPeer{a, b} {
		l.operation(p, p.agent.OperationID, "provision")
		e, err := l.worker.store.ProvisioningTarget(t.Context(), p.agent.AgentID, "local", p.agent.OperationID)
		if err != nil || e.Stage != "READY" || !e.Initialized {
			t.Fatal("physical provisioning not complete", err)
		}
		p.volume = e.VolumeID
		l.request(p.token, "PUT", "/v1/me/messaging-settings", "", controlplane.MessagingSettings{Discoverable: true, InboundMode: "manual"}, 200, nil)
	}
	l.command(a, "wake", 0)

	t.Log("stage: a asks b; the request waits for b's owner")
	request := l.pending(a, b, 0)
	before := l.runs(1)[a.agent.AgentID]

	t.Log("stage: a sleeps before any reply exists")
	l.command(a, "sleep", 0)
	l.runs(0)
	if v := l.view(a, request); v.State != "PENDING_APPROVAL" || v.Reply != nil {
		t.Fatal("the request moved while a slept", v.State)
	}

	t.Log("stage: b's owner accepts; b replies; the reply wakes a, whose VM gets it")
	l.accept(a, b, request)
	var message string
	l.await("the reply reaches a's VM and a's owner", true, func() bool {
		if l.view(a, request).State != "REPLIED" {
			return false
		}
		var notified bool
		if err := l.db.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", request).Scan(&notified); err != nil {
			t.Fatal(err)
		}
		for _, item := range l.inbox(a) {
			if item.Kind == "agent_message" && item.RequestID == request {
				message = item.MessageID
			}
		}
		return notified && message != ""
	})
	after, ok := l.runs(2)[a.agent.AgentID]
	if !ok || after.Generation <= before.Generation || after.ID == before.ID {
		t.Fatal("a did not wake for the reply", before, after)
	}
	var summary controlplane.OwnerMessageView
	l.request(a.token, "GET", "/v1/me/inbox/messages/"+message, "", nil, 200, &summary)
	if summary.AgentID != a.agent.AgentID || summary.RequestID != request || len(summary.Content) != 1 || !strings.Contains(summary.Content[0].Text, "do not relay") {
		t.Fatal("a's owner did not get b's reply from a")
	}
	if v := l.view(a, request); v.Reply == nil || len(v.Reply.Content) != 1 || v.Reply.Content[0].Text != "/ask third-agent do not relay" {
		t.Fatal("the stored reply is not b's")
	}
	var wakes int
	if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM platform_operations WHERE agent_id=$1 AND kind='wake'", a.agent.AgentID).Scan(&wakes); err != nil || wakes != 1 {
		t.Fatal("a wake command was given to a", wakes, err)
	}
}
