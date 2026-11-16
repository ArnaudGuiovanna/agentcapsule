package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Redeliveries of the agent-to-agent events that a restore lost (REC-02, ADR
// 008, migration 0033). The restore's last transaction decides, for each lost
// request, reply or status that PostgreSQL recorded as delivered, whether it
// is delivered again to the restored agent under the same mailbox ID, or
// skipped with a reason. The request itself never reopens: a request in a
// final state keeps it, and only a request its recipient was still working
// on goes back to DELIVERING. The delivery path is the ordinary one.

// Why a lost agent-to-agent event is not delivered again
// (peer_redeliveries.skip_reason). SkipAgentUnavailable and
// SkipRequesterRevoked are shared with the reruns of invocations.
const (
	SkipRequestClosed = "request_closed"
	SkipContentPurged = "content_purged"
)

// peerKinds are the mailbox kinds of agent-to-agent events.
const peerKinds = `('request','reply','status')`

// lockRestorePeers locks the restored agent and the other party of each lost
// agent-to-agent event in declared, in the order of every other path
// (lockAgents), before restorePlan locks the agent again: a deletion of a
// party must not commit between the decision and the requeue. It reads the
// mailboxes without locks: a request's parties never change.
func lockRestorePeers(ctx context.Context, tx pgx.Tx, restoreID string, declared []DeclaredLoss) error {
	if len(declared) == 0 {
		return nil
	}
	var agentID string
	err := tx.QueryRow(ctx, "SELECT agent_id FROM volume_restores WHERE restore_id=$1", restoreID).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // restorePlan reports it
	}
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(declared))
	for _, l := range declared {
		wanted[l.OutcomeID] = true
	}
	rows, err := tx.Query(ctx, `SELECT m.id,r.sender_agent_id,r.recipient_agent_id FROM agent_mailboxes m
        JOIN agent_requests r ON r.id=m.ref_id WHERE m.dest_agent_id=$1 AND m.kind IN `+peerKinds, agentID)
	if err != nil {
		return err
	}
	ids := []string{agentID}
	for rows.Next() {
		var mailbox, sender, recipient string
		if err = rows.Scan(&mailbox, &sender, &recipient); err != nil {
			rows.Close()
			return err
		}
		id, err := outcomeID(agentID, mailbox)
		if err != nil {
			rows.Close()
			return err
		}
		if wanted[id] {
			ids = append(ids, sender, recipient)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	_, err = lockAgents(ctx, tx, ids...)
	return err
}

// scheduleRedeliveries decides the redelivery of each agent-to-agent event
// that restore restoreID lost, in the order of the agent's queue. It runs in
// the transaction that copies the losses and puts the volume back in
// service, with the parties locked (lockRestorePeers). A loss whose rerun the
// authority recorded is not due. An event whose delivery is still open
// simply runs again through its own retry; one closed without delivery stays
// closed. Neither gets a decision.
func scheduleRedeliveries(ctx context.Context, tx pgx.Tx, restoreID string, recorded map[string]bool) error {
	rows, err := tx.Query(ctx, `SELECT l.outcome_id,l.mailbox_id FROM volume_restore_losses l
        JOIN agent_mailboxes m ON m.id=l.mailbox_id WHERE l.restore_id=$1 AND l.invocation_id IS NULL
        AND m.kind IN `+peerKinds+` ORDER BY m.seq`, restoreID)
	if err != nil {
		return err
	}
	var lost [][2]string
	for rows.Next() {
		var outcome, mailbox string
		if err = rows.Scan(&outcome, &mailbox); err != nil {
			rows.Close()
			return err
		}
		if !recorded[outcome] {
			lost = append(lost, [2]string{outcome, mailbox})
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, l := range lost {
		if err = decideRedelivery(ctx, tx, restoreID, l[0], l[1]); err != nil {
			return err
		}
	}
	return nil
}

// decideRedelivery queues the lost event of mailbox again, or records why
// not (ADR 008):
//   - agent_unavailable: a party it needs is being deleted; the deletion
//     cancels or ends what remains.
//   - request_closed: a request event whose request is final, closing or past
//     its deadline. A final request never reopens.
//   - requester_revoked: the person the request was sent for can no longer
//     invoke the sender. The recipient would run new work for them.
//   - content_purged: the request's or reply's content is no longer kept.
//
// A request its recipient will not get again, while it is still active,
// fails at once (lost_in_restore): its sender is told, rather than waiting for
// its deadline.
func decideRedelivery(ctx context.Context, tx pgx.Tx, restoreID, outcome, mailbox string) error {
	var kind, delivery, requestID string
	if err := tx.QueryRow(ctx, "SELECT kind,delivery_state,ref_id FROM agent_mailboxes WHERE id=$1 FOR UPDATE", mailbox).
		Scan(&kind, &delivery, &requestID); err != nil {
		return err
	}
	if delivery != "DELIVERED" {
		return nil
	}
	r := requestRow{ID: requestID}
	var mandate string
	var expired, closing bool
	if err := tx.QueryRow(ctx, `SELECT sender_agent_id,recipient_agent_id,state,payload_ref,reply_ref,mandate_id,
            expires_at<=clock_timestamp(),EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)
        FROM agent_requests WHERE id=$1 FOR UPDATE`, requestID).
		Scan(&r.Sender, &r.Recipient, &r.State, &r.Payload, &r.ReplyPayload, &mandate, &expired, &closing); err != nil {
		return err
	}
	// Already locked by lockRestorePeers: this reads their current phases.
	agents, err := lockAgents(ctx, tx, r.Sender, r.Recipient)
	if err != nil {
		return err
	}
	needed := []string{r.Sender, r.Recipient}
	if kind == "status" {
		needed = needed[:1]
	}
	reason := ""
	for _, id := range needed {
		if agents[id].Phase != "LIVE" {
			reason = SkipAgentUnavailable
		}
	}
	if reason == "" && kind == "request" && (r.State != "PROCESSING" || closing || expired) {
		reason = SkipRequestClosed
	}
	if reason == "" && kind == "request" {
		requester, err := peerRequester(ctx, tx, mandate, agents[r.Sender])
		if err != nil {
			return err
		}
		if ok, err := mayInvokeAgain(ctx, tx, agents[r.Sender], requester); err != nil {
			return err
		} else if !ok {
			reason = SkipRequesterRevoked
		}
	}
	content := r.Payload
	if kind == "reply" {
		content = r.ReplyPayload
	}
	if reason == "" && kind != "status" {
		if gone, err := contentGone(ctx, tx, content); err != nil {
			return err
		} else if gone {
			reason = SkipContentPurged
		}
	}
	if reason != "" {
		if kind == "request" && (reason == SkipRequesterRevoked || reason == SkipContentPurged) {
			if err = beginClosure(ctx, tx, r, "FAILED", "lost_in_restore"); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO peer_redeliveries(restore_id,outcome_id,mailbox_id,request_id,kind,state,skip_reason)
            VALUES($1,$2,$3,$4,$5,'skipped',$6)`, restoreID, outcome, mailbox, requestID, kind, reason)
		return err
	}
	return queueRedelivery(ctx, tx, restoreID, outcome, mailbox, kind, r, content)
}

// queueRedelivery puts a delivered event back in its destination's queue,
// under the same mailbox ID and at its place: what the agent lost reaches it
// again before newer work, in its first order. It gets fresh attempts. A
// request keeps its own deadline and goes back to DELIVERING, which is what
// the platform knows: its recipient no longer holds it. A reply or status
// gets a fresh delivery window, as a new one does, and its sender no longer
// counts as notified. Content waits, without retention, for the delivery.
func queueRedelivery(ctx context.Context, tx pgx.Tx, restoreID, outcome, mailbox, kind string, r requestRow, content string) error {
	window := "expires_at"
	if kind == "request" {
		if _, err := tx.Exec(ctx, "UPDATE agent_requests SET state='DELIVERING' WHERE id=$1 AND state='PROCESSING'", r.ID); err != nil {
			return err
		}
	} else {
		window = "clock_timestamp()+interval '7 days'"
		if _, err := tx.Exec(ctx, "UPDATE agent_requests SET sender_notified=false WHERE id=$1", r.ID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET delivery_state='PENDING',attempts=0,lease_token='',lease_until=NULL,
        dispatch_authorized=false,may_have_reached=false,closing=false,expires_at=`+window+` WHERE id=$1`, mailbox); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES($1,$2) ON CONFLICT (mailbox_id) DO NOTHING", newID("out"), mailbox); err != nil {
		return err
	}
	if kind != "status" {
		if err := holdInput(ctx, tx, content); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO peer_redeliveries(restore_id,outcome_id,mailbox_id,request_id,kind,state)
        VALUES($1,$2,$3,$4,$5,'queued')`, restoreID, outcome, mailbox, r.ID, kind)
	return err
}

// peerRequester is the person a request was sent for: the owner of a
// person's agent, or, between agents of an organization, the requester of
// the invocation whose mandate the request used (delegationOwners). Empty
// when none is known.
func peerRequester(ctx context.Context, tx pgx.Tx, mandate string, sender agent) (string, error) {
	if sender.Tenant == "" {
		return sender.Owner, nil
	}
	var requester string
	err := tx.QueryRow(ctx, `SELECT coalesce(o.requested_by_principal_id,'') FROM owner_instructions i
        JOIN platform_operations o ON o.id=i.operation_id WHERE i.mandate_id=$1`, mandate).Scan(&requester)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return requester, err
}

// contentGone reports whether a request's or reply's content is no longer
// kept: purged, or past its retention. It locks the content, so that the
// purge cannot take it while its redelivery is queued. A reference without
// private content (legacy metadata) has none to lose.
func contentGone(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	var gone bool
	err := tx.QueryRow(ctx, `SELECT purged_at IS NOT NULL OR coalesce(purge_after<=clock_timestamp(),false)
        FROM transit_payloads WHERE id=$1 FOR UPDATE`, id).Scan(&gone)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return gone, err
}

// requestLostAt is the time of the newest loss of one of a request's events
// in a restore, or nil.
func requestLostAt(ctx context.Context, tx pgx.Tx, requestID string) (*time.Time, error) {
	var lostAt *time.Time
	err := tx.QueryRow(ctx, `SELECT max(l.declared_at) FROM volume_restore_losses l JOIN agent_mailboxes m ON m.id=l.mailbox_id
        WHERE m.ref_id=$1 AND m.kind IN `+peerKinds, requestID).Scan(&lostAt)
	return lostAt, err
}
