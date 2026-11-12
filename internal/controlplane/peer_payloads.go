package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

type admissionPayload struct {
	transit *Transit
	body    []byte
}

// The private body digest, not a fresh ciphertext ID/nonce, determines replay.
// Legacy metadata admission has a distinct hash domain and cannot alias it.
func admissionHash(input any, payload *admissionPayload) ([32]byte, error) {
	if payload == nil {
		return requestHash(input)
	}
	return requestHash(struct {
		Domain      string
		Input       any
		ContentHash [32]byte
	}{"private-transit-v1", input, sha256.Sum256(payload.body)})
}

type peerContent struct {
	Subject       string                      `json:"subject,omitempty"`
	CorrelationID string                      `json:"correlation_id,omitempty"`
	Payload       capsuleprotocol.PeerPayload `json:"payload"`
}

func encodePeerContent(content peerContent) ([]byte, error) {
	if content.Payload.Validate() != nil || !utf8.ValidString(content.Subject) || utf8.RuneCountInString(content.Subject) > 200 || strings.ContainsRune(content.Subject, 0) || len(content.CorrelationID) > 100 {
		return nil, ErrInput
	}
	if content.CorrelationID != "" && !catalogName(content.CorrelationID) {
		return nil, ErrInput
	}
	body, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	if len(body) > 64*1024 {
		clear(body)
		return nil, ErrInput
	}
	return body, nil
}

// SubmitFromVM uses the existing authorization/mandate/idempotency transaction.
// The client supplies content, never a reference to another party's payload.
func (t *Transit) SubmitFromVM(ctx context.Context, caller VMCaller, key string, in capsuleprotocol.Submission) (Receipt, error) {
	if in.Payload == nil || in.PayloadRef != "" || in.PayloadHash != ([32]byte{}) {
		return Receipt{}, ErrInput
	}
	body, err := encodePeerContent(peerContent{Subject: in.Subject, CorrelationID: in.CorrelationID, Payload: *in.Payload})
	if err != nil {
		return Receipt{}, err
	}
	defer clear(body)
	input := Submission{RecipientAgentID: in.RecipientAgentID, MandateID: in.MandateID, ExpiresAt: in.ExpiresAt}
	return t.store.submitPayload(ctx, caller.AgentID, key, input, &caller, &admissionPayload{t, body})
}

func (t *Transit) ReplyFromVM(ctx context.Context, caller VMCaller, id, key string, in capsuleprotocol.Reply) (Receipt, error) {
	if in.PayloadRef != "" || in.PayloadHash != ([32]byte{}) {
		return Receipt{}, ErrInput
	}
	if in.Outcome == "declined" {
		if in.Payload != nil {
			return Receipt{}, ErrInput
		}
		return t.store.replyToRequest(ctx, caller.AgentID, id, key, Reply{Outcome: "declined"}, &caller)
	}
	if in.Outcome != "completed" || in.Payload == nil {
		return Receipt{}, ErrInput
	}
	body, err := encodePeerContent(peerContent{Payload: *in.Payload})
	if err != nil {
		return Receipt{}, err
	}
	defer clear(body)
	return t.store.replyPayload(ctx, caller.AgentID, id, key, Reply{Outcome: in.Outcome}, &caller, &admissionPayload{t, body})
}

// Resolve only a current, authorized delivery; all parties are locked in the
// existing order. The resulting plaintext is transient and has no new mandate.
func (t *Transit) resolveDelivery(ctx context.Context, attempt DeliveryAttempt) (harnessstore.Event, error) {
	var empty harnessstore.Event
	tx, err := t.store.begin(ctx)
	if err != nil {
		return empty, err
	}
	defer rollback(tx)
	m, r, agents, err := lockMailbox(ctx, tx, attempt.ID)
	if err != nil {
		return empty, err
	}
	if err = isHead(ctx, tx, m); err != nil {
		return empty, err
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT lease_token=$2 AND lease_until>clock_timestamp() AND dispatch_authorized
        AND NOT closing AND expires_at>clock_timestamp() FROM agent_mailboxes WHERE id=$1`, m.ID, attempt.Token).Scan(&current)
	if err != nil {
		return empty, err
	}
	if !current {
		return empty, ErrLeaseLost
	}
	if m.Destination != attempt.Destination || r.ID != attempt.RequestID {
		return empty, ErrTransition
	}
	if agents[m.Destination].Phase != "LIVE" {
		return empty, ErrUnavailable
	}
	if m.Kind == "status" {
		return attempt.Envelope, commit(ctx, tx)
	}
	if agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE" {
		return empty, ErrUnavailable
	}
	if m.Kind == "request" {
		var closing bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)", r.ID).Scan(&closing); err != nil {
			return empty, err
		}
		if closing {
			return empty, ErrClosurePending
		}
		if r.State != "DELIVERING" {
			return empty, ErrTransition
		}
	} else if m.Kind != "reply" || r.State != "REPLIED" {
		return empty, ErrTransition
	}
	content, err := t.readPeerContent(ctx, tx, r, agents, m.Kind)
	if err != nil {
		return empty, err
	}
	encoded, err := json.Marshal(capsuleprotocol.PeerEvent{Kind: m.Kind, RequestID: r.ID, SenderAgentID: r.Sender, RecipientAgentID: r.Recipient, Sequence: m.Sequence, Subject: content.Subject, CorrelationID: content.CorrelationID, Payload: content.Payload})
	if err != nil {
		return empty, err
	}
	if err = commit(ctx, tx); err != nil {
		clear(encoded)
		return empty, err
	}
	return harnessstore.Event{ID: m.ID, Subjects: []string{"agent/" + r.Sender, "agent/" + r.Recipient, "request/" + r.ID, "event/" + m.ID}, Body: encoded}, nil
}

// readPeerContent requires the caller to own both participant locks and to have
// separately authorized its role (owner read or current dispatch permission).
func (t *Transit) readPeerContent(ctx context.Context, tx pgx.Tx, r requestRow, agents map[string]agent, kind string) (peerContent, error) {
	if kind != "request" && kind != "reply" {
		return peerContent{}, ErrInput
	}
	if agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE" {
		return peerContent{}, ErrNotFound
	}
	ref, hash := r.Payload, r.PayloadHash
	if kind == "reply" {
		ref, hash = r.ReplyPayload, r.ReplyHash
	}
	// Bind both kind/reference and the exact set of current participants before
	// decryption. Swapping valid payload references must never reveal content.
	owners, err := peerOwners(ctx, tx, r, agents)
	if err != nil {
		return peerContent{}, err
	}
	var bound bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM transit_payloads WHERE id=$1 AND kind=$2 AND ref_id=$3 AND content_hash=$4)
        AND (SELECT count(*)=2 FROM transit_parties WHERE payload_id=$1)
        AND EXISTS(SELECT 1 FROM transit_parties WHERE payload_id=$1 AND agent_id=$5 AND owner_user_id=$6)
        AND EXISTS(SELECT 1 FROM transit_parties WHERE payload_id=$1 AND agent_id=$7 AND owner_user_id=$8)`,
		ref, kind, r.ID, hash, r.Sender, owners[r.Sender], r.Recipient, owners[r.Recipient]).Scan(&bound)
	if err != nil {
		return peerContent{}, err
	}
	if !bound {
		return peerContent{}, ErrTransitPayload
	}
	parties := []transitParty{{r.Sender, owners[r.Sender]}, {r.Recipient, owners[r.Recipient]}}
	if parties[0].Agent > parties[1].Agent {
		parties[0], parties[1] = parties[1], parties[0]
	}
	body, err := t.read(ctx, tx, ref, parties)
	if err != nil {
		return peerContent{}, err
	}
	defer clear(body)
	actual := sha256.Sum256(body)
	if !bytes.Equal(actual[:], hash) {
		return peerContent{}, ErrTransitPayload
	}
	var content peerContent
	if json.Unmarshal(body, &content) != nil || content.Payload.Validate() != nil {
		return peerContent{}, ErrTransitPayload
	}
	return content, nil
}

// peerOwners names the identity each party of a request is bound to: the owner
// of an agent of a person, or, between agents of an organization, the person
// whose invocation granted the request's mandate, who must still belong to the
// organization (D-02).
func peerOwners(ctx context.Context, tx pgx.Tx, r requestRow, agents map[string]agent) (map[string]string, error) {
	sender, recipient := agents[r.Sender], agents[r.Recipient]
	if sender.Tenant == "" && recipient.Tenant == "" {
		return map[string]string{r.Sender: sender.Owner, r.Recipient: recipient.Owner}, nil
	}
	var mandate string
	if err := tx.QueryRow(ctx, "SELECT mandate_id FROM agent_requests WHERE id=$1", r.ID).Scan(&mandate); err != nil {
		return nil, err
	}
	owners, err := delegationOwners(ctx, tx, mandate, sender, recipient)
	if errors.Is(err, ErrMandate) {
		return nil, ErrTransitPayload
	}
	if err != nil {
		return nil, err
	}
	for id, owner := range owners {
		var known bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals WHERE tenant_id=$1 AND id=$2)`, agents[id].Tenant, owner).Scan(&known); err != nil {
			return nil, err
		}
		if !known {
			return nil, ErrNotFound
		}
	}
	return owners, nil
}
