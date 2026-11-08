package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

// PostOwnerFromVM commits the private body, owner notification and stable
// receipt together. It never creates or renews a mandate. Linked summaries are
// bound to both parties for revocation, but readable only by this agent's owner.
func (t *Transit) PostOwnerFromVM(ctx context.Context, caller VMCaller, key string, in capsuleprotocol.OwnerPost) (capsuleprotocol.OwnerPostReceipt, error) {
	var result capsuleprotocol.OwnerPostReceipt
	if requireIdentity(caller.AgentID, key) != nil || in.Validate() != nil {
		return result, ErrInput
	}
	body, err := json.Marshal(in)
	if err != nil {
		return result, err
	}
	defer clear(body)
	hash := sha256.Sum256(body)
	tx, err := t.store.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	var agents map[string]agent
	parties := []string{caller.AgentID}
	var request requestRow
	if in.RequestID != "" {
		request, agents, err = lockRequest(ctx, tx, in.RequestID, caller.AgentID)
		if err == nil && request.Sender != caller.AgentID {
			return result, ErrNotFound
		}
		parties = []string{request.Sender, request.Recipient}
	} else {
		agents, err = lockAgents(ctx, tx, caller.AgentID)
	}
	if err != nil {
		return result, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return result, err
	}
	var oldHash []byte
	err = tx.QueryRow(ctx, "SELECT id,body_hash FROM owner_messages WHERE agent_id=$1 AND idempotency_key=$2", caller.AgentID, key).Scan(&result.MessageID, &oldHash)
	if err == nil {
		if !bytes.Equal(oldHash, hash[:]) {
			return capsuleprotocol.OwnerPostReceipt{}, ErrConflict
		}
		result.Replayed = true
		return result, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if in.RequestID != "" && request.State != "REPLIED" {
		return result, ErrTransition
	}
	result.MessageID = newID("msg")
	payload, err := t.put(ctx, tx, "owner_message", result.MessageID, parties, body)
	if err != nil {
		return capsuleprotocol.OwnerPostReceipt{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO owner_messages(id,agent_id,owner_user_id,request_id,payload_id,idempotency_key,body_hash)
        VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7)`, result.MessageID, caller.AgentID, agents[caller.AgentID].Owner, in.RequestID, payload.ID, key, hash[:])
	if err != nil {
		return capsuleprotocol.OwnerPostReceipt{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO inbox_items(id,user_id,kind,owner_message_id) VALUES($1,$2,'agent_message',$3)`, newID("inb"), agents[caller.AgentID].Owner, result.MessageID)
	if err != nil {
		return capsuleprotocol.OwnerPostReceipt{}, err
	}
	return result, commit(ctx, tx)
}

type OwnerMessageView struct {
	ID        string                        `json:"id"`
	AgentID   string                        `json:"agent_id"`
	RequestID string                        `json:"request_id,omitempty"`
	Content   []capsuleprotocol.TextContent `json:"content"`
	CreatedAt time.Time                     `json:"created_at"`
}

// OwnerMessage intentionally does not share Request's two-owner read access.
// The first successful read starts retention; repeats do not extend it.
func (c *AgentCatalog) OwnerMessage(ctx context.Context, p Principal, id string) (OwnerMessageView, error) {
	var result OwnerMessageView
	if c.transit == nil {
		return result, ErrTransitKey
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", "inbox:own"); err != nil {
		return result, err
	}
	var payload string
	err = tx.QueryRow(ctx, `SELECT m.id,m.agent_id,coalesce(m.request_id,''),m.payload_id,m.created_at
        FROM owner_messages m JOIN transit_payloads t ON t.id=m.payload_id AND t.kind='owner_message' AND t.ref_id=m.id
        WHERE m.id=$1 AND m.owner_user_id=$2`, id, p.ID).Scan(&result.ID, &result.AgentID, &result.RequestID, &payload, &result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	parties, err := payloadParties(ctx, tx, payload)
	if err != nil {
		return result, err
	}
	ownerMatches := false
	for _, party := range parties {
		if party.Agent == result.AgentID && party.Owner == p.ID {
			ownerMatches = true
		}
	}
	if !ownerMatches {
		return OwnerMessageView{}, ErrNotFound
	}
	body, err := c.transit.read(ctx, tx, payload, parties)
	if err != nil {
		return result, err
	}
	defer clear(body)
	var in capsuleprotocol.OwnerPost
	if json.Unmarshal(body, &in) != nil || in.Validate() != nil || in.RequestID != result.RequestID {
		return OwnerMessageView{}, ErrTransitPayload
	}
	if err = c.transit.delivered(ctx, tx, payload); err != nil {
		return result, err
	}
	result.Content = in.Content
	return result, commit(ctx, tx)
}
