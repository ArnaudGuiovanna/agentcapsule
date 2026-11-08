package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

type MessagingSettings struct {
	Discoverable bool   `json:"discoverable"`
	InboundMode  string `json:"inbound_mode"`
}

// Settings reauthorizes the owner inside the same transaction as the preference
// update. Publication/search must continue to postcheck this SQL source of truth.
func (c *AgentCatalog) MessagingSettings(ctx context.Context, p Principal, update *MessagingSettings) (MessagingSettings, error) {
	var result MessagingSettings
	if update != nil && update.InboundMode != "manual" && update.InboundMode != "auto" {
		return result, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", "agent:own"); err != nil {
		return result, err
	}
	var id string
	err = tx.QueryRow(ctx, "SELECT id FROM agents WHERE owner_user_id=$1", p.ID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return result, err
	}
	a, ok := agents[id]
	if !ok || a.Owner != p.ID {
		return result, ErrNotFound
	}
	result = MessagingSettings{a.Visible, a.Mode}
	if update != nil {
		if a.Phase != "LIVE" {
			return result, ErrUnavailable
		}
		if _, err = tx.Exec(ctx, "UPDATE agents SET discoverable=$2,inbound_mode=$3 WHERE id=$1", id, update.Discoverable, update.InboundMode); err != nil {
			return result, err
		}
		result = *update
	}
	return result, commit(ctx, tx)
}

type OwnerRequestReceipt struct {
	RequestID string `json:"request_id"`
	State     State  `json:"state"`
	Replayed  bool   `json:"-"`
}

func (c *AgentCatalog) DecideRequest(ctx context.Context, p Principal, id, key string, accept bool) (OwnerRequestReceipt, error) {
	var r Receipt
	var err error
	if accept {
		r, err = c.accounts.store.acceptOwner(ctx, p.ID, id, key, &p)
	} else {
		r, err = c.accounts.store.declineOwner(ctx, p.ID, id, key, &p)
	}
	return OwnerRequestReceipt{r.RequestID, r.State, r.Replayed}, err
}

type InboxItem struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	RequestID string    `json:"request_id,omitempty"`
	MessageID string    `json:"message_id,omitempty"`
	State     string    `json:"state,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func validRequestState(state string) bool {
	switch state {
	case "", "PENDING_APPROVAL", "DELIVERING", "PROCESSING", "REPLIED", "DECLINED", "EXPIRED", "CANCELED", "FAILED":
		return true
	}
	return false
}

// Inbox is a bounded metadata view. Preview/content goes through the separately
// authorized party read; administrative account access never includes it.
func (c *AgentCatalog) Inbox(ctx context.Context, p Principal, after, state string, limit int) ([]InboxItem, error) {
	if limit < 1 || limit > 100 || len(after) > 100 || !validRequestState(state) {
		return nil, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", "inbox:own"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT i.id,i.kind,coalesce(i.ref_id,m.request_id,''),coalesce(i.owner_message_id,''),coalesce(r.state,''),i.created_at FROM inbox_items i
        LEFT JOIN agent_requests r ON r.id=i.ref_id
        LEFT JOIN owner_messages m ON m.id=i.owner_message_id WHERE i.user_id=$1 AND ($3='' OR r.state=$3)
        AND ($2='' OR (i.created_at,i.id)<(SELECT created_at,id FROM inbox_items WHERE id=$2 AND user_id=$1))
        ORDER BY i.created_at DESC,i.id DESC LIMIT $4`, p.ID, after, state, limit)
	if err != nil {
		return nil, err
	}
	result := []InboxItem{}
	for rows.Next() {
		var item InboxItem
		if err = rows.Scan(&item.ID, &item.Kind, &item.RequestID, &item.MessageID, &item.State, &item.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, item)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, commit(ctx, tx)
}

type RequestView struct {
	ID               string                       `json:"id"`
	SenderAgentID    string                       `json:"sender_agent_id"`
	RecipientAgentID string                       `json:"recipient_agent_id"`
	State            string                       `json:"state"`
	ClosureState     string                       `json:"closure_state,omitempty"`
	ExpiresAt        time.Time                    `json:"expires_at"`
	Subject          string                       `json:"subject,omitempty"`
	CorrelationID    string                       `json:"correlation_id,omitempty"`
	Payload          *capsuleprotocol.PeerPayload `json:"payload,omitempty"`
	Reply            *capsuleprotocol.PeerPayload `json:"reply,omitempty"`
}

func (c *AgentCatalog) Request(ctx context.Context, p Principal, id string) (RequestView, error) {
	var result RequestView
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
	r, agents, err := lockRequest(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if agents[r.Sender].Owner != p.ID && agents[r.Recipient].Owner != p.ID {
		return result, ErrNotFound
	}
	result = RequestView{ID: r.ID, SenderAgentID: r.Sender, RecipientAgentID: r.Recipient, State: r.State, ExpiresAt: r.Deadline}
	if err = tx.QueryRow(ctx, "SELECT coalesce((SELECT phase FROM request_closures WHERE request_id=$1),'')", id).Scan(&result.ClosureState); err != nil {
		return RequestView{}, err
	}
	content, err := c.transit.readPeerContent(ctx, tx, r, agents, "request")
	if err == nil {
		result.Subject = content.Subject
		result.CorrelationID = content.CorrelationID
		result.Payload = &content.Payload
	} else if !errors.Is(err, ErrNotFound) {
		return RequestView{}, err
	}
	if r.ReplyPayload != "" {
		content, err = c.transit.readPeerContent(ctx, tx, r, agents, "reply")
		if err == nil {
			result.Reply = &content.Payload
		} else if !errors.Is(err, ErrNotFound) {
			return RequestView{}, err
		}
	}
	return result, commit(ctx, tx)
}
