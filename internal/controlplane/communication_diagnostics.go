package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// CommunicationDiagnostic describes the two legs of an admitted exchange.
// Content, payload references, contact details and the mandate stay private.
type CommunicationDiagnostic struct {
	RequestID           string    `json:"request_id"`
	State               string    `json:"state"`
	Directory           string    `json:"directory"`
	VisibleAtSubmission bool      `json:"visible_at_submission"`
	MandateCurrent      bool      `json:"mandate_current"`
	Consent             string    `json:"consent"`
	Delivery            string    `json:"delivery"`
	Attempts            int       `json:"attempts"`
	ReplyDelivery       string    `json:"reply_delivery"`
	ExpiresAt           time.Time `json:"expires_at"`
	ObservedAt          time.Time `json:"observed_at"`
	NextCheck           string    `json:"next_check"`
}

func (c *AgentCatalog) ExplainCommunication(ctx context.Context, p Principal, recipient, id string) (CommunicationDiagnostic, error) {
	var d CommunicationDiagnostic
	if p.Kind != "tenant" || !validOrganizationText(id, 100) || !validOrganizationText(recipient, 100) {
		return d, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return d, err
	}
	defer rollback(tx)
	if err = authorizeHeldRequests(ctx, tx, p, recipient); err != nil {
		return d, err
	}
	err = tx.QueryRow(ctx, `SELECT r.id,r.state,coalesce(directory.state,'unpublished'),r.recipient_visible_at_submit,
		m.valid AND m.expires_at>clock_timestamp(),
		CASE WHEN r.via_auto THEN 'automatic' WHEN r.accepted THEN 'accepted' WHEN r.state='DECLINED' THEN 'declined'
		WHEN r.state='PENDING_APPROVAL' THEN 'pending' ELSE 'ended' END,
		coalesce(delivery.delivery_state,'not_queued'),coalesce(delivery.attempts,0),
		coalesce(reply.delivery_state,'not_queued'),r.expires_at,clock_timestamp()
		FROM agent_requests r JOIN mandates m ON m.id=r.mandate_id
		JOIN agents a ON a.id=r.recipient_agent_id AND a.tenant_id=$3
		LEFT JOIN agent_directory directory ON directory.agent_id=a.id
		LEFT JOIN agent_mailboxes delivery ON delivery.ref_id=r.id AND delivery.kind='request'
		LEFT JOIN agent_mailboxes reply ON reply.ref_id=r.id AND reply.kind='reply'
		WHERE r.id=$1 AND r.recipient_agent_id=$2`, id, recipient, p.TenantID).Scan(&d.RequestID, &d.State, &d.Directory, &d.VisibleAtSubmission, &d.MandateCurrent, &d.Consent, &d.Delivery, &d.Attempts, &d.ReplyDelivery, &d.ExpiresAt, &d.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	switch {
	case d.Delivery == "DEAD" || d.ReplyDelivery == "DEAD":
		d.NextCheck = "inspect_worker_dead_letters"
	case d.State == "PENDING_APPROVAL" && d.ExpiresAt.After(d.ObservedAt):
		d.NextCheck = "await_recipient_decision"
	case d.State == "DELIVERING":
		d.NextCheck = "inspect_worker_and_slim_delivery"
	case d.State == "PROCESSING":
		d.NextCheck = "await_recipient_response"
	case d.State == "REPLIED" && d.ReplyDelivery == "PENDING":
		d.NextCheck = "check_return_delivery"
	case d.State == "PENDING_APPROVAL":
		d.NextCheck = "check_expiration_sweep"
	default:
		d.NextCheck = "none"
	}
	return d, commit(ctx, tx)
}
