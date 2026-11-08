package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type Submission struct {
	RecipientAgentID string
	MandateID        string
	PayloadRef       string // reference to separately authenticated, encrypted transit storage
	PayloadHash      [32]byte
	ExpiresAt        time.Time
}

// Submit derives the sender and idempotency scope from the authenticated channel.
// The caller cannot substitute a different sender inside Submission.
func (s *Store) Submit(ctx context.Context, callerAgentID, key string, input Submission) (Receipt, error) {
	return s.submit(ctx, callerAgentID, key, input, nil)
}

func (s *Store) submit(ctx context.Context, callerAgentID, key string, input Submission, vm *VMCaller) (Receipt, error) {
	return s.submitPayload(ctx, callerAgentID, key, input, vm, nil)
}

func (s *Store) submitPayload(ctx context.Context, callerAgentID, key string, input Submission, vm *VMCaller, payload *admissionPayload) (Receipt, error) {
	if err := requireIdentity(callerAgentID, key); err != nil {
		return Receipt{}, err
	}
	if input.RecipientAgentID == "" || input.RecipientAgentID == callerAgentID || input.MandateID == "" || (input.PayloadRef == "" && payload == nil) || input.ExpiresAt.IsZero() {
		return Receipt{}, errors.New("recipient, mandate, payload reference and deadline are required")
	}
	input.ExpiresAt = input.ExpiresAt.UTC().Truncate(time.Microsecond)
	hash, err := admissionHash(input, payload)
	if err != nil {
		return Receipt{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, callerAgentID, input.RecipientAgentID)
	if err != nil {
		return Receipt{}, err
	}
	sender, senderExists := agents[callerAgentID]
	recipient, recipientExists := agents[input.RecipientAgentID]
	if !senderExists || !recipientExists {
		return Receipt{}, ErrNotFound
	}
	if err = authorizeVM(ctx, tx, vm, agents); err != nil {
		return Receipt{}, err
	}
	state := PendingApproval
	if recipient.Mode == "auto" {
		state = Delivering
	}
	receipt, err := claim(ctx, tx, "agent/"+callerAgentID, "submit", key, hash, Receipt{RequestID: newID("arq"), State: state})
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Replayed {
		return receipt, commit(ctx, tx)
	}
	if sender.Phase != "LIVE" {
		return Receipt{}, ErrUnavailable
	}
	// Hidden and missing recipients intentionally have the same error.
	if recipient.Phase != "LIVE" || !recipient.Visible {
		return Receipt{}, ErrNotFound
	}
	var future bool
	if err := tx.QueryRow(ctx, "SELECT $1::timestamptz > clock_timestamp()", input.ExpiresAt).Scan(&future); err != nil {
		return Receipt{}, err
	}
	if !future {
		return Receipt{}, ErrExpired
	}
	tag, err := tx.Exec(ctx, `UPDATE mandates SET remaining=remaining-1
        WHERE id=$1 AND agent_id=$2 AND valid AND remaining>0 AND expires_at>clock_timestamp()`, input.MandateID, callerAgentID)
	if err != nil {
		return Receipt{}, err
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrMandate
	}
	if payload != nil {
		ref, err := payload.transit.put(ctx, tx, "request", receipt.RequestID, []string{callerAgentID, recipient.ID}, payload.body)
		if err != nil {
			return Receipt{}, err
		}
		input.PayloadRef = ref.ID
		copy(input.PayloadHash[:], ref.Hash)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_requests
        (id,sender_agent_id,recipient_agent_id,mandate_id,state,via_auto,payload_ref,expires_at,payload_hash,recipient_visible_at_submit)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, receipt.RequestID, callerAgentID, recipient.ID, input.MandateID, receipt.State, recipient.Mode == "auto", input.PayloadRef, input.ExpiresAt, input.PayloadHash[:], recipient.Visible); err != nil {
		return Receipt{}, err
	}
	kind := "request_pending"
	if receipt.State == Delivering {
		kind = "request_update"
		if err = enqueueRequest(ctx, tx, receipt.RequestID, recipient.ID, input.ExpiresAt); err != nil {
			return Receipt{}, err
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO inbox_items(id,user_id,kind,ref_id) VALUES ($1,$2,$3,$4)", newID("inb"), recipient.Owner, kind, receipt.RequestID); err != nil {
		return Receipt{}, err
	}
	return receipt, commit(ctx, tx)
}

// Accept records consent and creates the delivery/mailbox/outbox in one commit.
// Visibility may have changed since submission; existing inbox requests remain
// acceptable, but quiescing/deleted participants and terminal requests do not.
func (s *Store) Accept(ctx context.Context, callerUserID, requestID, key string) (Receipt, error) {
	return s.acceptOwner(ctx, callerUserID, requestID, key, nil)
}

func (s *Store) acceptOwner(ctx context.Context, callerUserID, requestID, key string, principal *Principal) (Receipt, error) {
	if err := requireIdentity(callerUserID, key); err != nil {
		return Receipt{}, err
	}
	hash, _ := requestHash(requestID)
	tx, err := s.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer rollback(tx)
	if principal != nil {
		if err = authorizePrincipal(ctx, tx, *principal, "user", "inbox:own"); err != nil {
			return Receipt{}, err
		}
	}
	var sender, recipient string
	var deadline time.Time
	if err := tx.QueryRow(ctx, "SELECT sender_agent_id,recipient_agent_id,expires_at FROM agent_requests WHERE id=$1", requestID).Scan(&sender, &recipient, &deadline); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Receipt{}, ErrNotFound
		}
		return Receipt{}, err
	}
	agents, err := lockAgents(ctx, tx, sender, recipient)
	if err != nil {
		return Receipt{}, err
	}
	if agents[recipient].Owner != callerUserID {
		return Receipt{}, ErrNotFound
	}
	receipt, err := claim(ctx, tx, "user/"+callerUserID, "accept/"+requestID, key, hash, Receipt{RequestID: requestID, State: Delivering})
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Replayed {
		return receipt, commit(ctx, tx)
	}
	if agents[sender].Phase != "LIVE" || agents[recipient].Phase != "LIVE" {
		return Receipt{}, ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_requests SET state='DELIVERING', accepted=true,
        decided_by=$2, decided_at=clock_timestamp()
        WHERE id=$1 AND state='PENDING_APPROVAL' AND expires_at>clock_timestamp()
        AND NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)`, requestID, callerUserID)
	if err != nil {
		return Receipt{}, err
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrTransition
	}
	if err := enqueueRequest(ctx, tx, requestID, recipient, deadline); err != nil {
		return Receipt{}, err
	}
	return receipt, commit(ctx, tx)
}

// QuiesceAgent blocks NEW admissions/acceptances in the same lock order as Submit.
// It does not declare deletion complete, cancel already authorized work, or claim
// an effects barrier in another database. The revocation coordinator must do that.
func (s *Store) QuiesceAgent(ctx context.Context, callerUserID, agentID string) error {
	if callerUserID == "" || agentID == "" {
		return ErrNotFound
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return err
	}
	a, exists := agents[agentID]
	if !exists || a.Owner != callerUserID {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, "UPDATE agents SET phase='QUIESCING' WHERE id=$1 AND phase='LIVE'", agentID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
