package controlplane

import (
	"context"
	"errors"
)

type Reply struct {
	Outcome     string // completed or declined; declined never carries private content
	PayloadRef  string
	PayloadHash [32]byte
}

// ReplyToRequest uses the authenticated recipient identity. The harness must
// commit its local work before reporting completion. This transaction atomically
// publishes the final state, immutable reply reference, idempotent receipt and
// sender mailbox. It never repeats the local business effect.
func (s *Store) ReplyToRequest(ctx context.Context, callerAgentID, requestID, key string, input Reply) (Receipt, error) {
	return s.replyToRequest(ctx, callerAgentID, requestID, key, input, nil)
}

func (s *Store) replyToRequest(ctx context.Context, callerAgentID, requestID, key string, input Reply, vm *VMCaller) (Receipt, error) {
	return s.replyPayload(ctx, callerAgentID, requestID, key, input, vm, nil)
}

func (s *Store) replyPayload(ctx context.Context, callerAgentID, requestID, key string, input Reply, vm *VMCaller, payload *admissionPayload) (Receipt, error) {
	if err := requireIdentity(callerAgentID, key); err != nil {
		return Receipt{}, err
	}
	final, kind := "REPLIED", "reply"
	switch input.Outcome {
	case "completed":
		if input.PayloadRef == "" && payload == nil {
			return Receipt{}, errors.New("completed reply requires an authenticated transit reference")
		}
	case "declined":
		if input.PayloadRef != "" || input.PayloadHash != ([32]byte{}) || payload != nil {
			return Receipt{}, errors.New("declined reply must not carry private content")
		}
		final, kind = "DECLINED", "status"
	default:
		return Receipt{}, errors.New("reply outcome must be completed or declined")
	}
	hash, err := admissionHash(input, payload)
	if err != nil {
		return Receipt{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer rollback(tx)
	r, agents, err := lockRequest(ctx, tx, requestID, callerAgentID)
	if err != nil {
		return Receipt{}, err
	}
	if err = authorizeVM(ctx, tx, vm, agents); err != nil {
		return Receipt{}, err
	}
	if r.Recipient != callerAgentID {
		return Receipt{}, ErrNotFound
	}
	receipt, err := claim(ctx, tx, "agent/"+callerAgentID, "reply/"+requestID, key, hash, Receipt{RequestID: requestID, State: State(final)})
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Replayed {
		return receipt, commit(ctx, tx)
	}
	if agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE" {
		return Receipt{}, ErrUnavailable
	}
	if input.Outcome == "declined" && !r.ViaAuto {
		return Receipt{}, ErrTransition
	}
	if payload != nil && r.State != "PROCESSING" {
		return Receipt{}, ErrTransition
	}
	if payload != nil {
		ref, err := payload.transit.put(ctx, tx, "reply", requestID, []string{r.Sender, r.Recipient}, payload.body)
		if err != nil {
			return Receipt{}, err
		}
		input.PayloadRef = ref.ID
		copy(input.PayloadHash[:], ref.Hash)
	}
	var replyHash []byte
	if input.Outcome == "completed" {
		replyHash = input.PayloadHash[:]
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_requests SET state=$2,reply_ref=$3,reply_hash=$4
        WHERE id=$1 AND state='PROCESSING' AND expires_at>clock_timestamp()
        AND NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)`, requestID, final, input.PayloadRef, replyHash)
	if err != nil {
		return Receipt{}, err
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrTransition
	}
	if err := enqueueTerminal(ctx, tx, r.ID, r.Sender, r.Recipient, kind, agents); err != nil {
		return Receipt{}, err
	}
	return receipt, commit(ctx, tx)
}

// DeclineRequest is an owner decision before acceptance; no request was delivered
// to the harness. After delivery, only an auto-mode recipient can decline via Reply.
func (s *Store) DeclineRequest(ctx context.Context, callerUserID, requestID, key string) (Receipt, error) {
	return s.declineOwner(ctx, callerUserID, requestID, key, nil)
}

func (s *Store) declineOwner(ctx context.Context, callerUserID, requestID, key string, principal *Principal) (Receipt, error) {
	if err := requireIdentity(callerUserID, key); err != nil {
		return Receipt{}, err
	}
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
	r, agents, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return Receipt{}, err
	}
	if agents[r.Recipient].Owner != callerUserID {
		return Receipt{}, ErrNotFound
	}
	hash, _ := requestHash(requestID)
	receipt, err := claim(ctx, tx, "user/"+callerUserID, "decline/"+requestID, key, hash, Receipt{RequestID: requestID, State: "DECLINED"})
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Replayed {
		return receipt, commit(ctx, tx)
	}
	if agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE" {
		return Receipt{}, ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_requests SET state='DECLINED',decided_by=$2,decided_at=clock_timestamp()
        WHERE id=$1 AND state='PENDING_APPROVAL' AND expires_at>clock_timestamp()
        AND NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)`, requestID, callerUserID)
	if err != nil {
		return Receipt{}, err
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrTransition
	}
	if err := notifyTerminal(ctx, tx, r.ID, r.Sender, r.Recipient, agents); err != nil {
		return Receipt{}, err
	}
	return receipt, commit(ctx, tx)
}
