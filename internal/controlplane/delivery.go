package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNoDelivery        = errors.New("no pending delivery")
	ErrNotHead           = errors.New("delivery is not the FIFO head")
	ErrDeliveryBusy      = errors.New("delivery lease is active")
	ErrLeaseLost         = errors.New("delivery lease is no longer current")
	ErrAttemptsExhausted = errors.New("delivery attempt budget exhausted")
	ErrDeliveryClosing   = errors.New("delivery is waiting for its durable barrier")
)

// DeliveryRuntime must authenticate the destination/envelope and send an ACK
// only after its SQL effect and deduplication result have durably committed.
// The caller derives subjects from PostgreSQL, not from untrusted event input.
type DeliveryRuntime interface {
	RevocationRuntime
	Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error)
}

// Admission-aware runtimes can pause ordinary work BEFORE ClaimDelivery consumes
// an attempt. The callback is synchronous; retirement/fencing runs after its
// release, never while holding the application's shared admission scope.
type DeliveryAdmission interface {
	WithDeliveryAdmission(context.Context, func(context.Context) error) error
}

// Destination-aware runtimes prepare a usable boot before a durable delivery
// attempt is consumed. Capacity/admission/startup backpressure is not an RPC.
type PreparedDeliveryAdmission interface {
	WithPreparedDelivery(context.Context, string, func(context.Context) error) error
}

type DeliveryAttempt struct {
	ID, RequestID, Destination, Token string
	Sequence                          int64
	Envelope                          harnessstore.Event
}

type mailboxRow struct {
	ID, Destination, Kind, State, Token string
	StatusReason                        string
	Sequence                            int64
	Attempts, Limit                     int
	Closing                             bool
	MayHaveReached                      bool
	Deadline                            time.Time
	LeaseUntil                          *time.Time
}

func lockMailbox(ctx context.Context, tx pgx.Tx, id string) (mailboxRow, requestRow, map[string]agent, error) {
	m := mailboxRow{ID: id}
	var requestID string
	var kind string
	if err := tx.QueryRow(ctx, "SELECT coalesce(ref_id,''),kind FROM agent_mailboxes WHERE id=$1", id).Scan(&requestID, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrNotFound
		}
		return m, requestRow{}, nil, err
	}
	// Owner instructions share FIFO order, but have no inter-agent request.
	// This legacy dispatcher cannot decrypt them. Transit.DispatchMailbox routes
	// them explicitly; never interpret or skip an instruction head here.
	if kind == "instruction" {
		return m, requestRow{}, nil, ErrUnavailable
	}
	r, agents, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return m, r, nil, err
	}
	err = tx.QueryRow(ctx, `SELECT dest_agent_id,kind,delivery_state,seq,attempts,attempt_limit,
        lease_token,lease_until,closing,expires_at,may_have_reached,status_reason FROM agent_mailboxes WHERE id=$1 FOR UPDATE`, id).
		Scan(&m.Destination, &m.Kind, &m.State, &m.Sequence, &m.Attempts, &m.Limit, &m.Token, &m.LeaseUntil, &m.Closing, &m.Deadline, &m.MayHaveReached, &m.StatusReason)
	return m, r, agents, err
}

func (s *Store) HeadDelivery(ctx context.Context, agentID string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE dest_agent_id=$1 AND delivery_state='PENDING' ORDER BY seq LIMIT 1", agentID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNoDelivery
	}
	return id, err
}

func isHead(ctx context.Context, tx pgx.Tx, m mailboxRow) error {
	if m.State != "PENDING" {
		return ErrNoDelivery
	}
	var head string
	if err := tx.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE dest_agent_id=$1 AND delivery_state='PENDING' ORDER BY seq LIMIT 1", m.Destination).Scan(&head); err != nil {
		return err
	}
	if head != m.ID {
		return ErrNotHead
	}
	return nil
}

// ClaimDelivery reserves the head and consumes a durable attempt BEFORE any RPC.
// No database lock is held during delivery. Stale workers carry the same envelope
// but different lease tokens; only the current lease may acknowledge PostgreSQL.
func (s *Store) ClaimDelivery(ctx context.Context, mailboxID string, lease time.Duration) (DeliveryAttempt, error) {
	var attempt DeliveryAttempt
	if lease < time.Microsecond {
		return attempt, errors.New("positive delivery lease required")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return attempt, err
	}
	defer rollback(tx)
	m, r, agents, err := lockMailbox(ctx, tx, mailboxID)
	if err != nil {
		return attempt, err
	}
	if err := isHead(ctx, tx, m); err != nil {
		return attempt, err
	}
	if agents[m.Destination].Phase != "LIVE" || (m.Kind != "status" && (agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE")) {
		return attempt, ErrUnavailable
	}
	if m.Kind == "request" {
		var closing bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)", r.ID).Scan(&closing); err != nil {
			return attempt, err
		}
		if closing {
			return attempt, ErrClosurePending
		}
		if r.State != "DELIVERING" {
			return attempt, ErrTransition
		}
	}
	if m.Closing {
		return attempt, ErrDeliveryClosing
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return attempt, err
	}
	if !m.Deadline.After(now) {
		return attempt, ErrExpired
	}
	if m.LeaseUntil != nil && m.LeaseUntil.After(now) {
		return attempt, ErrDeliveryBusy
	}
	if m.Attempts >= m.Limit {
		return attempt, ErrAttemptsExhausted
	}
	// The envelope is stable across retries. Private bodies remain opaque transit
	// references here; resolving/decrypting them belongs to the authenticated runtime.
	payload, payloadHash, status := r.Payload, r.PayloadHash, ""
	subjects := []string{"agent/" + r.Sender, "agent/" + r.Recipient, "request/" + r.ID, "event/" + m.ID}
	if m.Kind == "status" {
		payload, payloadHash, status = "", nil, r.State
		subjects = []string{"agent/" + m.Destination, "notification/" + m.ID, "event/" + m.ID}
	} else if m.Kind == "reply" {
		if r.State != "REPLIED" {
			return attempt, ErrTransition
		}
		payload, payloadHash, status = r.ReplyPayload, r.ReplyHash, r.State
	}
	if m.Kind != "status" && (payload == "" || len(payloadHash) != 32) {
		return attempt, errors.New("delivery payload requires a reference and content hash; migrate legacy metadata first")
	}
	body, err := json.Marshal(struct {
		Kind, RequestID, PayloadRef, PayloadHash, Status, Reason string
		Sequence                                                 int64
	}{m.Kind, r.ID, payload, hex.EncodeToString(payloadHash), status, m.StatusReason, m.Sequence})
	if err != nil {
		return attempt, err
	}
	token := newID("lease")
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET attempts=attempts+1,lease_token=$2,dispatch_authorized=false,
        lease_until=clock_timestamp()+$3::bigint*interval '1 microsecond' WHERE id=$1`, m.ID, token, lease.Microseconds()); err != nil {
		return attempt, err
	}
	if _, err := tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1 WHERE mailbox_id=$1", m.ID); err != nil {
		return attempt, err
	}
	attempt = DeliveryAttempt{ID: m.ID, RequestID: r.ID, Destination: m.Destination, Token: token, Sequence: m.Sequence,
		Envelope: harnessstore.Event{ID: m.ID, Subjects: subjects, Body: body}}
	return attempt, commit(ctx, tx)
}

// AuthorizeDispatch persists the possibility of an external effect BEFORE the
// worker may call Send. A crash after this permission remains "outcome unknown";
// a claimed attempt that never received permission is known not to have run.
func (s *Store) AuthorizeDispatch(ctx context.Context, mailboxID, token string) error {
	if token == "" {
		return ErrLeaseLost
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	m, r, agents, err := lockMailbox(ctx, tx, mailboxID)
	if err != nil {
		return err
	}
	if agents[m.Destination].Phase != "LIVE" || (m.Kind != "status" && (agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE")) {
		return ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET may_have_reached=true,dispatch_authorized=true
        WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()
        AND delivery_state='PENDING' AND NOT closing AND expires_at>clock_timestamp()
        AND (kind='status' OR NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$3))`, mailboxID, token, r.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return commit(ctx, tx)
}

// AcknowledgeDelivery records reception, not completion of the business request.
func (s *Store) AcknowledgeDelivery(ctx context.Context, mailboxID, token string) error {
	return s.acknowledgeDelivery(ctx, mailboxID, token, nil)
}

func (s *Store) acknowledgeDelivery(ctx context.Context, mailboxID, token string, transit *Transit) error {
	if token == "" {
		return ErrLeaseLost
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	m, r, agents, err := lockMailbox(ctx, tx, mailboxID)
	if err != nil {
		return err
	}
	var current bool
	if err := tx.QueryRow(ctx, "SELECT lease_token=$2 AND lease_until>clock_timestamp() AND delivery_state='PENDING' AND NOT closing AND dispatch_authorized FROM agent_mailboxes WHERE id=$1", mailboxID, token).Scan(&current); err != nil {
		return err
	}
	if !current {
		return ErrLeaseLost
	}
	if transit != nil && (agents[m.Destination].Phase != "LIVE" || m.Kind != "status" && (agents[r.Sender].Phase != "LIVE" || agents[r.Recipient].Phase != "LIVE")) {
		return ErrUnavailable
	}
	if m.Kind == "request" {
		tag, err := tx.Exec(ctx, `UPDATE agent_requests SET state='PROCESSING',delivered=true
            WHERE id=$1 AND state='DELIVERING' AND NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)`, r.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrClosurePending
		}
	} else {
		if _, err := tx.Exec(ctx, "UPDATE agent_requests SET sender_notified=true WHERE id=$1 AND state IN ('REPLIED','DECLINED','EXPIRED','CANCELED','FAILED')", r.ID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='DELIVERED',lease_token='',lease_until=NULL WHERE id=$1", m.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM outbox WHERE mailbox_id=$1", m.ID); err != nil {
		return err
	}
	if transit != nil && m.Kind != "status" {
		ref := r.Payload
		if m.Kind == "reply" {
			ref = r.ReplyPayload
		}
		if err = transit.delivered(ctx, tx, ref); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}

// RetireDelivery revokes uncertain old work before removing the queue head. Merely
// expiring a lease is insufficient: a delayed RPC can outlive that lease.
func (s *Store) RetireDelivery(ctx context.Context, mailboxID string, runtime RevocationRuntime) error {
	if runtime == nil {
		return errors.New("revocation runtime is required")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	m, r, _, err := lockMailbox(ctx, tx, mailboxID)
	if err != nil {
		return err
	}
	if m.State != "PENDING" {
		return commit(ctx, tx)
	}
	if err := isHead(ctx, tx, m); err != nil {
		return err
	}
	var expired, exhausted bool
	if err := tx.QueryRow(ctx, `SELECT expires_at<=clock_timestamp(),
        attempts>=attempt_limit AND (lease_until IS NULL OR lease_until<=clock_timestamp())
        FROM agent_mailboxes WHERE id=$1`, mailboxID).Scan(&expired, &exhausted); err != nil {
		return err
	}
	if m.Kind == "request" {
		var existing bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)", r.ID).Scan(&existing); err != nil {
			return err
		}
		if !existing {
			if !expired && !exhausted {
				return ErrTransition
			}
			final, reason := "FAILED", "delivery_outcome_unknown"
			if !m.MayHaveReached {
				reason = "delivery_failed"
			}
			if expired {
				final, reason = "EXPIRED", "deadline_elapsed"
			}
			if err := beginClosure(ctx, tx, r, final, reason); err != nil {
				return err
			}
		}
		if err := commit(ctx, tx); err != nil {
			return err
		}
		return s.ReconcileRequestClosure(ctx, r.ID, runtime)
	}
	if !m.Closing && !expired && !exhausted {
		return ErrTransition
	}
	if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET closing=true WHERE id=$1", mailboxID); err != nil {
		return err
	}
	if err := publishRevocation(ctx, tx, "event/"+mailboxID); err != nil {
		return err
	}
	if err := commit(ctx, tx); err != nil {
		return err
	}
	if err := runtime.Fence(ctx, m.Destination, "event/"+m.ID); err != nil {
		return err
	}
	return commitBarrier(ctx, runtime, "event/"+m.ID, []string{m.Destination}, func() error {
		finish, err := s.begin(ctx)
		if err != nil {
			return err
		}
		defer rollback(finish)
		current, _, _, err := lockMailbox(ctx, finish, mailboxID)
		if err != nil {
			return err
		}
		if current.State == "PENDING" && current.Closing {
			if _, err := finish.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='DEAD',lease_token='',lease_until=NULL WHERE id=$1", mailboxID); err != nil {
				return err
			}
			if _, err := finish.Exec(ctx, "DELETE FROM outbox WHERE mailbox_id=$1", mailboxID); err != nil {
				return err
			}
		}
		return commit(ctx, finish)
	})
}

// DispatchOne performs at most one RPC attempt or one head retirement. Scheduling,
// wakeup and retry/backoff are external; a failed RPC leaves its lease to expire.
func (s *Store) DispatchOne(ctx context.Context, agentID string, lease time.Duration, runtime DeliveryRuntime) error {
	if runtime == nil {
		return errors.New("delivery runtime is required")
	}
	id, err := s.HeadDelivery(ctx, agentID)
	if err != nil {
		return err
	}
	return s.dispatchMailbox(ctx, agentID, id, lease, runtime)
}

// DispatchMailbox preserves a scheduler job's exact identity even if another
// worker has already advanced this destination's queue head.
func (s *Store) DispatchMailbox(ctx context.Context, id string, lease time.Duration, runtime DeliveryRuntime) error {
	if runtime == nil {
		return errors.New("delivery runtime is required")
	}
	var agentID, state string
	err := s.pool.QueryRow(ctx, "SELECT dest_agent_id,delivery_state FROM agent_mailboxes WHERE id=$1", id).Scan(&agentID, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoDelivery
	}
	if err != nil {
		return err
	}
	if state != "PENDING" {
		return ErrNoDelivery
	}
	return s.dispatchMailbox(ctx, agentID, id, lease, runtime)
}

func (s *Store) dispatchMailbox(ctx context.Context, agentID, id string, lease time.Duration, runtime DeliveryRuntime) error {
	return s.dispatchMailboxWithTransit(ctx, agentID, id, lease, runtime, nil)
}

func (s *Store) dispatchMailboxWithTransit(ctx context.Context, agentID, id string, lease time.Duration, runtime DeliveryRuntime, transit *Transit) error {
	var err error
	retire := false
	dispatch := func(ctx context.Context) error {
		attempt, err := s.ClaimDelivery(ctx, id, lease)
		if errors.Is(err, ErrExpired) || errors.Is(err, ErrAttemptsExhausted) || errors.Is(err, ErrClosurePending) || errors.Is(err, ErrDeliveryClosing) {
			retire = true
			return nil
		}
		if err != nil {
			return err
		}
		if err = s.AuthorizeDispatch(ctx, attempt.ID, attempt.Token); err != nil {
			return err
		}
		if transit != nil {
			attempt.Envelope, err = transit.resolveDelivery(ctx, attempt)
			if err != nil {
				return err
			}
			defer clear(attempt.Envelope.Body)
		}
		if _, err = runtime.Send(ctx, attempt.Destination, attempt.Envelope); err != nil {
			return err
		}
		return s.acknowledgeDelivery(ctx, attempt.ID, attempt.Token, transit)
	}
	if admission, ok := runtime.(PreparedDeliveryAdmission); ok {
		err = admission.WithPreparedDelivery(ctx, agentID, dispatch)
	} else if admission, ok := runtime.(DeliveryAdmission); ok {
		err = admission.WithDeliveryAdmission(ctx, dispatch)
	} else {
		err = dispatch(ctx)
	}
	if err != nil {
		return err
	}
	if retire {
		return s.RetireDelivery(ctx, id, runtime)
	}
	return nil
}
