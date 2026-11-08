package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrClosurePending = errors.New("request termination is waiting for durable barriers")

type requestRow struct {
	ID, Sender, Recipient, State, Payload string
	Deadline                              time.Time
	ReplyPayload                          string
	PayloadHash, ReplyHash                []byte
	ViaAuto                               bool
}

func active(state string) bool {
	return state == "PENDING_APPROVAL" || state == "DELIVERING" || state == "PROCESSING"
}

// All paths acquire agent locks before request/mailbox locks. Participant IDs
// cannot change between the first read and the locked read.
func lockRequest(ctx context.Context, tx pgx.Tx, id string, extraAgents ...string) (requestRow, map[string]agent, error) {
	r := requestRow{ID: id}
	if err := tx.QueryRow(ctx, "SELECT sender_agent_id,recipient_agent_id FROM agent_requests WHERE id=$1", id).Scan(&r.Sender, &r.Recipient); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrNotFound
		}
		return r, nil, err
	}
	agents, err := lockAgents(ctx, tx, append([]string{r.Sender, r.Recipient}, extraAgents...)...)
	if err != nil {
		return r, nil, err
	}
	err = tx.QueryRow(ctx, "SELECT state,payload_ref,expires_at,reply_ref,payload_hash,reply_hash,via_auto FROM agent_requests WHERE id=$1 FOR UPDATE", id).
		Scan(&r.State, &r.Payload, &r.Deadline, &r.ReplyPayload, &r.PayloadHash, &r.ReplyHash, &r.ViaAuto)
	return r, agents, err
}

func beginClosure(ctx context.Context, tx pgx.Tx, r requestRow, final, reason string) error {
	var existing string
	err := tx.QueryRow(ctx, "SELECT final_state FROM request_closures WHERE request_id=$1", r.ID).Scan(&existing)
	if err == nil {
		if existing != final {
			return ErrClosurePending
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !active(r.State) {
		return ErrTransition
	}
	if _, err := tx.Exec(ctx, "INSERT INTO request_closures(request_id,final_state,reason) VALUES ($1,$2,$3)", r.ID, final, reason); err != nil {
		return err
	}
	if err := publishRevocation(ctx, tx, "request/"+r.ID); err != nil {
		return err
	}
	// Stores in creation catch up before activation; existing stores remain in
	// the manifest even when stopped or permanently sealed.
	_, err = tx.Exec(ctx, "INSERT INTO request_closure_targets(request_id,store_agent_id) SELECT $1,id FROM agents WHERE phase<>'PROVISIONING'", r.ID)
	return err
}

// RequestCancellation acknowledges only durable INTENT. ReconcileRequestClosure
// must fence existing work before the request may become terminal.
func (s *Store) RequestCancellation(ctx context.Context, callerUserID, requestID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	r, agents, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return err
	}
	if callerUserID == "" || agents[r.Sender].Owner != callerUserID {
		return ErrNotFound
	}
	if err := beginClosure(ctx, tx, r, "CANCELED", "sender_canceled"); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// RequestExpiration is worker-only and checks the database clock. This starts
// closure; it does not promise an instantaneous effect cutoff at wall-clock time.
func (s *Store) RequestExpiration(ctx context.Context, requestID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	r, _, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return err
	}
	var due bool
	if err := tx.QueryRow(ctx, "SELECT $1::timestamptz <= clock_timestamp()", r.Deadline).Scan(&due); err != nil {
		return err
	}
	if !due {
		return ErrTransition
	}
	if err := beginClosure(ctx, tx, r, "EXPIRED", "deadline_elapsed"); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (s *Store) ReconcileRequestClosure(ctx context.Context, requestID string, runtime RevocationRuntime) error {
	if runtime == nil {
		return errors.New("revocation runtime is required")
	}
	var phase string
	if err := s.pool.QueryRow(ctx, "SELECT phase FROM request_closures WHERE request_id=$1", requestID).Scan(&phase); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	rows, err := s.pool.Query(ctx, "SELECT store_agent_id,acknowledged FROM request_closure_targets WHERE request_id=$1 ORDER BY store_agent_id", requestID)
	if err != nil {
		return err
	}
	var targets, pending []string
	for rows.Next() {
		var target string
		var acknowledged bool
		if err := rows.Scan(&target, &acknowledged); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, target)
		if !acknowledged {
			pending = append(pending, target)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, target := range pending {
		if err := runtime.Fence(ctx, target, "request/"+requestID); err != nil {
			return fmt.Errorf("fence request in store %s: %w", target, err)
		}
		if err := s.recordRequestFence(ctx, requestID, target); err != nil {
			return err
		}
	}
	return commitBarrier(ctx, runtime, "request/"+requestID, targets, func() error { return s.commitRequestClosure(ctx, requestID) })
}

// recordRequestFence is the durable coordinator half of a local fence RPC.
// It is called only after a trusted runtime has acknowledged that subject.
func (s *Store) recordRequestFence(ctx context.Context, requestID, target string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "UPDATE request_closure_targets SET acknowledged=true WHERE request_id=$1 AND store_agent_id=$2", requestID, target); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (s *Store) commitRequestClosure(ctx context.Context, requestID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	r, agents, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return err
	}
	var final, phase string
	if err := tx.QueryRow(ctx, "SELECT final_state,phase FROM request_closures WHERE request_id=$1 FOR UPDATE", requestID).Scan(&final, &phase); err != nil {
		return err
	}
	if phase == "COMMITTED" {
		return commit(ctx, tx)
	}
	var pending bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM request_closure_targets WHERE request_id=$1 AND NOT acknowledged)", requestID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrPendingFences
	}
	if active(r.State) {
		if _, err := tx.Exec(ctx, "UPDATE agent_requests SET state=$2 WHERE id=$1 AND state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING')", requestID, final); err != nil {
			return err
		}
		mailboxState := "CANCELED"
		if final == "FAILED" {
			mailboxState = "DEAD"
		}
		if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state=$2,lease_token='',lease_until=NULL WHERE ref_id=$1 AND kind IN ('request','reply') AND delivery_state='PENDING'", requestID, mailboxState); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM outbox AS o USING agent_mailboxes AS m
            WHERE o.mailbox_id=m.id AND m.ref_id=$1 AND m.delivery_state <> 'PENDING'`, requestID); err != nil {
			return err
		}
		if err := notifyTerminal(ctx, tx, r.ID, r.Sender, r.Recipient, agents); err != nil {
			return err
		}
	}
	// Agent deletion may have safely canceled this request in the meantime.
	// Its terminal state and notification win; never resurrect or overwrite it.
	if _, err := tx.Exec(ctx, "UPDATE request_closures SET phase='COMMITTED' WHERE request_id=$1", requestID); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func notifyTerminal(ctx context.Context, tx pgx.Tx, id, sender, recipient string, agents map[string]agent) error {
	return enqueueTerminal(ctx, tx, id, sender, recipient, "status", agents)
}

func enqueueTerminal(ctx context.Context, tx pgx.Tx, id, sender, recipient, kind string, agents map[string]agent) error {
	if agents[sender].Phase == "LIVE" {
		var seq int64
		if err := tx.QueryRow(ctx, "UPDATE agents SET next_seq=next_seq+1 WHERE id=$1 RETURNING next_seq", sender).Scan(&seq); err != nil {
			return err
		}
		mailbox := newID("mbx")
		if _, err := tx.Exec(ctx, `INSERT INTO agent_mailboxes(id,dest_agent_id,seq,kind,ref_id,expires_at)
            VALUES ($1,$2,$3,$5,$4,clock_timestamp()+interval '7 days')`, mailbox, sender, seq, id, kind); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES ($1,$2)", newID("out"), mailbox); err != nil {
			return err
		}
	}
	for _, peer := range []string{sender, recipient} {
		if agents[peer].Phase == "LIVE" {
			if _, err := tx.Exec(ctx, "INSERT INTO inbox_items(id,user_id,kind,ref_id) VALUES ($1,$2,'request_update',$3)", newID("inb"), agents[peer].Owner, id); err != nil {
				return err
			}
		}
	}
	return nil
}
