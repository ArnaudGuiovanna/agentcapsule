package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var ErrPendingFences = errors.New("durable revocation barriers are still pending")

// RevocationRuntime must fence the subject in the target store before returning
// success: either a durable transactional tombstone or a proven permanent seal.
// An unreachable store is NOT a successful fence. No database lock spans this RPC.
type RevocationRuntime interface {
	Fence(context.Context, string, string) error
}

// BarrierCommitter is implemented by the product worker. It checks the entire
// target manifest against independent incarnation-bound receipts, then holds
// that authority stable through publish. publish is SQL-only and must never
// acquire a host lock. SQL/MockRuntime fixtures have no independent catalogue.
type BarrierCommitter interface {
	CommitBarrier(context.Context, string, []string, func() error) error
}

func commitBarrier(ctx context.Context, runtime RevocationRuntime, subject string, targets []string, publish func() error) error {
	if r, ok := runtime.(BarrierCommitter); ok {
		return r.CommitBarrier(ctx, subject, targets, publish)
	}
	return publish()
}

// RequestDeletion durably records intent and a target census, then blocks NEW work.
// QUIESCING is not the model's deletion tombstone: previously authorized effects
// may still finish until the distributed barrier completes. No completion ACK or
// terminal cancellation is advertised here.
func (s *Store) RequestDeletion(ctx context.Context, ownerUserID, agentID string) error {
	if ownerUserID == "" || agentID == "" {
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
	if !exists || a.Owner != ownerUserID {
		return ErrNotFound
	}
	if err = requestDeletion(ctx, tx, a, ownerUserID); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// The caller holds the agent lock and has authenticated the owner/admin.
// No RPC or physical completion occurs in this transaction.
func requestDeletion(ctx context.Context, tx pgx.Tx, a agent, requestedBy string) error {
	tag, err := tx.Exec(ctx, `INSERT INTO deletion_operations(agent_id,requested_by)
        VALUES ($1,$2) ON CONFLICT(agent_id) DO NOTHING`, a.ID, requestedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if a.Phase != "LIVE" && a.Phase != "QUIESCING" {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, "UPDATE agents SET phase='QUIESCING',discoverable=false WHERE id=$1", a.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
        WHERE purged_at IS NULL AND id IN (SELECT payload_id FROM transit_parties WHERE agent_id=$1)`, a.ID); err != nil {
		return err
	}
	// Files sent to this agent are content too: their bytes go in the same commit.
	if _, err := tx.Exec(ctx, "DELETE FROM attachment_segments WHERE attachment_id IN (SELECT id FROM attachments WHERE agent_id=$1)", a.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "UPDATE attachments SET status='purged',purged_at=clock_timestamp() WHERE agent_id=$1 AND status<>'purged'", a.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM placement_renewals WHERE agent_id=$1", a.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code='agent_unavailable',completed_at=clock_timestamp()
        WHERE agent_id=$1 AND kind IN ('wake','sleep') AND status IN ('PENDING','RUNNING')`, a.ID); err != nil {
		return err
	}
	// Scheduled instructions have no mailbox entry yet, so closure would never
	// see them. Their content is purged above; close them visibly here.
	if _, err := tx.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code='agent_unavailable',completed_at=clock_timestamp()
        WHERE agent_id=$1 AND kind='instruction' AND status='PENDING'
          AND id IN (SELECT operation_id FROM owner_instructions WHERE run_at IS NOT NULL AND released_at IS NULL)`, a.ID); err != nil {
		return err
	}
	// Working invocations would otherwise wait for an outcome that can no longer
	// come; their content was purged above.
	if _, err := tx.Exec(ctx, `UPDATE platform_operations o SET status='CANCELED',error_code='agent_unavailable',completed_at=clock_timestamp()
        FROM owner_instructions i WHERE i.operation_id=o.id AND o.agent_id=$1 AND `+workingFilter, a.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE owner_instructions SET released_at=clock_timestamp()
        WHERE run_at IS NOT NULL AND released_at IS NULL AND operation_id IN (SELECT id FROM platform_operations WHERE agent_id=$1)`, a.ID); err != nil {
		return err
	}
	if err := publishRevocation(ctx, tx, "agent/"+a.ID); err != nil {
		return err
	}
	// New PROVISIONING stores have no ordinary authority and must catch up with
	// this permanent catalogue before activation. Their absence cannot hold an
	// existing deletion hostage. Activation excludes this intent/census commit.
	if _, err := tx.Exec(ctx, `INSERT INTO deletion_targets(agent_id,store_agent_id)
        SELECT $1,id FROM agents WHERE phase<>'PROVISIONING'`, a.ID); err != nil {
		return err
	}
	return nil
}

// ReconcileRevocation is worker-only. Repeating it after a worker/database crash
// reuses the durable manifest and retries unacknowledged, idempotent fences.
// It ends at DELETING. VM stop, permanent volume sealing and key destruction are
// separate runtime obligations before anyone may publish DELETED.
func (s *Store) ReconcileRevocation(ctx context.Context, agentID string, runtime RevocationRuntime) error {
	if runtime == nil {
		return errors.New("revocation runtime is required")
	}
	// This status reports work started, never physical completion. Trusted
	// deletions without a public operation retain their existing behavior.
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE platform_operations SET status='RUNNING' WHERE kind='delete' AND status='PENDING'
        AND id=(SELECT operation_id FROM deletion_operations WHERE agent_id=$1)`, agentID)
	if err == nil {
		err = commit(ctx, tx)
	}
	rollback(tx)
	if err != nil {
		return err
	}
	var phase string
	if err := s.pool.QueryRow(ctx, "SELECT phase FROM deletion_operations WHERE agent_id=$1", agentID).Scan(&phase); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	rows, err := s.pool.Query(ctx, "SELECT store_agent_id,acknowledged FROM deletion_targets WHERE agent_id=$1 ORDER BY store_agent_id", agentID)
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
		if err := runtime.Fence(ctx, target, "agent/"+agentID); err != nil {
			return fmt.Errorf("fence store %s: %w", target, err)
		}
		if err := s.recordFence(ctx, agentID, target); err != nil {
			return err
		}
	}
	return commitBarrier(ctx, runtime, "agent/"+agentID, targets, func() error { return s.commitRevocation(ctx, agentID) })
}

func (s *Store) recordFence(ctx context.Context, subject, target string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, "UPDATE deletion_targets SET acknowledged=true WHERE agent_id=$1 AND store_agent_id=$2", subject, target)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return commit(ctx, tx)
}

func (s *Store) commitRevocation(ctx context.Context, agentID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, "SELECT store_agent_id FROM deletion_targets WHERE agent_id=$1 ORDER BY store_agent_id", agentID)
	if err != nil {
		return err
	}
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(targets) == 0 {
		return ErrNotFound
	}
	// Notifications also update recipients' sequence counters. Acquire all rows
	// before the subject, in the same order as Submit/Accept, to avoid lock cycles.
	agents, err := lockAgents(ctx, tx, targets...)
	if err != nil {
		return err
	}
	var phase string
	var pending bool
	if err := tx.QueryRow(ctx, "SELECT phase FROM deletion_operations WHERE agent_id=$1 FOR UPDATE", agentID).Scan(&phase); err != nil {
		return err
	}
	if phase == "TOMBSTONED" {
		return commit(ctx, tx)
	}
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM deletion_targets WHERE agent_id=$1 AND NOT acknowledged)", agentID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrPendingFences
	}
	if agents[agentID].Phase != "QUIESCING" {
		return ErrTransition
	}
	if _, err := tx.Exec(ctx, "UPDATE agents SET phase='DELETING' WHERE id=$1", agentID); err != nil {
		return err
	}
	// An instruction with an uncertain ACK cannot become terminal until the
	// same durable agent barrier has retired all of its admitted guest effects.
	if _, err := tx.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code='agent_unavailable',completed_at=clock_timestamp()
        WHERE agent_id=$1 AND kind='instruction' AND status IN ('PENDING','RUNNING')`, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes SET delivery_state='CANCELED',lease_token='',lease_until=NULL
        WHERE dest_agent_id=$1 AND kind='instruction' AND delivery_state='PENDING'`, agentID); err != nil {
		return err
	}
	// Cancel old work AND old reply payloads. A new status-only notification is
	// authored by the control plane; it never carries the revoked party's content.
	if _, err := tx.Exec(ctx, `UPDATE agent_mailboxes AS m SET delivery_state='CANCELED'
        FROM agent_requests AS r WHERE m.ref_id=r.id AND m.delivery_state='PENDING'
        AND (m.dest_agent_id=$1 OR (m.kind IN ('request','reply')
        AND (r.sender_agent_id=$1 OR r.recipient_agent_id=$1)))`, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM outbox AS o USING agent_mailboxes AS m
        WHERE o.mailbox_id=m.id AND m.delivery_state='CANCELED'`); err != nil {
		return err
	}
	canceled, err := tx.Query(ctx, `UPDATE agent_requests SET state='CANCELED'
        WHERE (sender_agent_id=$1 OR recipient_agent_id=$1)
        AND state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING')
        RETURNING id,sender_agent_id,recipient_agent_id`, agentID)
	if err != nil {
		return err
	}
	type request struct{ id, sender, recipient string }
	var requests []request
	for canceled.Next() {
		var r request
		if err := canceled.Scan(&r.id, &r.sender, &r.recipient); err != nil {
			canceled.Close()
			return err
		}
		requests = append(requests, r)
	}
	canceled.Close()
	if err := canceled.Err(); err != nil {
		return err
	}
	for _, r := range requests {
		if err := notifyTerminal(ctx, tx, r.id, r.sender, r.recipient, agents); err != nil {
			return err
		}
	}
	// A completed reply may still be queued when its author is deleted. Canceling
	// that private payload must not silently discard the live sender's final status.
	// Preserve REPLIED, but send content-free metadata; an already applied reply
	// is not rolled back, and no claim is made that it was never observed.
	replies, err := tx.Query(ctx, `SELECT r.id,r.sender_agent_id,r.recipient_agent_id
        FROM agent_requests r JOIN agent_mailboxes m ON m.ref_id=r.id AND m.kind='reply'
        WHERE r.state='REPLIED' AND NOT r.sender_notified AND m.delivery_state IN ('CANCELED','DEAD')
        AND (r.sender_agent_id=$1 OR r.recipient_agent_id=$1)
        AND NOT EXISTS(SELECT 1 FROM agent_mailboxes s WHERE s.ref_id=r.id AND s.kind='status')`, agentID)
	if err != nil {
		return err
	}
	var notices []request
	for replies.Next() {
		var r request
		if err := replies.Scan(&r.id, &r.sender, &r.recipient); err != nil {
			replies.Close()
			return err
		}
		notices = append(notices, r)
	}
	replies.Close()
	if err := replies.Err(); err != nil {
		return err
	}
	for _, r := range notices {
		if agents[r.sender].Phase != "LIVE" {
			continue
		}
		if err := notifyTerminal(ctx, tx, r.id, r.sender, r.recipient, agents); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET status_reason='content_revoked' WHERE ref_id=$1 AND kind='status'", r.id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE deletion_operations SET phase='TOMBSTONED' WHERE agent_id=$1", agentID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
