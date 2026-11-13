package controlplane

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Reruns of the invocations that a restore lost (REC-02, ADR 003, migration
// 0030). The restore's last transaction decides, for each lost invocation,
// whether it runs again. Its rerun is queued under the same mailbox ID, or
// skipped with a reason. A rerun is due only while its outcome is lost and its
// requester may still invoke the agent: the model's due. The delivery path
// checks the requester again before the rerun reaches the agent.

// Rerun states (invocation_reruns.state).
const (
	RerunQueued  = "queued"
	RerunSkipped = "skipped"
)

// Why a lost invocation does not run again (invocation_reruns.skip_reason).
// The API shows it as the error_code of the lost invocation.
const (
	SkipRequesterRevoked  = "requester_revoked"
	SkipAgentUnavailable  = "agent_unavailable"
	SkipInputPurged       = "input_purged"
	SkipAttachmentsPurged = "attachments_purged"
)

// ErrRerunSkipped reports that the rerun at the head of an agent's queue was
// skipped instead of claimed: its requester can no longer invoke the agent.
// Nothing was sent; the queue moves on.
var ErrRerunSkipped = errors.New("the rerun of a lost invocation was skipped")

// DeclaredLoss is an outcome that the restore authority declared lost for a
// restore's incarnation. RerunRecorded is set when the authority already
// recorded its rerun (OutcomeStatus rerun_confirmed): it is no longer due.
type DeclaredLoss struct {
	OutcomeID     string
	RerunRecorded bool
}

// rerunJoins adds, for operation o, its newest rerun decision (rerun) and
// the time its newest loss was declared (loss.lost_at). A later restore's
// decision replaces an earlier one.
const rerunJoins = ` LEFT JOIN LATERAL (SELECT r.state,r.skip_reason FROM invocation_reruns r JOIN volume_restore_losses l
        ON (l.restore_id,l.outcome_id)=(r.restore_id,r.outcome_id) WHERE r.invocation_id=o.id
        ORDER BY l.incarnation DESC LIMIT 1) rerun ON true
    LEFT JOIN LATERAL (SELECT max(l.declared_at) AS lost_at FROM volume_restore_losses l WHERE l.invocation_id=o.id) loss ON true `

// lostCondition holds while invocation o is lost: its rerun is skipped and
// the invocation was not canceled, or its rerun is queued and has not ended.
const lostCondition = `coalesce((rerun.state='skipped' AND o.status<>'CANCELED') OR (rerun.state='queued' AND o.status IN ('PENDING','RUNNING')),false)`

// latestRerun selects the newest rerun decision of invocation $1, locked.
const latestRerun = `SELECT r.restore_id,r.outcome_id,r.state FROM invocation_reruns r JOIN volume_restore_losses l
    ON (l.restore_id,l.outcome_id)=(r.restore_id,r.outcome_id) WHERE r.invocation_id=$1
    ORDER BY l.incarnation DESC LIMIT 1 FOR UPDATE OF r`

// scheduleReruns decides the rerun of each invocation that restore restoreID
// lost. It runs in the transaction that copies the losses and puts the volume
// back in service, under the agent's lock. Nothing was delivered to the new
// incarnation yet, so each loss is still lost, unless the authority recorded
// its rerun (recorded). A candidate is an invocation whose delivery
// PostgreSQL recorded and that its requester did not cancel. Another one's
// delivery is still open, so it simply runs again, or it was closed.
func scheduleReruns(ctx context.Context, tx pgx.Tx, restoreID string, a agent, recorded map[string]bool) error {
	rows, err := tx.Query(ctx, `SELECT l.outcome_id,l.invocation_id,l.mailbox_id FROM volume_restore_losses l
        JOIN agent_mailboxes m ON m.id=l.mailbox_id WHERE l.restore_id=$1 AND l.invocation_id IS NOT NULL
        ORDER BY m.seq`, restoreID)
	if err != nil {
		return err
	}
	type lost struct{ outcome, invocation, mailbox string }
	var candidates []lost
	for rows.Next() {
		var l lost
		if err = rows.Scan(&l.outcome, &l.invocation, &l.mailbox); err != nil {
			rows.Close()
			return err
		}
		if !recorded[l.outcome] {
			candidates = append(candidates, l)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, l := range candidates {
		if err = decideRerun(ctx, tx, restoreID, l.outcome, l.invocation, l.mailbox, a); err != nil {
			return err
		}
	}
	return nil
}

func decideRerun(ctx context.Context, tx pgx.Tx, restoreID, outcome, op, mailbox string, a agent) error {
	var delivery, status, input, mandate, requester string
	err := tx.QueryRow(ctx, `SELECT m.delivery_state,o.status,i.input_payload_id,coalesce(i.mandate_id,''),
            coalesce(o.owner_user_id,o.requested_by_principal_id,'')
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN platform_operations o ON o.id=i.operation_id
        WHERE m.id=$1 AND i.operation_id=$2 FOR UPDATE OF m,i,o`, mailbox, op).Scan(&delivery, &status, &input, &mandate, &requester)
	if err != nil {
		return err
	}
	if delivery != "DELIVERED" || status == "CANCELED" {
		return nil
	}
	reason := ""
	if a.Phase != "LIVE" {
		reason = SkipAgentUnavailable
	} else if ok, err := mayInvokeAgain(ctx, tx, a, requester); err != nil {
		return err
	} else if !ok {
		reason = SkipRequesterRevoked
	}
	if reason == "" {
		var purged bool
		if err = tx.QueryRow(ctx, "SELECT purged_at IS NOT NULL FROM transit_payloads WHERE id=$1 FOR UPDATE", input).Scan(&purged); err != nil {
			return err
		}
		if purged {
			reason = SkipInputPurged
		}
	}
	if reason == "" {
		if reason, err = attachmentsGone(ctx, tx, op); err != nil {
			return err
		}
	}
	if reason != "" {
		// The input waits while the attachments question is open; nobody may
		// use the input of a revoked requester or of an agent on its way out.
		if reason == SkipAttachmentsPurged {
			if err = holdInput(ctx, tx, input); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO invocation_reruns(restore_id,outcome_id,invocation_id,state,skip_reason)
            VALUES($1,$2,$3,'skipped',$4)`, restoreID, outcome, op, reason)
		return err
	}
	return queueRerun(ctx, tx, restoreID, outcome, op, mailbox, input, mandate)
}

// attachmentsGone returns SkipAttachmentsPurged when a file of the invocation
// is no longer stored: a rerun could not send it again. It locks the files,
// so that the purge cannot take them while the rerun is queued.
func attachmentsGone(ctx context.Context, tx pgx.Tx, op string) (string, error) {
	rows, err := tx.Query(ctx, "SELECT status FROM attachments WHERE operation_id=$1 FOR UPDATE", op)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	gone := false
	for rows.Next() {
		var status string
		if err = rows.Scan(&status); err != nil {
			return "", err
		}
		gone = gone || status != "attached"
	}
	if err = rows.Err(); err != nil || !gone {
		return "", err
	}
	return SkipAttachmentsPurged, nil
}

// holdInput stops the purge of a delivered input: it is undelivered again,
// and its retention starts once more when the rerun is delivered.
func holdInput(ctx context.Context, tx pgx.Tx, input string) error {
	_, err := tx.Exec(ctx, `UPDATE transit_payloads SET delivered_at=NULL,purge_after=NULL WHERE id=$1 AND purged_at IS NULL`, input)
	return err
}

// queueRerun puts a lost invocation back in its agent's queue, under the same
// mailbox ID. It keeps its place: the lost work runs before newer work, in its
// first order. It gets a fresh set of attempts and its first delivery window
// again (its TTL), counted from now. Its mandate is reused: the same ID, the
// same remaining budget and validity, its expiry moved with the delivery
// deadline as AuthorizeInstruction requires. The operation is PENDING again;
// the result that the database still holds stays until the rerun's replaces
// it (putResult).
func queueRerun(ctx context.Context, tx pgx.Tx, restoreID, outcome, op, mailbox, input, mandate string) error {
	var ttl int64
	if err := tx.QueryRow(ctx, `SELECT LEAST(GREATEST(coalesce(i.ttl_micros,
            floor(extract(epoch FROM m.expires_at-o.created_at))::bigint*1000000),$2::bigint),$3::bigint)
        FROM agent_mailboxes m JOIN owner_instructions i ON i.operation_id=m.instruction_id
        JOIN platform_operations o ON o.id=i.operation_id WHERE m.id=$1`,
		mailbox, MinInstructionTTL.Microseconds(), MaxInstructionTTL.Microseconds()).Scan(&ttl); err != nil {
		return err
	}
	var deadline time.Time
	if err := tx.QueryRow(ctx, `UPDATE agent_mailboxes SET delivery_state='PENDING',attempts=0,lease_token='',lease_until=NULL,
        dispatch_authorized=false,may_have_reached=false,expires_at=clock_timestamp()+$2::bigint*interval '1 microsecond'
        WHERE id=$1 RETURNING expires_at`, mailbox, ttl).Scan(&deadline); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES($1,$2) ON CONFLICT (mailbox_id) DO NOTHING", newID("out"), mailbox); err != nil {
		return err
	}
	if mandate != "" {
		if _, err := tx.Exec(ctx, "UPDATE mandates SET expires_at=$2 WHERE id=$1 AND origin_event_id=$3", mandate, deadline, mailbox); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE platform_operations SET status='PENDING',error_code='',completed_at=NULL WHERE id=$1", op); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE owner_instructions SET working_since=NULL,result_due_at=NULL,completion_key=NULL,
        completion_hash=NULL,close_reason='' WHERE operation_id=$1`, op); err != nil {
		return err
	}
	if err := holdInput(ctx, tx, input); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO invocation_reruns(restore_id,outcome_id,invocation_id,state)
        VALUES($1,$2,$3,'queued')`, restoreID, outcome, op)
	return err
}

// mayInvokeAgain reports whether requester still holds the right that the
// lost request used: the owner of a historical agent is an active user; a
// tenant requester is an active principal and member of an active
// organization, with the invoke permission on the agent.
func mayInvokeAgain(ctx context.Context, tx pgx.Tx, a agent, requester string) (bool, error) {
	var active bool
	if a.Tenant == "" {
		if requester != a.Owner {
			return false, nil
		}
		err := tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1", requester).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return active, err
	}
	err := tx.QueryRow(ctx, `SELECT g.status='active' AND p.status='active' AND m.status='active' FROM principals p
        JOIN organizations g ON g.id=p.tenant_id JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
        WHERE p.tenant_id=$1 AND p.id=$2`, a.Tenant, requester).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, a.Tenant, requester, a.ID)
	if err != nil {
		return false, err
	}
	return slices.Contains(toPermissions(perms), authorization.PermissionInvoke), nil
}

// skipRevokedRerun skips the queued rerun of instruction i when its requester
// can no longer invoke the agent, before the rerun reaches it. The mailbox is
// closed, the mandate revoked, and the input's retention starts. The
// invocation stays lost. The caller holds the agent's and the instruction's
// locks.
func (t *Transit) skipRevokedRerun(ctx context.Context, tx pgx.Tx, i instructionRow, a agent) (bool, error) {
	if i.State != "PENDING" || i.MayHaveReached {
		return false, nil
	}
	var restoreID, outcome, state string
	err := tx.QueryRow(ctx, latestRerun, i.Operation).Scan(&restoreID, &outcome, &state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != RerunQueued {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if ok, err := mayInvokeAgain(ctx, tx, a, i.Requester); err != nil || ok {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE invocation_reruns SET state='skipped',skip_reason=$3,decided_at=clock_timestamp()
        WHERE restore_id=$1 AND outcome_id=$2`, restoreID, outcome, SkipRequesterRevoked); err != nil {
		return false, err
	}
	if err = closeRerun(ctx, tx, i.ID, i.Mandate); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='FAILED',error_code=$2,completed_at=clock_timestamp() WHERE id=$1",
		i.Operation, SkipRequesterRevoked); err != nil {
		return false, err
	}
	return true, t.delivered(ctx, tx, i.Input)
}

// closeRerun takes a queued rerun that has not reached the agent out of the
// queue, and revokes its mandate.
func closeRerun(ctx context.Context, tx pgx.Tx, mailbox, mandate string) error {
	if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='CANCELED',lease_token='',lease_until=NULL WHERE id=$1", mailbox); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM outbox WHERE mailbox_id=$1", mailbox); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE mandates SET valid=false WHERE id=$1", mandate)
	return err
}

// cancelLost cancels a lost invocation for its requester. A queued rerun
// that has not reached the agent never runs; a skipped one is closed. The
// invocation is then canceled and its stored input destroyed. A rerun being
// delivered is never interrupted from here, and a rerun acknowledged
// "working" is canceled by cancelWorking. The caller holds the agent's lock.
func cancelLost(ctx context.Context, tx pgx.Tx, op string) (bool, error) {
	var restoreID, outcome, state, status string
	err := tx.QueryRow(ctx, latestRerun, op).Scan(&restoreID, &outcome, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = tx.QueryRow(ctx, "SELECT status FROM platform_operations WHERE id=$1 FOR UPDATE", op).Scan(&status); err != nil {
		return false, err
	}
	switch {
	case state == RerunSkipped && status != "CANCELED":
	case state == RerunQueued && (status == "PENDING" || status == "RUNNING"):
		var mailbox, delivery, mandate string
		var reached bool
		if err = tx.QueryRow(ctx, `SELECT m.id,m.delivery_state,m.may_have_reached,coalesce(i.mandate_id,'') FROM agent_mailboxes m
            JOIN owner_instructions i ON i.operation_id=m.instruction_id WHERE m.instruction_id=$1 FOR UPDATE OF m`, op).
			Scan(&mailbox, &delivery, &reached, &mandate); err != nil {
			return false, err
		}
		if delivery != "PENDING" || reached {
			return false, nil
		}
		if err = closeRerun(ctx, tx, mailbox, mandate); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	if _, err = tx.Exec(ctx, "UPDATE platform_operations SET status='CANCELED',error_code='canceled',completed_at=clock_timestamp() WHERE id=$1", op); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
        WHERE purged_at IS NULL AND id=(SELECT input_payload_id FROM owner_instructions WHERE operation_id=$1)`, op)
	return err == nil, err
}
