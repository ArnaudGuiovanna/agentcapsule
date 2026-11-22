package controlplane

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The retention of finished records (P-04, migration 0072). Finished
// invocations, wakes, sleeps and requests between agents stayed forever, with
// their mailbox entries, idempotency keys, inbox items, closures, mandates
// and content tombstones, although nothing reads them once their content is
// gone. Past a retention, the worker of their agent's host deletes them, a
// bounded batch at a time, unless something still needs them:
//   - content still held: an unread result is never purged (ADR 007, 022),
//     nor is a record whose input or message content is still retained;
//   - a delivery still queued, a closure still fencing;
//   - an audit event that names it (ADR 014): it goes once the audit's own
//     retention removed the event;
//   - a restore's record of a loss or a rerun, a redelivery decision, an
//     owner's message bound to a request: these are permanent;
//   - a corpus build or extension that ran it;
//   - for an invocation, a request it sent that is still kept.
//
// The retention must exceed the life of every archive a restore could start
// from, so that a restore still finds every event it lost (ADR 003, 008):
// the worker refuses one shorter than its archives' horizon, and at least
// MinFinishedRetention. Idempotency keys of requests go with their request:
// they replay for as long as the request is kept, which a rerun after a
// restore needs no longer than that horizon.

// Finished-record retention bounds and default (docs/worker.md).
const (
	MinFinishedRetention     = 45 * 24 * time.Hour
	MaxFinishedRetention     = 3650 * 24 * time.Hour
	DefaultFinishedRetention = 90 * 24 * time.Hour
)

// FinishedPurge counts what one purge deleted.
type FinishedPurge struct {
	Requests, Lifecycle, Invocations int64
}

// Total is the number of records deleted.
func (p FinishedPurge) Total() int64 { return p.Requests + p.Lifecycle + p.Invocations }

// finishedRequests selects, for host $2's senders, at most $3 finished
// requests whose deadline passed before $1 minus the retention ($4
// microseconds), that nothing needs any more (see above).
const finishedRequests = `SELECT r.id FROM agent_requests r JOIN agent_placements p ON p.agent_id=r.sender_agent_id AND p.host_id=$2
    WHERE r.state IN ('REPLIED','DECLINED','EXPIRED','CANCELED','FAILED')
      AND r.expires_at < ` + dbNow + `-$4::bigint*interval '1 microsecond'
      AND NOT EXISTS(SELECT 1 FROM agent_mailboxes m WHERE m.ref_id=r.id
          AND (m.delivery_state='PENDING' OR EXISTS(SELECT 1 FROM volume_restore_losses l WHERE l.mailbox_id=m.id)))
      AND NOT EXISTS(SELECT 1 FROM request_closures c WHERE c.request_id=r.id AND c.phase<>'COMMITTED')
      AND NOT EXISTS(SELECT 1 FROM transit_payloads t WHERE t.kind IN ('request','reply') AND t.ref_id=r.id AND t.purged_at IS NULL)
      AND NOT EXISTS(SELECT 1 FROM owner_messages x WHERE x.request_id=r.id)
      AND NOT EXISTS(SELECT 1 FROM peer_redeliveries x WHERE x.request_id=r.id)
      AND NOT EXISTS(SELECT 1 FROM tenant_agent_audit x WHERE x.request_id=r.id)
    ORDER BY r.expires_at LIMIT $3 FOR UPDATE OF r SKIP LOCKED`

// finishedLifecycle selects host $2's wakes and sleeps that ended before $1
// minus the retention ($4 microseconds), at most $3.
const finishedLifecycle = `SELECT o.id FROM platform_operations o JOIN agent_placements p ON p.agent_id=o.agent_id AND p.host_id=$2
    WHERE o.kind IN ('wake','sleep') AND o.status IN ('SUCCEEDED','FAILED','CANCELED')
      AND o.completed_at < ` + dbNow + `-$4::bigint*interval '1 microsecond'
    ORDER BY o.completed_at LIMIT $3 FOR UPDATE OF o SKIP LOCKED`

// finishedInvocations selects host $2's invocations that ended before $1
// minus the retention ($4 microseconds), at most $3, that nothing needs any
// more (see above).
const finishedInvocations = `SELECT o.id FROM platform_operations o JOIN owner_instructions i ON i.operation_id=o.id
    JOIN agent_placements p ON p.agent_id=o.agent_id AND p.host_id=$2
    WHERE o.kind='instruction' AND o.status IN ('SUCCEEDED','FAILED','CANCELED')
      AND o.completed_at < ` + dbNow + `-$4::bigint*interval '1 microsecond'
      AND NOT EXISTS(SELECT 1 FROM transit_payloads t WHERE t.id IN (i.input_payload_id,i.result_payload_id) AND t.purged_at IS NULL)
      AND NOT EXISTS(SELECT 1 FROM agent_mailboxes m WHERE m.instruction_id=o.id
          AND (m.delivery_state='PENDING' OR EXISTS(SELECT 1 FROM volume_restore_losses l WHERE l.mailbox_id=m.id)))
      AND NOT EXISTS(SELECT 1 FROM agent_requests r WHERE r.mandate_id=i.mandate_id)
      AND NOT EXISTS(SELECT 1 FROM instruction_replays x WHERE x.operation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM volume_restore_losses x WHERE x.invocation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM invocation_reruns x WHERE x.invocation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM corpus_builds x WHERE x.invocation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM corpus_builds x WHERE x.conversion_invocation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM corpus_extensions x WHERE x.invocation_id=o.id)
      AND NOT EXISTS(SELECT 1 FROM attachments x WHERE x.operation_id=o.id AND x.status<>'purged')
    ORDER BY o.completed_at LIMIT $3 FOR UPDATE OF o,i SKIP LOCKED`

// PurgeFinished deletes, for host's agents, at most limit finished requests,
// limit finished wakes and sleeps and limit finished invocations that ended
// more than retention ago and that nothing needs any more, with what hangs on
// them, in one transaction. now is the database clock when nil.
func (s *Store) PurgeFinished(ctx context.Context, host string, now *time.Time, retention time.Duration, limit int) (FinishedPurge, error) {
	var out FinishedPurge
	if host == "" || limit < 1 || limit > 1000 || retention < MinFinishedRetention || retention > MaxFinishedRetention {
		return out, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	args := []any{nowArg(now), host, limit, retention.Microseconds()}
	selectIDs := func(query string) ([]string, error) {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowTo[string])
	}
	exec := func(statements []string, ids []string) error {
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement, ids); err != nil {
				return err
			}
		}
		return nil
	}
	// Requests first: their mandates belong to the invocations that sent them.
	requests, err := selectIDs(finishedRequests)
	if err != nil {
		return out, err
	}
	if len(requests) > 0 {
		payloads, err := idsOf(ctx, tx, `SELECT id FROM transit_payloads WHERE kind IN ('request','reply') AND ref_id=ANY($1)`, requests)
		if err != nil {
			return out, err
		}
		if err = exec([]string{
			`DELETE FROM idempotency_keys WHERE response_ref=ANY($1)`,
			`DELETE FROM inbox_items WHERE ref_id=ANY($1)`,
			`DELETE FROM request_closure_targets WHERE request_id=ANY($1)`,
			`DELETE FROM request_closures WHERE request_id=ANY($1)`,
			`DELETE FROM peer_wakes WHERE request_id=ANY($1)`,
			`DELETE FROM outbox o USING agent_mailboxes m WHERE o.mailbox_id=m.id AND m.ref_id=ANY($1)`,
			`DELETE FROM agent_mailboxes WHERE ref_id=ANY($1)`,
		}, requests); err != nil {
			return out, err
		}
		if err = deleteTombstones(ctx, tx, payloads); err != nil {
			return out, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM agent_requests WHERE id=ANY($1)`, requests)
		if err != nil {
			return out, err
		}
		out.Requests = tag.RowsAffected()
	}
	lifecycle, err := selectIDs(finishedLifecycle)
	if err != nil {
		return out, err
	}
	if len(lifecycle) > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM platform_operations WHERE id=ANY($1)`, lifecycle)
		if err != nil {
			return out, err
		}
		out.Lifecycle = tag.RowsAffected()
	}
	invocations, err := selectIDs(finishedInvocations)
	if err != nil {
		return out, err
	}
	if len(invocations) > 0 {
		chunks, err := idsOf(ctx, tx, `DELETE FROM invocation_stream_chunks WHERE operation_id=ANY($1) RETURNING payload_id`, invocations)
		if err != nil {
			return out, err
		}
		if err = deleteChunkPayloads(ctx, tx, chunks); err != nil {
			return out, err
		}
		if err = exec([]string{
			`DELETE FROM invocation_streams WHERE operation_id=ANY($1)`,
			`DELETE FROM attachment_segments WHERE attachment_id IN (SELECT id FROM attachments WHERE operation_id=ANY($1))`,
			`DELETE FROM attachments WHERE operation_id=ANY($1)`,
			`DELETE FROM outbox o USING agent_mailboxes m WHERE o.mailbox_id=m.id AND m.instruction_id=ANY($1)`,
			`DELETE FROM agent_mailboxes WHERE instruction_id=ANY($1)`,
		}, invocations); err != nil {
			return out, err
		}
		rows, err := tx.Query(ctx, `DELETE FROM owner_instructions WHERE operation_id=ANY($1)
            RETURNING input_payload_id,coalesce(result_payload_id,''),coalesce(mandate_id,'')`, invocations)
		if err != nil {
			return out, err
		}
		var payloads, mandates []string
		for rows.Next() {
			var input, result, mandate string
			if err = rows.Scan(&input, &result, &mandate); err != nil {
				rows.Close()
				return out, err
			}
			payloads = append(payloads, input)
			if result != "" {
				payloads = append(payloads, result)
			}
			if mandate != "" {
				mandates = append(mandates, mandate)
			}
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return out, err
		}
		if err = deleteTombstones(ctx, tx, payloads); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM mandates WHERE id=ANY($1)`, mandates); err != nil {
			return out, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM platform_operations WHERE id=ANY($1)`, invocations)
		if err != nil {
			return out, err
		}
		out.Invocations = tag.RowsAffected()
	}
	return out, commit(ctx, tx)
}

func idsOf(ctx context.Context, tx pgx.Tx, query string, ids []string) ([]string, error) {
	rows, err := tx.Query(ctx, query, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// deleteTombstones deletes purged payloads, whose content is already gone,
// and their parties.
func deleteTombstones(ctx context.Context, tx pgx.Tx, payloads []string) error {
	if len(payloads) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM transit_parties WHERE payload_id IN
        (SELECT id FROM transit_payloads WHERE id=ANY($1) AND purged_at IS NOT NULL)`, payloads); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM transit_payloads WHERE id=ANY($1) AND purged_at IS NOT NULL`, payloads)
	return err
}
