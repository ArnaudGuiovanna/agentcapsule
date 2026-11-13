package controlplane

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrWakeBudget: the organization's agents already woke as many sleeping
// agents through requests as its budget allows in the last hour. It is
// backpressure, like an absent SLIM bridge: no delivery attempt is spent, the
// worker retries later, and the request expires at its deadline if no wake
// frees up before.
var ErrWakeBudget = errors.New("organization wake budget exhausted")

const defaultMaxPeerWakesPerHour = 60

// ReservePeerWake is asked by the worker before it boots an agent's VM for a
// delivery (INT-04, A2A-009). The next delivery decides: only a request
// between agents of an organization is counted against the organization's
// budget. A reply or a status completes work already admitted and always
// wakes its recipient; an owner instruction is bounded by the queue limits; an
// agent of a person has no organization. It returns the wake's ID, "" when the
// boot is not counted, or ErrWakeBudget. Wakes are counted per organization
// over a rolling hour, serialized per organization.
func (s *Store) ReservePeerWake(ctx context.Context, agentID string) (string, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(tx)
	var kind, tenant, request string
	err = tx.QueryRow(ctx, `SELECT m.kind,coalesce(a.tenant_id,''),coalesce(m.ref_id,'') FROM agent_mailboxes m JOIN agents a ON a.id=m.dest_agent_id
        WHERE m.dest_agent_id=$1 AND m.delivery_state='PENDING' ORDER BY m.seq LIMIT 1`, agentID).Scan(&kind, &tenant, &request)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (kind != "request" || tenant == "") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "peer-wakes/"+tenant); err != nil {
		return "", err
	}
	limits, err := queueLimits(ctx, tx, tenant)
	if err != nil {
		return "", err
	}
	// Older wakes no longer count; the organization's lock keeps this bounded.
	if _, err = tx.Exec(ctx, `DELETE FROM peer_wakes WHERE tenant_id=$1 AND woken_at<=clock_timestamp()-interval '1 hour'`, tenant); err != nil {
		return "", err
	}
	var used int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM peer_wakes WHERE tenant_id=$1`, tenant).Scan(&used); err != nil {
		return "", err
	}
	if used >= limits.MaxPeerWakesPerHour {
		return "", ErrWakeBudget
	}
	id := newID("wake")
	if _, err = tx.Exec(ctx, `INSERT INTO peer_wakes(id,tenant_id,agent_id,request_id) VALUES($1,$2,$3,$4)`, id, tenant, agentID, request); err != nil {
		return "", err
	}
	return id, commit(ctx, tx)
}

// ReleasePeerWake returns a reserved wake whose boot failed, so that an agent
// that cannot start does not use up its organization's budget by retrying.
func (s *Store) ReleasePeerWake(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM peer_wakes WHERE id=$1`, id)
	return err
}

// peerWakesLastHour counts the organization's wakes still in the window.
func peerWakesLastHour(ctx context.Context, tx pgx.Tx, tenant string) (int, error) {
	var used int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM peer_wakes WHERE tenant_id=$1 AND woken_at>clock_timestamp()-interval '1 hour'`, tenant).Scan(&used)
	return used, err
}
