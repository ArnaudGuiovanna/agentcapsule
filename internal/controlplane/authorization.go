package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// UpdatePreferences changes the PostgreSQL source of truth. The directory adapter
// must asynchronously project it; search/submission never trust that stale cache.
func (s *Store) UpdatePreferences(ctx context.Context, ownerUserID, agentID string, discoverable *bool, mode *string) error {
	if ownerUserID == "" || agentID == "" {
		return ErrNotFound
	}
	if mode != nil && *mode != "manual" && *mode != "auto" {
		return errors.New("inbound mode must be manual or auto")
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
	a, ok := agents[agentID]
	if !ok || a.Owner != ownerUserID {
		return ErrNotFound
	}
	if a.Phase != "LIVE" {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE agents SET discoverable=coalesce($2,discoverable),inbound_mode=coalesce($3,inbound_mode) WHERE id=$1`, agentID, discoverable, mode); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// DirectoryVisibility is worker-only: it supplies the current source value for
// one directory publication. It is not a user-visible existence lookup.
func (s *Store) DirectoryVisibility(ctx context.Context, agentID string) (bool, error) {
	var visible bool
	err := s.pool.QueryRow(ctx, "SELECT discoverable AND phase='LIVE' FROM agents WHERE id=$1", agentID).Scan(&visible)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return visible, err
}

// SearchDirectory rechecks untrusted/stale directory candidates in one PostgreSQL
// snapshot, excludes the authenticated caller, and returns only currently visible
// agents. The actual ADS client and authorization transport are separate adapters.
func (s *Store) SearchDirectory(ctx context.Context, callerAgentID string, candidates []string) ([]string, error) {
	if callerAgentID == "" {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT caller.phase, candidate.id
        FROM agents caller LEFT JOIN agents candidate ON candidate.id=ANY($2)
          AND candidate.id<>caller.id AND candidate.discoverable AND candidate.phase='LIVE'
        WHERE caller.id=$1 ORDER BY candidate.id`, callerAgentID, candidates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	found := false
	for rows.Next() {
		var phase string
		var id *string
		if err := rows.Scan(&phase, &id); err != nil {
			return nil, err
		}
		found = true
		if phase != "LIVE" {
			return nil, ErrUnavailable
		}
		if id != nil {
			result = append(result, *id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return result, nil
}

// GrantMandate is called by the trusted owner-instruction path, after it has
// authenticated the owner and durably registered originEventID. Capsule callers
// cannot invoke it through the agent-request interface. Replaying the same owner
// instruction returns its original grant without replenishing its budget.
func (s *Store) GrantMandate(ctx context.Context, ownerUserID, agentID, originEventID string, budget int, deadline time.Time) (string, error) {
	if ownerUserID == "" || agentID == "" || originEventID == "" || budget <= 0 || deadline.IsZero() {
		return "", errors.New("authenticated owner, instruction, positive budget and deadline required")
	}
	deadline = deadline.UTC().Truncate(time.Microsecond)
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return "", err
	}
	a, ok := agents[agentID]
	if !ok || a.Owner != ownerUserID {
		return "", ErrNotFound
	}
	var id string
	var originalBudget int
	var originalDeadline time.Time
	err = tx.QueryRow(ctx, "SELECT id,max_requests,expires_at FROM mandates WHERE agent_id=$1 AND origin_event_id=$2", agentID, originEventID).Scan(&id, &originalBudget, &originalDeadline)
	if err == nil {
		if budget != originalBudget || !deadline.Equal(originalDeadline) {
			return "", ErrConflict
		}
		return id, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if a.Phase != "LIVE" {
		return "", ErrUnavailable
	}
	var future bool
	if err := tx.QueryRow(ctx, "SELECT $1::timestamptz>clock_timestamp()", deadline).Scan(&future); err != nil {
		return "", err
	}
	if !future {
		return "", ErrExpired
	}
	id = newID("mdt")
	if _, err := tx.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ($1,$2,$3,$4,$4,$5)`, id, agentID, originEventID, budget, deadline); err != nil {
		return "", err
	}
	return id, commit(ctx, tx)
}

// RevokeMandate prevents future submissions. It does not retroactively revoke
// already-authorized requests, which have their own closure protocol/deadline.
func (s *Store) RevokeMandate(ctx context.Context, ownerUserID, mandateID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var agentID string
	if err := tx.QueryRow(ctx, "SELECT agent_id FROM mandates WHERE id=$1", mandateID).Scan(&agentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	agents, err := lockAgents(ctx, tx, agentID)
	if err != nil {
		return err
	}
	if ownerUserID == "" || agents[agentID].Owner != ownerUserID {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, "UPDATE mandates SET valid=false WHERE id=$1", mandateID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
