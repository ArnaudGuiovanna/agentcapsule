package controlplane

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// AgentOrganization returns an agent's organization, or "" for an agent of a
// person. The SLIM bridge names agents by it (INT-04), like the Directory.
func (s *Store) AgentOrganization(ctx context.Context, agentID string) (string, error) {
	var tenant *string
	err := s.pool.QueryRow(ctx, "SELECT tenant_id FROM agents WHERE id=$1", agentID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil || tenant == nil {
		return "", err
	}
	return *tenant, nil
}

// HeadKind returns the kind of the next pending delivery to an agent
// ("request", "reply", "status" or "instruction"), or "" when none is pending.
// Only deliveries between agents cross SLIM.
func (s *Store) HeadKind(ctx context.Context, agentID string) (string, error) {
	var kind string
	err := s.pool.QueryRow(ctx, "SELECT kind FROM agent_mailboxes WHERE dest_agent_id=$1 AND delivery_state='PENDING' ORDER BY seq LIMIT 1", agentID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return kind, err
}
