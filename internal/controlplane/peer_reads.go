package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// The reads behind a running agent's A2A endpoint (INT-03). They pass the same
// placement check as every VM call and decide nothing: an Agent Card or a
// request state grants no right, and a request still goes through Submit.

// DescribeAgentFromVM describes an agent the caller may send requests to,
// with exactly Submit's recipient rules: another agent, live, discoverable,
// of the caller's own domain (its organization, or the historical domain).
// A missing, hidden and foreign agent are the same ErrNotFound. The
// description and skills are those the organization chose to publish; an
// agent it never described has none.
func (s *Store) DescribeAgentFromVM(ctx context.Context, caller VMCaller, agentID string) (DirectoryAgent, error) {
	if agentID == "" || len(agentID) > 100 {
		return DirectoryAgent{}, ErrNotFound
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return DirectoryAgent{}, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return DirectoryAgent{}, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return DirectoryAgent{}, err
	}
	a := DirectoryAgent{Skills: []int{}, Domains: []int{}}
	err = tx.QueryRow(ctx, `SELECT a.id,coalesce(d.description,''),coalesce(d.skills,'{}'),coalesce(d.domains,'{}')
        FROM agents a LEFT JOIN agent_directory d ON d.agent_id=a.id
        WHERE a.id=$1 AND a.id<>$2 AND a.discoverable AND a.phase='LIVE'
          AND a.tenant_id IS NOT DISTINCT FROM (SELECT tenant_id FROM agents WHERE id=$2)`, agentID, caller.AgentID).
		Scan(&a.AgentID, &a.Description, &a.Skills, &a.Domains)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectoryAgent{}, ErrNotFound
	}
	if err != nil {
		return DirectoryAgent{}, err
	}
	return a, commit(ctx, tx)
}

// RequestState is what the sender of a request may know of it now.
type RequestState struct {
	RequestID        string
	RecipientAgentID string
	State            string
	ExpiresAt        time.Time
}

// RequestStateFromVM reads a request the caller sent. Any other request,
// including one the caller received, is ErrNotFound. A request whose closure
// is still waiting for its barriers keeps its active state until it commits.
func (s *Store) RequestStateFromVM(ctx context.Context, caller VMCaller, requestID string) (RequestState, error) {
	if requestID == "" || len(requestID) > 100 {
		return RequestState{}, ErrNotFound
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return RequestState{}, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return RequestState{}, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return RequestState{}, err
	}
	r := RequestState{RequestID: requestID}
	err = tx.QueryRow(ctx, `SELECT recipient_agent_id,state,expires_at FROM agent_requests WHERE id=$1 AND sender_agent_id=$2`,
		requestID, caller.AgentID).Scan(&r.RecipientAgentID, &r.State, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RequestState{}, ErrNotFound
	}
	if err != nil {
		return RequestState{}, err
	}
	return r, commit(ctx, tx)
}
