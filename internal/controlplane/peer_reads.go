package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
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
	// Reply is the reply of a REPLIED request while it is kept, read by
	// Transit.RequestStateFromVM only. Reason says why a REPLIED request has
	// none there: content_purged at the end of its retention, content_revoked
	// once its author is deleted or the person it is bound to lost access.
	Reply  *capsuleprotocol.PeerPayload
	Reason string
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

// RequestStateFromVM is Store.RequestStateFromVM with the reply (ADR 007): the
// sender's agent reads it whether its delivery is pending, delivered or dead.
// The reply event stays the way a reply arrives; this read is how the agent
// catches up. The content is read with the checks of the owners' read.
func (t *Transit) RequestStateFromVM(ctx context.Context, caller VMCaller, requestID string) (RequestState, error) {
	if requestID == "" || len(requestID) > 100 {
		return RequestState{}, ErrNotFound
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return RequestState{}, err
	}
	defer rollback(tx)
	// Participants never change. Both agents of the caller's own request are
	// locked in the common order before the request; any other request is
	// not found, once the caller is authorized.
	var sender, recipient string
	err = tx.QueryRow(ctx, "SELECT sender_agent_id,recipient_agent_id FROM agent_requests WHERE id=$1", requestID).Scan(&sender, &recipient)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return RequestState{}, err
	}
	ids := []string{caller.AgentID}
	if sender == caller.AgentID {
		ids = append(ids, recipient)
	}
	agents, err := lockAgents(ctx, tx, ids...)
	if err != nil {
		return RequestState{}, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return RequestState{}, err
	}
	if sender != caller.AgentID {
		return RequestState{}, ErrNotFound
	}
	r, agents, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return RequestState{}, err
	}
	state := RequestState{RequestID: r.ID, RecipientAgentID: r.Recipient, State: r.State, ExpiresAt: r.Deadline}
	if r.State == "REPLIED" {
		if state.Reply, state.Reason, err = t.senderReply(ctx, tx, r, agents); err != nil {
			return RequestState{}, err
		}
	}
	return state, commit(ctx, tx)
}

// senderReply reads a REPLIED request's reply for its sender, or says why it
// is gone. A reply without private content (a legacy reference) has neither.
func (t *Transit) senderReply(ctx context.Context, tx pgx.Tx, r requestRow, agents map[string]agent) (*capsuleprotocol.PeerPayload, string, error) {
	var purged bool
	err := tx.QueryRow(ctx, `SELECT purged_at IS NOT NULL OR coalesce(purge_after<=clock_timestamp(),false)
        FROM transit_payloads WHERE id=$1 AND kind='reply' AND ref_id=$2`, r.ReplyPayload, r.ID).Scan(&purged)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	content, err := t.readPeerContent(ctx, tx, r, agents, "reply")
	if err == nil {
		return &content.Payload, "", nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	// Deleting the author purges its content at once: that is a revocation,
	// not the end of the retention.
	if agents[r.Recipient].Phase == "LIVE" && purged {
		return nil, "content_purged", nil
	}
	return nil, "content_revoked", nil
}
