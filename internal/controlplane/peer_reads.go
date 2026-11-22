package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
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
	// once the deletion of its author purged it. Offboarding the person it is
	// bound to revokes nothing: the request is work accepted before, which
	// may complete for the organization (ADR 002).
	Reply  *wire.PeerPayload
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
//
// capsule-adapter polls this read. It locks the caller's agent, whose
// placement it checks, and the reply's content; neither the recipient's agent
// nor the request, which a pure read does not need (ADR 007 §7): a request's
// parties never change, and a REPLIED request never changes again.
func (t *Transit) RequestStateFromVM(ctx context.Context, caller VMCaller, requestID string) (RequestState, error) {
	if requestID == "" || len(requestID) > 100 {
		return RequestState{}, ErrNotFound
	}
	tx, err := t.store.begin(ctx)
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
	// Any other request, including one the caller received, is not found.
	r := requestRow{ID: requestID, Sender: caller.AgentID}
	err = tx.QueryRow(ctx, `SELECT recipient_agent_id,state,expires_at,payload_ref,reply_ref,payload_hash,reply_hash,via_auto
        FROM agent_requests WHERE id=$1 AND sender_agent_id=$2`, requestID, caller.AgentID).
		Scan(&r.Recipient, &r.State, &r.Deadline, &r.Payload, &r.ReplyPayload, &r.PayloadHash, &r.ReplyHash, &r.ViaAuto)
	if errors.Is(err, pgx.ErrNoRows) {
		return RequestState{}, ErrNotFound
	}
	if err != nil {
		return RequestState{}, err
	}
	state := RequestState{RequestID: r.ID, RecipientAgentID: r.Recipient, State: r.State, ExpiresAt: r.Deadline}
	if r.State == "REPLIED" {
		if state.Reply, state.Reason, err = t.senderReply(ctx, tx, r, agents[caller.AgentID]); err != nil {
			return RequestState{}, err
		}
	}
	return state, commit(ctx, tx)
}

// senderReply reads a REPLIED request's reply for its sender, whose agent the
// caller holds, or says why it is gone. A reply without private content (a
// legacy reference) has neither.
//
// It decides under the lock of the reply's content, so that no purge commits
// between the check and the read. The deletion of either party purges that
// content in the transaction that ends its LIVE phase: content found unpurged
// under the lock has two live parties, and the recipient's agent is read
// without its lock.
func (t *Transit) senderReply(ctx context.Context, tx pgx.Tx, r requestRow, sender agent) (*wire.PeerPayload, string, error) {
	var gone, ended bool
	err := tx.QueryRow(ctx, `SELECT purged_at IS NOT NULL OR coalesce(purge_after<=clock_timestamp(),false),
        coalesce(purge_after<=coalesce(purged_at,clock_timestamp()),false)
        FROM transit_payloads WHERE id=$1 AND kind='reply' AND ref_id=$2 FOR UPDATE`, r.ReplyPayload, r.ID).Scan(&gone, &ended)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if gone {
		// Gone at the end of its retention, it was purged. Gone before, the
		// deletion of a party revoked it.
		if ended {
			return nil, "content_purged", nil
		}
		return nil, "content_revoked", nil
	}
	recipient := agent{ID: r.Recipient}
	if err = tx.QueryRow(ctx, "SELECT coalesce(owner_user_id,''),phase,inbound_mode,discoverable,coalesce(tenant_id,'') FROM agents WHERE id=$1", r.Recipient).
		Scan(&recipient.Owner, &recipient.Phase, &recipient.Mode, &recipient.Visible, &recipient.Tenant); err != nil {
		return nil, "", err
	}
	content, err := t.readPeerContent(ctx, tx, r, map[string]agent{r.Sender: sender, r.Recipient: recipient}, "reply")
	if err == nil {
		return &content.Payload, "", nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	return nil, "content_revoked", nil
}
