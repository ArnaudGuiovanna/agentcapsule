package controlplane

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// HeldRequest is what a person deciding on a request held for approval sees:
// which agent sends it, on behalf of whom, and until when. Its content belongs
// to the person whose invocation granted the sender's mandate (D-02), so
// deciding never reveals it.
type HeldRequest struct {
	ID            string    `json:"id"`
	SenderAgentID string    `json:"sender_agent_id"`
	RequestedBy   string    `json:"requested_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// HeldRequestDecision is the outcome of an approval: DELIVERING once accepted,
// DECLINED once declined.
type HeldRequestDecision struct {
	RequestID string `json:"request_id"`
	State     State  `json:"state"`
}

// authorizeHeldRequests resolves the caller's current authority and decides
// whether it may approve requests to recipient, an agent of the caller's
// organization: whoever may configure the agent (the right that sets its
// inbound policy), or whoever is assigned to it with invoke. An agent the
// caller cannot see is not found; one it can see but not decide for is
// forbidden.
func authorizeHeldRequests(ctx context.Context, tx pgx.Tx, p Principal, recipient string) error {
	if !tenantBound(p) {
		return ErrForbidden
	}
	// Either scope may carry the decision; authorizeTenant needs one the token
	// holds, and the decision below checks each scope against its own rule.
	scope := authorization.ScopeAgentInvoke
	if slices.Contains(tenantScopes(p), authorization.ScopeAgentManage) {
		scope = authorization.ScopeAgentManage
	}
	current, err := authorizeTenant(ctx, tx, p, scope)
	if err != nil {
		return err
	}
	var found bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1 AND tenant_id=$2 AND phase<>'DELETED')", recipient, p.TenantID).Scan(&found); err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, recipient)
	if err != nil {
		return err
	}
	access := tenantAccess(p)
	if authorization.CanAdminister(access, authorization.Role(current.Role), authorization.ConfigureAgent) ||
		authorization.CanAccessAssignedAgent(access, authorization.InvokeAgent, toPermissions(perms)) {
		return nil
	}
	if canSeeTenantAgent(p, current.Role, perms) {
		return ErrForbidden
	}
	return ErrNotFound
}

// HeldRequests lists the requests held for approval by one agent of the
// organization, the nearest deadline first. A request past its deadline, or
// closing, is no longer listed: it can no longer be accepted.
func (c *AgentCatalog) HeldRequests(ctx context.Context, p Principal, recipient, after string, limit int) ([]HeldRequest, error) {
	if p.Kind != "tenant" || !validOrganizationText(recipient, 100) || limit < 1 || limit > 100 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizeHeldRequests(ctx, tx, p, recipient); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT r.id,r.sender_agent_id,coalesce(o.requested_by_principal_id,''),r.created_at,r.expires_at
        FROM agent_requests r
        LEFT JOIN owner_instructions i ON i.mandate_id=r.mandate_id
        LEFT JOIN platform_operations o ON o.id=i.operation_id
        WHERE r.recipient_agent_id=$1 AND r.state='PENDING_APPROVAL' AND r.expires_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM request_closures x WHERE x.request_id=r.id)
          AND ($2='' OR (r.expires_at,r.id)>(SELECT expires_at,id FROM agent_requests WHERE id=$2 AND recipient_agent_id=$1))
        ORDER BY r.expires_at,r.id LIMIT $3`, recipient, after, limit)
	if err != nil {
		return nil, err
	}
	items := []HeldRequest{}
	for rows.Next() {
		var h HeldRequest
		if err = rows.Scan(&h.ID, &h.SenderAgentID, &h.RequestedBy, &h.CreatedAt, &h.ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, h)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}

// DecideHeldRequest accepts or declines one request held for approval by an
// agent of the organization. Accepting delivers it as the policy "auto" would
// have, still under the sender's mandate; declining tells the sender. Both
// agents must still be live. The authority is read in this transaction, before
// any replay, so a revoked member or assignment is refused even with a key it
// used before. One key decides one request once.
func (c *AgentCatalog) DecideHeldRequest(ctx context.Context, p Principal, recipient, requestID, key string, accept bool) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(recipient, 100) || !validOrganizationText(requestID, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizeHeldRequests(ctx, tx, p, recipient); err != nil {
		return APIReceipt{}, err
	}
	var sender string
	var deadline time.Time
	err = tx.QueryRow(ctx, "SELECT sender_agent_id,expires_at FROM agent_requests WHERE id=$1 AND recipient_agent_id=$2", requestID, recipient).Scan(&sender, &deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	agents, err := lockAgents(ctx, tx, sender, recipient)
	if err != nil {
		return APIReceipt{}, err
	}
	decision, state, action := "decline", State("DECLINED"), "agent.request_declined"
	if accept {
		decision, state, action = "accept", Delivering, "agent.request_accepted"
	}
	body := HeldRequestDecision{RequestID: requestID, State: state}
	input := struct {
		Decision string `json:"decision"`
	}{decision}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.held_request/"+requestID, key, input, func() (int, any, error) {
		if agents[sender].Phase != "LIVE" || agents[recipient].Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		update := `UPDATE agent_requests SET state='DECLINED',decided_by=$2,decided_at=clock_timestamp()`
		if accept {
			update = `UPDATE agent_requests SET state='DELIVERING',accepted=true,decided_by=$2,decided_at=clock_timestamp()`
		}
		tag, err := tx.Exec(ctx, update+` WHERE id=$1 AND state='PENDING_APPROVAL' AND expires_at>clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM request_closures WHERE request_id=$1)`, requestID, p.ID)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, ErrTransition
		}
		if accept {
			err = enqueueRequest(ctx, tx, requestID, recipient, deadline)
		} else {
			err = notifyTerminal(ctx, tx, requestID, sender, recipient, agents)
		}
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action,request_id)
            VALUES($1,$2,$3,$4,$5,$6)`, newID("audit"), p.TenantID, p.ID, recipient, action, requestID); err != nil {
			return 0, nil, err
		}
		return 200, body, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}
