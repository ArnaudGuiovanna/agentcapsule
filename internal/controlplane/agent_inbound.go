package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// InboundPolicy says how requests from the other agents of the organization
// reach one of its agents: accepted by policy ("auto": delivered at once) or
// held for approval ("manual", the default). A held request waits until a
// person of the organization accepts or declines it (DecideHeldRequest), its
// deadline passes or its sender cancels it.
type InboundPolicy struct {
	AgentID string `json:"agent_id"`
	Mode    string `json:"mode"`
}

// SetInboundPolicy sets how a live organization agent accepts requests from
// the organization's other agents. Who may deliver work to an agent is an
// authorization rule: a change bumps the organization's policy version. It
// applies to requests submitted afterwards; a request already held for
// approval stays held.
func (c *AgentCatalog) SetInboundPolicy(ctx context.Context, p Principal, id, key, mode string) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) || (mode != "auto" && mode != "manual") {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	a, _, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return APIReceipt{}, err
	}
	body := InboundPolicy{AgentID: id, Mode: mode}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.inbound/"+id, key, body, func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		tag, err := tx.Exec(ctx, "UPDATE agents SET inbound_mode=$2 WHERE id=$1 AND inbound_mode<>$2", id, mode)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 1 {
			if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
				return 0, nil, err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action)
            VALUES($1,$2,$3,$4,'agent.inbound_changed')`, newID("audit"), p.TenantID, p.ID, id); err != nil {
			return 0, nil, err
		}
		return 200, body, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// GetInboundPolicy reports an agent's inbound policy to whoever may read the
// agent's metadata.
func (c *AgentCatalog) GetInboundPolicy(ctx context.Context, p Principal, id string) (InboundPolicy, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return InboundPolicy{}, ErrInput
	}
	if _, err := c.getTenant(ctx, p, id); err != nil {
		return InboundPolicy{}, err
	}
	out := InboundPolicy{AgentID: id}
	if err := c.accounts.store.pool.QueryRow(ctx, "SELECT inbound_mode FROM agents WHERE id=$1 AND tenant_id=$2", id, p.TenantID).Scan(&out.Mode); err != nil {
		return InboundPolicy{}, err
	}
	return out, nil
}
