package controlplane

import (
	"context"
	"errors"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/jackc/pgx/v5"
)

// ErrCapability: the agent's effective capabilities do not include the one
// its call needs, because its harness did not request it or a policy denies
// it. The platform channel answers capability_denied.
var ErrCapability = errors.New("capability not granted to this agent")

// CapabilityPolicy is what an organization, or one of its agents, allows.
// Allowed is replaced as a whole; every known capability is the default.
type CapabilityPolicy struct {
	Allowed []string `json:"allowed"`
}

// AgentCapabilities is the catalog of one agent's capabilities (EXT-003):
// what its pinned release requests, what its organization and the agent
// allow, and their intersection, which the platform channel enforces.
type AgentCapabilities struct {
	AgentID string           `json:"agent_id"`
	Release HarnessReference `json:"release"`
	// Requested is what the release's harness.yaml requests. Declared is
	// false for a release whose manifest predates the field: it is treated
	// as requesting every capability.
	Requested    []string `json:"requested"`
	Declared     bool     `json:"declared"`
	Organization []string `json:"organization"`
	Agent        []string `json:"agent"`
	Effective    []string `json:"effective"`
}

// releaseCapabilities is what a release requests; NULL means not declared.
func releaseCapabilities(declared []string) ([]string, bool) {
	if declared == nil {
		return capability.Known(), false
	}
	return capability.Intersect(declared), true
}

// capabilitiesOf reads an agent's catalog in tx. The agent must exist.
func capabilitiesOf(ctx context.Context, tx pgx.Tx, agentID string) (AgentCapabilities, error) {
	out := AgentCapabilities{AgentID: agentID}
	var requested, org, own []string
	err := tx.QueryRow(ctx, `SELECT r.name,r.version,r.capabilities,o.allowed,p.allowed
        FROM agents a JOIN agent_specs x ON x.agent_id=a.id JOIN harness_releases r ON r.id=x.release_id
        LEFT JOIN organization_capability_policies o ON o.tenant_id=a.tenant_id
        LEFT JOIN agent_capability_policies p ON p.agent_id=a.id
        WHERE a.id=$1`, agentID).Scan(&out.Release.Name, &out.Release.Version, &requested, &org, &own)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.Requested, out.Declared = releaseCapabilities(requested)
	out.Organization, out.Agent = capability.Known(), capability.Known()
	if org != nil {
		out.Organization = capability.Intersect(org)
	}
	if own != nil {
		out.Agent = capability.Intersect(own)
	}
	out.Effective = capability.Intersect(out.Requested, out.Organization, out.Agent)
	return out, nil
}

// RequireCapabilityFromVM refuses a platform channel call whose capability is
// not in the calling agent's effective set. It is read at each call, so a
// policy change applies to the next one. The caller's identity comes from the
// authenticated channel; the effect itself rechecks its placement.
func (s *Store) RequireCapabilityFromVM(ctx context.Context, caller VMCaller, name string) error {
	if caller.AgentID == "" || capability.ValidSet([]string{name}) != nil {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	c, err := capabilitiesOf(ctx, tx, caller.AgentID)
	if err != nil {
		return err
	}
	if !slices.Contains(c.Effective, name) {
		return ErrCapability
	}
	return commit(ctx, tx)
}

// AgentCapabilities shows an agent's catalog to whoever may read its metadata.
func (c *AgentCatalog) AgentCapabilities(ctx context.Context, p Principal, id string) (AgentCapabilities, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return AgentCapabilities{}, ErrNotFound
	}
	if _, err := c.getTenant(ctx, p, id); err != nil {
		return AgentCapabilities{}, err
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return AgentCapabilities{}, err
	}
	defer rollback(tx)
	out, err := capabilitiesOf(ctx, tx, id)
	if err != nil {
		return AgentCapabilities{}, err
	}
	return out, commit(ctx, tx)
}

// SetAgentCapabilities replaces what one live agent allows. Allowing a
// capability its harness does not request or its organization denies grants
// nothing: the effective set stays the intersection. Who may call the
// platform for what is an authorization rule: a change bumps the
// organization's policy version and is audited.
func (c *AgentCatalog) SetAgentCapabilities(ctx context.Context, p Principal, id, key string, in CapabilityPolicy) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) || in.Allowed == nil || capability.ValidSet(in.Allowed) != nil {
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
	allowed := capability.Intersect(in.Allowed)
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.capabilities/"+id, key, CapabilityPolicy{Allowed: allowed}, func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_capability_policies(agent_id,allowed,updated_by) VALUES($1,$2,$3)
            ON CONFLICT (agent_id) DO UPDATE SET allowed=EXCLUDED.allowed,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`,
			id, allowed, p.ID); err != nil {
			return 0, nil, err
		}
		if err := capabilityChanged(ctx, tx, p, &id, "agent.capabilities_changed"); err != nil {
			return 0, nil, err
		}
		out, err := capabilitiesOf(ctx, tx, id)
		return 200, out, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// OrganizationCapabilities shows what the organization allows.
func (a *Accounts) OrganizationCapabilities(ctx context.Context, p Principal) (CapabilityPolicy, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return CapabilityPolicy{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeOrganizationRead)
	if err != nil {
		return CapabilityPolicy{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadOrganizationMetadata) {
		return CapabilityPolicy{}, ErrForbidden
	}
	out, err := organizationPolicy(ctx, tx, p.TenantID)
	if err != nil {
		return CapabilityPolicy{}, err
	}
	return out, commit(ctx, tx)
}

func organizationPolicy(ctx context.Context, tx pgx.Tx, tenant string) (CapabilityPolicy, error) {
	var allowed []string
	err := tx.QueryRow(ctx, "SELECT allowed FROM organization_capability_policies WHERE tenant_id=$1", tenant).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return CapabilityPolicy{Allowed: capability.Known()}, nil
	}
	if err != nil {
		return CapabilityPolicy{}, err
	}
	return CapabilityPolicy{Allowed: capability.Intersect(allowed)}, nil
}

// SetOrganizationCapabilities replaces what the organization's agents may be
// allowed, for owners and administrators (quota:manage). It applies to the
// next call of every agent.
func (a *Accounts) SetOrganizationCapabilities(ctx context.Context, p Principal, key string, in CapabilityPolicy) (APIReceipt, error) {
	if in.Allowed == nil || capability.ValidSet(in.Allowed) != nil {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	allowed := CapabilityPolicy{Allowed: capability.Intersect(in.Allowed)}
	r, err := a.withTenantReceipt(ctx, tx, p, "organization.capabilities", key, allowed, func() (int, any, error) {
		if _, err := tx.Exec(ctx, `INSERT INTO organization_capability_policies(tenant_id,allowed,updated_by) VALUES($1,$2,$3)
            ON CONFLICT (tenant_id) DO UPDATE SET allowed=EXCLUDED.allowed,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`,
			p.TenantID, allowed.Allowed, p.ID); err != nil {
			return 0, nil, err
		}
		if err := capabilityChanged(ctx, tx, p, nil, "organization.capabilities_changed"); err != nil {
			return 0, nil, err
		}
		return 200, allowed, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func capabilityChanged(ctx context.Context, tx pgx.Tx, p Principal, agentID *string, action string) error {
	if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, p.TenantID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO capability_audit(id,tenant_id,actor_principal_id,agent_id,action) VALUES($1,$2,$3,$4,$5)`,
		newID("audit"), p.TenantID, p.ID, agentID, action)
	return err
}
