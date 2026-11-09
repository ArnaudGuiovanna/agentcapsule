package controlplane

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// ReleaseChange asks to pin an agent to another release.
type ReleaseChange struct {
	Harness HarnessReference `json:"harness"`
}

// AgentRelease answers a release change: the release the agent is pinned to
// now, the one it had, and when the change takes effect.
type AgentRelease struct {
	AgentID  string           `json:"agent_id"`
	Harness  HarnessReference `json:"harness"`
	Previous HarnessReference `json:"previous"`
	// Applies is "next_boot": a running VM keeps the harness it booted with
	// until it stops. Nothing is restarted by the change itself.
	Applies string `json:"applies"`
}

// ChangeAgentRelease pins a live agent to another approved, non-deprecated
// release: an upgrade, or a rollback to the release it had. Its data volume is
// kept; migrating data between harness versions is the harness's job. The
// worker boots the new release the next time the agent starts, and refuses to
// boot it if the host does not hold a verified copy.
func (c *AgentCatalog) ChangeAgentRelease(ctx context.Context, p Principal, id, key string, in ReleaseChange) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !catalogName(in.Harness.Name) || !catalogName(in.Harness.Version) {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	tenant := p.Kind == "tenant"
	var a agent
	var legacy receiptScope
	if tenant {
		if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
			return APIReceipt{}, err
		}
		if a, _, err = tenantAgentForUpdate(ctx, tx, p, id); err != nil {
			return APIReceipt{}, err
		}
	} else {
		legacy = scope(p, "POST", "/v1/agents/"+id+"/release", key)
		if err = lockHTTPReceipt(ctx, tx, legacy); err != nil {
			return APIReceipt{}, err
		}
		if err = agentPermission(ctx, tx, p, "agent:manage"); err != nil {
			return APIReceipt{}, err
		}
		agents, err := lockAgents(ctx, tx, id)
		if err != nil {
			return APIReceipt{}, err
		}
		var ok bool
		if a, ok = agents[id]; !ok || a.Tenant != "" || (p.Kind != "service" && a.Owner != p.ID) {
			return APIReceipt{}, ErrNotFound
		}
	}
	body := struct {
		AgentID string           `json:"agent_id"`
		Harness HarnessReference `json:"harness"`
	}{id, in.Harness}
	change := func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		out := AgentRelease{AgentID: id, Harness: in.Harness, Applies: "next_boot"}
		var current string
		err := tx.QueryRow(ctx, `SELECT r.id,r.name,r.version FROM agent_specs x JOIN harness_releases r ON r.id=x.release_id
            WHERE x.agent_id=$1`, id).Scan(&current, &out.Previous.Name, &out.Previous.Version)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		}
		if err != nil {
			return 0, nil, err
		}
		var target string
		err = tx.QueryRow(ctx, "SELECT id FROM harness_releases WHERE name=$1 AND version=$2 AND enabled FOR SHARE",
			in.Harness.Name, in.Harness.Version).Scan(&target)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrRelease
		}
		if err != nil || target == current {
			return 200, out, err
		}
		if _, err = tx.Exec(ctx, "UPDATE agent_specs SET release_id=$2 WHERE agent_id=$1", id, target); err != nil {
			return 0, nil, err
		}
		if tenant {
			// Not an authorization change: no policy version bump.
			if _, err = tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action,release_id)
                VALUES($1,$2,$3,$4,'agent.release_changed',$5)`, newID("audit"), p.TenantID, p.ID, id, target); err != nil {
				return 0, nil, err
			}
		}
		return 200, out, nil
	}
	var result APIReceipt
	if tenant {
		result, err = c.accounts.withTenantReceipt(ctx, tx, p, "agent.release/"+id, key, body, change)
	} else {
		result, err = c.accounts.withReceipt(ctx, tx, legacy, body, change)
	}
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}
