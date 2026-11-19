package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

type ComputeResources struct {
	VCPUs     int `json:"vcpus"`
	MemoryMiB int `json:"memory_mib"`
}

// With zero new agents and zero new warm reservations, the deployment capacity
// check admits an individually bootable CPU/RAM profile. The validation boot
// competes for aggregate quota and real host slots under the normal boot locks.
func (c *AgentCatalog) ResizeAgent(ctx context.Context, p Principal, agentID, key string, in ComputeResources) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	host, err := maintenanceHost(ctx, tx, p, agentID)
	if err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.resize/"+agentID, key, in, func() (int, any, error) {
		a, err := lockMaintenanceAgent(ctx, tx, p, agentID, host)
		if err != nil {
			return 0, nil, err
		}
		var original AgentResources
		var ready, busy bool
		err = tx.QueryRow(ctx, `SELECT x.vcpus,x.memory_mib,x.volume_mib,
 EXISTS(SELECT FROM store_enrollments e WHERE e.agent_id=x.agent_id AND e.stage='READY'),
 EXISTS(SELECT FROM agent_rollout_steps m JOIN agent_rollouts u ON u.id=m.rollout_id WHERE m.agent_id=x.agent_id AND u.status<>'completed')
 OR EXISTS(SELECT FROM agent_volume_growth g WHERE g.agent_id=x.agent_id AND g.stage IN ('pending','capturing','restoring'))
 FROM agent_specs x WHERE x.agent_id=$1`, agentID).Scan(&original.VCPUs, &original.MemoryMiB, &original.DataVolumeMiB, &ready, &busy)
		if err != nil {
			return 0, nil, err
		}
		target := AgentResources{VCPUs: in.VCPUs, MemoryMiB: in.MemoryMiB, DataVolumeMiB: original.DataVolumeMiB}
		if !target.valid() {
			return 0, nil, ErrInput
		}
		if a.Phase != "LIVE" || !ready || busy || target == original {
			return 0, nil, ErrTransition
		}
		plan, err := planCapacityLocked(ctx, tx, p.TenantID, host, DeploymentRequest{Resources: &target})
		if err != nil {
			return 0, nil, err
		}
		if err = plan.shortfall(); err != nil {
			return 0, nil, err
		}
		id := newID("roll")
		_, err = tx.Exec(ctx, `INSERT INTO agent_rollouts(id,tenant_id,target_agent,resize_vcpus,resize_memory_mib,max_unavailable,status,created_by)
 VALUES($1,$2,$3,$4,$5,1,'running',$6)`, id, p.TenantID, agentID, in.VCPUs, in.MemoryMiB, p.ID)
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO agent_rollout_steps(rollout_id,agent_id,wave,stage) VALUES($1,$2,0,'pending')", id, agentID); err != nil {
			return 0, nil, err
		}
		if err = auditDeployment(ctx, tx, p, "agent.resize_requested", agentID); err != nil {
			return 0, nil, err
		}
		v, err := readRollout(ctx, tx, p.TenantID, id)
		return 202, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}
