package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// NextWarmAgent is a hint. ClaimWarmPlacement repeats this selection while
// reserving a generation. An in-flight ordinary boot already fills one place.
func (s *Store) NextWarmAgent(ctx context.Context, host string) (string, error) {
	return nextWarmAgent(ctx, s.pool, host, "")
}

func nextWarmAgent(ctx context.Context, db rowQuerier, host, candidate string) (string, error) {
	var id string
	err := db.QueryRow(ctx, `WITH `+quotaWaiters+`, physical AS (
 SELECT count(*) AS slots,coalesce(sum(coalesce(x.vcpus,1)),0) AS cpus,coalesce(sum(coalesce(x.memory_mib,256)+256),0) AS memory
 FROM agent_placements p LEFT JOIN agent_specs x USING(agent_id)
 WHERE p.host_id=$1 AND p.state IN ('STARTING','RUNNING','STOPPING')
 ), under_target AS (
 SELECT d.id,d.applied_at FROM agent_deployments d JOIN agent_deployment_members m ON m.deployment_id=d.id
 LEFT JOIN agent_placements p USING(agent_id)
 WHERE d.host_id=$1 AND d.applied_at IS NOT NULL AND d.active_count>0
 AND NOT EXISTS(SELECT FROM agent_rollouts r WHERE r.deployment_id=d.id AND r.status<>'completed')
 AND NOT EXISTS(SELECT FROM agent_rollouts r JOIN agent_deployment_members m2 ON m2.agent_id=r.target_agent WHERE m2.deployment_id=d.id AND r.status<>'completed')
 GROUP BY d.id HAVING count(*) FILTER(WHERE p.state IN ('STARTING','RUNNING') AND NOT p.fence_only)<d.active_count
 )
 SELECT m.agent_id FROM under_target d JOIN agent_deployment_members m ON m.deployment_id=d.id
 JOIN agents a ON a.id=m.agent_id JOIN organizations o ON o.id=a.tenant_id
 JOIN agent_specs x USING(agent_id) JOIN store_enrollments e USING(agent_id) JOIN agent_placements p USING(agent_id)
 JOIN deployment_hosts h ON h.host_id=p.host_id CROSS JOIN physical
 LEFT JOIN organization_quotas q ON q.tenant_id=a.tenant_id LEFT JOIN used u ON u.tenant_id=a.tenant_id
 WHERE ($2='' OR m.agent_id=$2) AND a.phase='LIVE' AND o.status='active' AND e.stage='READY' AND p.state='STOPPED'
 AND physical.slots + 1 + EXISTS(SELECT FROM worker_jobs j WHERE j.host_id=$1 AND j.kind='provision')::int <= h.max_active
 AND physical.cpus+x.vcpus<=h.vcpus AND physical.memory+x.memory_mib+256<=h.memory_mib
 AND (q.max_active_vms IS NULL OR coalesce(u.vms,0)+1<=q.max_active_vms)
 AND (q.max_vcpus IS NULL OR coalesce(u.vcpus,0)+x.vcpus<=q.max_vcpus)
 AND (q.max_memory_mib IS NULL OR coalesce(u.memory,0)+x.memory_mib<=q.max_memory_mib)
 AND NOT EXISTS(SELECT FROM waiting w WHERE NOT w.held OR w.agent_id IN (SELECT id FROM agents WHERE tenant_id=a.tenant_id))
 AND NOT EXISTS(SELECT FROM failed_agents f WHERE f.agent_id=m.agent_id)
 AND NOT EXISTS(SELECT FROM agent_volume_growth g WHERE g.agent_id=m.agent_id AND g.stage IN ('pending','capturing','restoring'))
 AND coalesce((SELECT kind FROM platform_operations op WHERE op.agent_id=m.agent_id
       AND op.kind IN ('sleep','wake') AND op.status IN ('PENDING','RUNNING','SUCCEEDED') ORDER BY op.seq DESC LIMIT 1),'')<>'sleep'
 ORDER BY d.applied_at,d.id,x.auto_start DESC,m.ordinal LIMIT 1`, host, candidate).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNoWork
	}
	return id, err
}

func (s *Store) ClaimWarmPlacement(ctx context.Context, id, host, worker string, lease time.Duration) (Placement, error) {
	return s.claimPlacement(ctx, id, host, worker, lease, placementIntent{warm: true})
}
