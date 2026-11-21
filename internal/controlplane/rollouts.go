package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type RolloutInput struct {
	Template       string `json:"template,omitempty"`
	MaxUnavailable int    `json:"max_unavailable"`
}
type Rollout struct {
	ID           string            `json:"id"`
	DeploymentID string            `json:"deployment_id,omitempty"`
	AgentID      string            `json:"agent_id,omitempty"`
	Resources    *ComputeResources `json:"resources,omitempty"`
	RolloutInput
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	Total       int    `json:"total"`
	Updated     int    `json:"updated"`
	Maintaining int    `json:"maintaining"`
	// Booted is the count that reached authenticated application readiness on the requested configuration.
	Booted int `json:"booted"`
}

// NULL for template rollouts. The public resource shape is shared with agent resize.
const requestedCompute = `CASE WHEN u.target_agent IS NOT NULL THEN jsonb_build_object('vcpus',u.resize_vcpus,'memory_mib',u.resize_memory_mib) END`

func readRollout(ctx context.Context, tx pgx.Tx, tenant, id string) (Rollout, error) {
	var v Rollout
	err := tx.QueryRow(ctx, `SELECT u.id,coalesce(u.deployment_id,''),coalesce(u.template_name||'@'||u.revision,''),coalesce(u.target_agent,''),`+requestedCompute+`,u.max_unavailable,u.status,u.reason,
 count(s.agent_id),count(*) FILTER (WHERE stage='complete'),count(*) FILTER (WHERE stage IN ('draining','validating','verified')),count(observed_generation)
 FROM agent_rollouts u JOIN agent_rollout_steps s ON s.rollout_id=u.id WHERE u.tenant_id=$1 AND u.id=$2 GROUP BY u.id`, tenant, id).Scan(&v.ID, &v.DeploymentID, &v.Template, &v.AgentID, &v.Resources, &v.MaxUnavailable, &v.Status, &v.Reason, &v.Total, &v.Updated, &v.Maintaining, &v.Booted)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
func (c *AgentCatalog) StartRollout(ctx context.Context, p Principal, dep, key string, in RolloutInput) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "rollout.start/"+dep, key, in, func() (int, any, error) {
		name, rev, err := templateRef(in.Template)
		if err != nil || in.MaxUnavailable < 1 || in.MaxUnavailable > 1000 {
			return 0, nil, ErrInput
		}
		plan, applied, err := pinnedPlan(ctx, tx, p.TenantID, dep)
		if err != nil {
			return 0, nil, err
		}
		if !applied {
			return 0, nil, ErrTransition
		}
		spec, err := readTemplate(ctx, tx, p.TenantID, name, rev)
		if err != nil {
			return 0, nil, err
		}
		release, err := validateTemplate(ctx, tx, p.TenantID, plan.host, spec)
		if err != nil {
			return 0, nil, err
		}
		// A disk resize is a separate archive-backed maintenance operation. The
		// rollout keeps the same encrypted container and its filesystem.
		var diskChange bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM agent_deployment_members m JOIN agent_specs x USING(agent_id) WHERE m.deployment_id=$1 AND x.volume_mib<>$2)`, dep, spec.Resources.DataVolumeMiB).Scan(&diskChange); err != nil {
			return 0, nil, err
		}
		if diskChange {
			return 0, nil, ErrTransition
		}
		var resizing bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM agent_rollouts u JOIN agent_deployment_members m ON m.agent_id=u.target_agent WHERE m.deployment_id=$1 AND u.status<>'completed')`, dep).Scan(&resizing); err != nil {
			return 0, nil, err
		}
		if resizing {
			return 0, nil, ErrTransition
		}
		id := newID("roll")
		changed, err := tx.Exec(ctx, `INSERT INTO agent_rollouts(id,tenant_id,deployment_id,template_name,revision,release_id,max_unavailable,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8) ON CONFLICT DO NOTHING`, id, p.TenantID, dep, name, rev, release, in.MaxUnavailable, p.ID)
		if err != nil {
			return 0, nil, err
		}
		if changed.RowsAffected() != 1 {
			return 0, nil, ErrTransition
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_rollout_steps(rollout_id,agent_id,wave,stage) SELECT $1,agent_id,CASE WHEN ordinal=1 THEN 0 ELSE 1+(ordinal-2)/$3 END,'pending' FROM agent_deployment_members WHERE deployment_id=$2`, id, dep, in.MaxUnavailable)
		if err != nil {
			return 0, nil, err
		}
		if err := auditDeployment(ctx, tx, p, "rollout.started", id); err != nil {
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
func (c *AgentCatalog) GetRollout(ctx context.Context, p Principal, id string) (Rollout, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return Rollout{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return Rollout{}, err
	}
	return readRollout(ctx, tx, p.TenantID, id)
}
func (c *AgentCatalog) ResumeRollout(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "rollout.resume/"+id, key, struct{}{}, func() (int, any, error) {
		changed, err := tx.Exec(ctx, `UPDATE agent_rollouts SET status='running',reason='' WHERE tenant_id=$1 AND id=$2 AND status='paused'`, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if changed.RowsAffected() > 0 {
			if err := auditDeployment(ctx, tx, p, "rollout.resumed", id); err != nil {
				return 0, nil, err
			}
		}
		v, err := readRollout(ctx, tx, p.TenantID, id)
		return 202, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// The first wave contains only the canary. Every member of a wave must have
// finished before any later member becomes visible to a worker.
func (s *Store) NextRollout(ctx context.Context, host string) (string, string, error) {
	var id, agent string
	err := s.pool.QueryRow(ctx, `WITH candidate AS (SELECT s.rollout_id,s.agent_id FROM agent_rollouts u JOIN agent_rollout_steps s ON s.rollout_id=u.id JOIN agent_specs x ON x.agent_id=s.agent_id LEFT JOIN agent_deployments d ON d.id=u.deployment_id
 WHERE coalesce(d.host_id,x.host_id)=$1 AND u.status='running' AND s.stage<>'complete' AND NOT EXISTS(SELECT FROM agent_rollout_steps e WHERE e.rollout_id=u.id AND e.wave<s.wave AND e.stage<>'complete')
 ORDER BY s.attempted_at NULLS FIRST,u.created_at,s.wave,s.agent_id FOR UPDATE OF s SKIP LOCKED LIMIT 1)
 UPDATE agent_rollout_steps s SET attempted_at=clock_timestamp() FROM candidate c
 WHERE (s.rollout_id,s.agent_id)=(c.rollout_id,c.agent_id) RETURNING s.rollout_id,s.agent_id`, host).Scan(&id, &agent)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNoWork
	}
	return id, agent, err
}

type RolloutStep struct {
	ID, Agent, Host, Stage, Tenant, Actor string
	KeepRunning                           bool
	Resize                                bool
	Target                                Enrollment
	Spec                                  TemplateSpec
	Release                               string
}

func (s *Store) RolloutStep(ctx context.Context, id, agent, host string, running bool) (RolloutStep, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return RolloutStep{}, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, agent)
	if err != nil {
		return RolloutStep{}, err
	}
	a := agents[agent]
	var enabled bool
	step := RolloutStep{ID: id, Agent: agent, Host: host}
	err = tx.QueryRow(ctx, `SELECT u.tenant_id,u.created_by,m.stage,coalesce(m.keep_running,$4),u.target_agent IS NOT NULL,
 coalesce(r.spec,jsonb_build_object('resources',jsonb_build_object('vcpus',u.resize_vcpus,'memory_mib',u.resize_memory_mib,'data_volume_mib',x.volume_mib))),
 h.enabled,h.id,h.artifact_digest,h.source,coalesce(h.rootfs_digest,''),coalesce(i.kernel_digest,''),coalesce(i.initrd_digest,'')
 FROM agent_rollout_steps m JOIN agent_rollouts u ON u.id=m.rollout_id JOIN agent_specs x ON x.agent_id=m.agent_id
 LEFT JOIN agent_deployments d ON d.id=u.deployment_id
 LEFT JOIN agent_template_revisions r ON (r.tenant_id,r.name,r.revision)=(u.tenant_id,u.template_name,u.revision)
 JOIN harness_releases h ON h.id=coalesce(u.release_id,x.release_id) LEFT JOIN system_images i ON i.id=coalesce(r.spec->>'system_image',x.system_image)
 WHERE u.id=$1 AND m.agent_id=$2 AND coalesce(d.host_id,x.host_id)=$3 AND u.status='running' AND m.stage<>'complete' FOR UPDATE OF u,m`, id, agent, host, running).Scan(&step.Tenant, &step.Actor, &step.Stage, &step.KeepRunning, &step.Resize, &step.Spec, &enabled, &step.Release, &step.Target.HarnessDigest, &step.Target.HarnessSource, &step.Target.RootfsDigest, &step.Target.SystemImage.Kernel, &step.Target.SystemImage.Initrd)
	if errors.Is(err, pgx.ErrNoRows) {
		return step, ErrTransition
	}
	if err != nil {
		return step, err
	}
	if !enabled {
		return step, ErrRelease
	}
	if a.Phase == "PROVISIONING" {
		return step, ErrNoWork
	}
	if a.Phase != "LIVE" {
		return step, ErrUnavailable
	}
	if step.Stage == "verified" && step.KeepRunning && !running {
		if _, err = tx.Exec(ctx, "UPDATE agent_rollout_steps SET stage='validating' WHERE rollout_id=$1 AND agent_id=$2", id, agent); err != nil {
			return step, err
		}
		step.Stage = "validating"
	}
	step.Target.AgentID = agent
	step.Target.HostID = host
	step.Target.Resources = step.Spec.Resources
	if step.Stage == "pending" {
		var growing bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM agent_volume_growth WHERE agent_id=$1 AND stage IN ('pending','capturing','restoring'))", agent).Scan(&growing); err != nil {
			return step, err
		}
		if growing {
			return step, ErrNoWork
		}
		var busy bool
		if err = tx.QueryRow(ctx, "SELECT "+workInProgress+" FROM agents a WHERE a.id=$1", agent).Scan(&busy); err != nil {
			return step, err
		}
		if busy {
			return step, ErrNoWork
		}
		_, err = tx.Exec(ctx, "UPDATE agent_rollout_steps SET stage='draining',keep_running=$3 WHERE rollout_id=$1 AND agent_id=$2", id, agent, running)
		if err != nil {
			return step, err
		}
		step.Stage = "draining"
	}
	return step, commit(ctx, tx)
}
func (s *Store) InstallRolloutSpec(ctx context.Context, st RolloutStep) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, st.Agent, st.Host)
	if err != nil {
		return err
	}
	if p.State != "STOPPED" || a.Phase != "LIVE" || a.Tenant != st.Tenant {
		return ErrPlacementBusy
	}
	var stage string
	err = tx.QueryRow(ctx, `SELECT m.stage FROM agent_rollout_steps m JOIN agent_rollouts u ON u.id=m.rollout_id WHERE u.status='running' AND m.rollout_id=$1 AND m.agent_id=$2 FOR UPDATE OF m,u`, st.ID, st.Agent).Scan(&stage)
	if err != nil {
		return err
	}
	if stage != "draining" {
		return ErrTransition
	}
	// Recheck the per-agent ceiling under the same lock as normal admission.
	if err = lockOrganizationQuota(ctx, tx, a.Tenant); err != nil {
		return err
	}
	q, _, err := organizationQuotas(ctx, tx, a.Tenant)
	if err != nil {
		return err
	}
	if quota := firstOf(overInt(q.MaxVCPUs, st.Spec.Resources.VCPUs, "max_vcpus"), over(q.MaxMemoryMiB, int64(st.Spec.Resources.MemoryMiB), "max_memory_mib")); quota != "" {
		return &OrganizationQuotaError{Quota: quota}
	}
	if st.Resize {
		tag, err := tx.Exec(ctx, "UPDATE agent_specs SET vcpus=$2,memory_mib=$3 WHERE agent_id=$1 AND volume_mib=$4", st.Agent, st.Spec.Resources.VCPUs, st.Spec.Resources.MemoryMiB, st.Spec.Resources.DataVolumeMiB)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrTransition
		}
	} else if err = installRolloutTemplate(ctx, tx, st); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE agent_rollout_steps SET stage='validating' WHERE rollout_id=$1 AND agent_id=$2", st.ID, st.Agent); err != nil {
		return err
	}
	return commit(ctx, tx)
}
func installRolloutTemplate(ctx context.Context, tx pgx.Tx, st RolloutStep) error {
	var previous *string
	err := tx.QueryRow(ctx, `UPDATE agent_specs SET release_id=$2,system_image=$3,vcpus=$4,memory_mib=$5 WHERE agent_id=$1 AND volume_mib=$6 RETURNING template_grant_id`, st.Agent, st.Release, st.Spec.SystemImage, st.Spec.Resources.VCPUs, st.Spec.Resources.MemoryMiB, st.Spec.Resources.DataVolumeMiB).Scan(&previous)
	if err != nil {
		return err
	}
	bindings, err := resolveCorpusBindings(ctx, tx, st.Tenant, st.Host, st.Spec.SystemImage, st.Spec.Corpora, false)
	if err != nil {
		return err
	}
	changes := &pgx.Batch{}
	changes.Queue("DELETE FROM agent_corpora WHERE agent_id=$1", st.Agent)
	insertCorpusBindings(changes, st.Tenant, []string{st.Agent}, bindings)
	if err = tx.SendBatch(ctx, changes).Close(); err != nil {
		return err
	}
	if previous != nil {
		if _, err = tx.Exec(ctx, "UPDATE llm_alias_grants SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1 AND status='active'", *previous, st.Actor); err != nil {
			return err
		}
	}
	var newGrant *string
	if st.Spec.LLMProfile != "" {
		v := newID("grant")
		tag, err := tx.Exec(ctx, `INSERT INTO llm_alias_grants(id,tenant_id,alias,agent_id,created_by) SELECT $1,$2,alias,$3,$4 FROM llm_model_aliases WHERE tenant_id=$2 AND alias=$5 AND status='active' ON CONFLICT DO NOTHING`, v, st.Tenant, st.Agent, st.Actor, st.Spec.LLMProfile)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			newGrant = &v
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE agent_specs SET template_grant_id=$2 WHERE agent_id=$1", st.Agent, newGrant); err != nil {
		return err
	}
	if st.Spec.Capabilities == nil {
		_, err = tx.Exec(ctx, "DELETE FROM agent_capability_policies WHERE agent_id=$1", st.Agent)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO agent_capability_policies(agent_id,allowed,updated_by) VALUES($1,$2,$3) ON CONFLICT(agent_id) DO UPDATE SET allowed=EXCLUDED.allowed,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`, st.Agent, st.Spec.Capabilities, st.Actor)
	}
	return err
}
func (s *Store) ObserveRolloutBoot(ctx context.Context, st RolloutStep, generation uint64, vm string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_rollout_steps m SET stage='verified',observed_generation=$3,observed_vm=$4 FROM agent_placements p JOIN placement_control_contracts c USING(agent_id,host_id,generation,vm_id)
 JOIN store_enrollments e ON e.agent_id=p.agent_id AND e.incarnation=c.incarnation WHERE m.rollout_id=$1 AND m.agent_id=$2 AND p.agent_id=$2 AND p.generation=$3 AND p.vm_id=$4 AND p.host_id=$5 AND p.state='RUNNING' AND NOT p.fence_only AND m.stage='validating'`, st.ID, st.Agent, generation, vm, st.Host)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrPlacement
	}
	return err
}

// A validation boot waits for a physical slot or tenant allowance. Other
// work retains its slot and a later dispatch pass retries the same member.
func (s *Store) WaitRolloutCapacity(ctx context.Context, st RolloutStep) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_rollouts SET reason='waiting_capacity' WHERE id=$1 AND status='running' AND EXISTS(SELECT FROM agent_rollout_steps WHERE rollout_id=$1 AND agent_id=$2 AND stage='validating')`, st.ID, st.Agent)
	return err
}

func (s *Store) FinishRolloutStep(ctx context.Context, st RolloutStep) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT id FROM agent_rollouts WHERE id=$1 FOR UPDATE", st.ID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_rollout_steps m SET stage='complete' FROM agent_placements p WHERE m.rollout_id=$1 AND m.agent_id=$2 AND p.agent_id=m.agent_id AND m.stage='verified' AND
 ((m.keep_running AND p.state='RUNNING' AND p.generation=m.observed_generation AND p.vm_id=m.observed_vm) OR (NOT m.keep_running AND p.state='STOPPED'))`, st.ID, st.Agent)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrPlacement
	}
	_, err = tx.Exec(ctx, `UPDATE agent_rollouts u SET reason='',status=CASE WHEN EXISTS(SELECT FROM agent_rollout_steps m WHERE m.rollout_id=u.id AND m.stage<>'complete') THEN 'running' ELSE 'completed' END WHERE u.id=$1 AND status='running'`, st.ID)
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}
func (s *Store) PauseRollout(ctx context.Context, id, agent, reason string) error {
	if reason != "artifact_unavailable" && reason != "update_failed" && reason != "agent_unavailable" && reason != "boot_failed" {
		return fmt.Errorf("invalid rollout reason")
	}
	_, err := s.pool.Exec(ctx, `UPDATE agent_rollouts SET status='paused',reason=$3 WHERE id=$1 AND status='running' AND EXISTS(SELECT FROM agent_rollout_steps WHERE rollout_id=$1 AND agent_id=$2 AND stage<>'complete')`, id, agent, reason)
	return err
}

func allowRolloutBoot(ctx context.Context, tx pgx.Tx, agent, rollout string) error {
	var growing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM agent_volume_growth WHERE agent_id=$1 AND stage IN ('capturing','restoring'))`, agent).Scan(&growing); err != nil {
		return err
	}
	if growing {
		return ErrPlacementBusy
	}
	var id, stage, status string
	err := tx.QueryRow(ctx, `SELECT s.rollout_id,s.stage,u.status FROM agent_rollout_steps s JOIN agent_rollouts u ON u.id=s.rollout_id
 WHERE s.agent_id=$1 AND s.stage IN ('draining','validating','verified')`, agent).Scan(&id, &stage, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		if rollout != "" {
			return ErrTransition
		}
		return nil
	}
	if err != nil {
		return err
	}
	if rollout == "" || id != rollout || stage != "validating" || status != "running" {
		return ErrPlacementBusy
	}
	return nil
}
func (s *Store) ClaimRolloutPlacement(ctx context.Context, agent, host, worker, id string, lease time.Duration) (Placement, error) {
	if id == "" {
		return Placement{}, ErrInput
	}
	return s.claimPlacement(ctx, agent, host, worker, lease, placementIntent{rolloutID: id})
}

type RolloutMember struct {
	AgentID      string            `json:"agent_id"`
	Stage        string            `json:"stage"`
	Requested    string            `json:"requested_template,omitempty"`
	Resources    *ComputeResources `json:"requested_resources,omitempty"`
	LastVerified string            `json:"last_verified_template,omitempty"`
	Generation   *uint64           `json:"verified_generation,omitempty"`
}

func (c *AgentCatalog) RolloutMembers(ctx context.Context, p Principal, id, after string, limit int) ([]RolloutMember, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return nil, err
	}
	if len(after) > 100 || limit < 1 || limit > 200 {
		return nil, ErrInput
	}
	if _, err = readRollout(ctx, tx, p.TenantID, id); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT m.agent_id,m.stage,coalesce(u.template_name||'@'||u.revision,''),`+requestedCompute+`,coalesce(v.ref,''),CASE WHEN u.target_agent IS NULL THEN v.generation ELSE m.observed_generation END
 FROM agent_rollout_steps m JOIN agent_rollouts u ON u.id=m.rollout_id
 LEFT JOIN LATERAL (SELECT z.template_name||'@'||z.revision ref,b.observed_generation generation FROM agent_rollout_steps b JOIN agent_rollouts z ON z.id=b.rollout_id
 WHERE b.agent_id=m.agent_id AND z.template_name IS NOT NULL AND b.observed_generation IS NOT NULL ORDER BY b.observed_generation DESC LIMIT 1) v ON true
 WHERE u.tenant_id=$1 AND u.id=$2 AND m.agent_id>$3 ORDER BY m.agent_id LIMIT $4`, p.TenantID, id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RolloutMember{}
	for rows.Next() {
		var v RolloutMember
		if err = rows.Scan(&v.AgentID, &v.Stage, &v.Requested, &v.Resources, &v.LastVerified, &v.Generation); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
