package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"

	"github.com/jackc/pgx/v5"
)

type ImageDigests struct {
	Kernel string `json:"kernel_digest"`
	Initrd string `json:"initrd_digest"`
}
type SystemImage struct {
	ID string `json:"reference"` // name@version
	ImageDigests
}
type HostProvisioningBudget struct {
	MaxActive, VCPUs, UIDSlots int
	MemoryMiB                  int64 // memory dedicated to the VMs including their VMMs
}

// ReportDeploymentHost replaces the verified local inventory at worker startup.
func (s *Store) ReportDeploymentHost(ctx context.Context, host string, budget HostProvisioningBudget, images []ImageDigests) error {
	if !catalogName(host) || budget.MaxActive < 1 || budget.VCPUs < 1 || budget.UIDSlots < 1 || budget.MemoryMiB < 1 || len(images) == 0 {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO deployment_hosts(host_id,max_active,vcpus,memory_mib,uid_slots) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(host_id) DO UPDATE SET max_active=EXCLUDED.max_active,vcpus=EXCLUDED.vcpus,memory_mib=EXCLUDED.memory_mib,uid_slots=EXCLUDED.uid_slots,observed_at=clock_timestamp()`,
		host, budget.MaxActive, budget.VCPUs, budget.MemoryMiB, budget.UIDSlots)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM host_system_images WHERE host_id=$1", host); err != nil {
		return err
	}
	for _, i := range images {
		if !validArtifactDigest(i.Kernel) || !validArtifactDigest(i.Initrd) {
			return ErrInput
		}
		if _, err = tx.Exec(ctx, "INSERT INTO host_system_images VALUES($1,$2,$3) ON CONFLICT DO NOTHING", host, i.Kernel, i.Initrd); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}
func imageID(id string) bool {
	name, version, ok := strings.Cut(id, "@")
	return ok && catalogName(name) && catalogName(version) && len(id) <= 100
}
func (c *AgentCatalog) ApproveSystemImage(ctx context.Context, p Principal, key string, in SystemImage) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	if !imageID(in.ID) || !validArtifactDigest(in.Kernel) || !validArtifactDigest(in.Initrd) {
		return APIReceipt{}, ErrInput
	}
	out, err := c.accounts.withReceipt(ctx, tx, scope(p, "POST", "/v1/system-images", key), in, func() (int, any, error) {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO system_images(id,kernel_digest,initrd_digest,approved_by) VALUES($1,$2,$3,$4)
 ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE (system_images.kernel_digest,system_images.initrd_digest)=(EXCLUDED.kernel_digest,EXCLUDED.initrd_digest) RETURNING id`, in.ID, in.Kernel, in.Initrd, p.ID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrTransition
		}
		return 201, in, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}
func (c *AgentCatalog) SystemImages(ctx context.Context, p Principal, after string, limit int) ([]SystemImage, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if len(after) > 100 || limit < 1 || limit > 200 {
		return nil, ErrInput
	}
	if p.Kind == "platform" {
		err = authorizePlatform(ctx, tx, p)
	} else {
		var current CurrentOrganization
		current, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
		if err == nil && !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata) {
			err = ErrForbidden
		}
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT i.id,i.kernel_digest,i.initrd_digest FROM system_images i JOIN host_system_images h USING(kernel_digest,initrd_digest) WHERE h.host_id=$1 AND i.id>$2 ORDER BY i.id LIMIT $3`, c.host, after, limit)
	if err != nil {
		return nil, err
	}
	items := []SystemImage{}
	defer rows.Close()
	for rows.Next() {
		var v SystemImage
		if err := rows.Scan(&v.ID, &v.Kernel, &v.Initrd); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

type TemplateSpec struct {
	Name         string           `json:"name"`
	SystemImage  string           `json:"system_image"`
	Harness      HarnessReference `json:"harness"`
	Resources    AgentResources   `json:"resources"`
	LLMProfile   string           `json:"llm_profile,omitempty"` // existing model alias
	Capabilities []string         `json:"capabilities"`
}
type TemplateRevision struct {
	TemplateSpec
	Revision  int    `json:"revision"`
	Reference string `json:"reference"`
}

func (r AgentResources) valid() bool {
	return r.VCPUs >= 1 && r.VCPUs <= 8 && r.MemoryMiB >= 128 && r.MemoryMiB <= 8192 && r.DataVolumeMiB >= 64 && r.DataVolumeMiB <= 32768
}
func templateRef(v string) (string, int, error) {
	name, rev, ok := strings.Cut(v, "@")
	n, e := strconv.Atoi(rev)
	if !ok || !catalogName(name) || e != nil || n <= 0 || n > 2147483647 {
		return "", 0, ErrInput
	}
	return name, n, nil
}
func (c *AgentCatalog) templateMutation(ctx context.Context, p Principal, key, op string, in any, f func(pgx.Tx) (int, any, error)) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.CreateAgent); err != nil {
		return APIReceipt{}, err
	}
	out, err := c.accounts.withTenantReceipt(ctx, tx, p, op, key, in, func() (int, any, error) { return f(tx) })
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}
func validateTemplate(ctx context.Context, tx pgx.Tx, tenant, host string, s TemplateSpec) (string, error) {
	if !catalogName(s.Name) || len(s.Name) > 75 || !imageID(s.SystemImage) || !catalogName(s.Harness.Name) || !catalogName(s.Harness.Version) || !s.Resources.valid() || capability.ValidSet(s.Capabilities) != nil {
		return "", ErrInput
	}
	var release string
	err := tx.QueryRow(ctx, `SELECT r.id FROM harness_releases r,system_images i JOIN host_system_images h USING(kernel_digest,initrd_digest)
 WHERE h.host_id=$1 AND i.id=$2 AND r.name=$3 AND r.version=$4 AND r.enabled AND (r.source='oci' OR r.artifact_digest=i.initrd_digest) FOR SHARE OF r,i,h`, host, s.SystemImage, s.Harness.Name, s.Harness.Version).Scan(&release)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRelease
	}
	if err != nil {
		return "", err
	}
	if s.LLMProfile != "" {
		var alias string
		err = tx.QueryRow(ctx, `SELECT m.alias FROM llm_model_aliases m JOIN llm_providers p ON (p.tenant_id,p.id)=(m.tenant_id,m.provider_id) WHERE m.tenant_id=$1 AND m.alias=$2 AND m.status='active' AND p.status='active' FOR SHARE OF m,p`, tenant, s.LLMProfile).Scan(&alias)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
	}
	return release, err
}
func (c *AgentCatalog) PublishTemplate(ctx context.Context, p Principal, key string, in TemplateSpec) (APIReceipt, error) {
	return c.templateMutation(ctx, p, key, "template.publish", in, func(tx pgx.Tx) (int, any, error) {
		if _, err := validateTemplate(ctx, tx, p.TenantID, c.host, in); err != nil {
			return 0, nil, err
		}
		if in.LLMProfile != "" {
			if _, err := authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
				return 0, nil, err
			}
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		var rev int
		err = tx.QueryRow(ctx, `INSERT INTO agent_template_revisions(tenant_id,name,revision,spec,published_by) SELECT $1,$2,coalesce(max(revision),0)+1,$3,$4 FROM agent_template_revisions WHERE tenant_id=$1 AND name=$2 RETURNING revision`, p.TenantID, in.Name, raw, p.ID).Scan(&rev)
		if err == nil {
			err = auditDeployment(ctx, tx, p, "template.published", p.TenantID)
		}
		return 201, TemplateRevision{in, rev, fmt.Sprintf("%s@%d", in.Name, rev)}, err
	})
}

type DeploymentRequest struct {
	Template    string          `json:"template"`
	Count       int             `json:"count"`
	ActiveCount int             `json:"active_count"`
	Resources   *AgentResources `json:"resources,omitempty"`
}
type ResourceCheck struct {
	Resource  string `json:"resource"`
	Required  int64  `json:"required"`
	Available *int64 `json:"available"` // nil for an unlimited organization quota
}
type DeploymentPlan struct {
	ID string `json:"id"`
	DeploymentRequest
	Admitted   bool            `json:"admitted"`
	Checks     []ResourceCheck `json:"checks"`
	MeasuredAt time.Time       `json:"host_observed_at"`
}
type DeploymentShortfall ResourceCheck

func (e *DeploymentShortfall) Error() string { return "insufficient " + e.Resource }

func planCapacity(ctx context.Context, tx pgx.Tx, tenant, host string, in DeploymentRequest) (DeploymentPlan, error) {
	plan := DeploymentPlan{DeploymentRequest: in, Admitted: true}
	if err := lockWorkerHost(ctx, tx, host); err != nil {
		return plan, err
	}
	if err := lockOrganizationQuota(ctx, tx, tenant); err != nil {
		return plan, err
	}
	org, err := quotaStatus(ctx, tx, tenant)
	if err != nil {
		return plan, err
	}
	var slots, vcpus, uidSlots int
	var mem, storage int64
	err = tx.QueryRow(ctx, `SELECT h.max_active,h.vcpus,h.memory_mib,h.uid_slots,w.storage_limit_mib,h.observed_at FROM deployment_hosts h JOIN worker_hosts w USING(host_id) WHERE h.host_id=$1`, host).Scan(&slots, &vcpus, &mem, &uidSlots, &storage, &plan.MeasuredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return plan, ErrUnavailable
	}
	if err != nil {
		return plan, err
	}
	var usedStorage, usedMem, tenantMem int64
	var usedSlots, usedCPUs, usedUIDs, tenantSlots, tenantCPUs int
	// A deployment keeps its warm reservation between boots. Count already
	// active members first so an on-demand boot can satisfy its target.
	err = tx.QueryRow(ctx, `WITH members AS (
 SELECT a.tenant_id,x.volume_mib+x.reserved_growth_mib AS volume_mib,x.vcpus,x.memory_mib,a.phase,
 d.id AS deployment_id, d.active_count,x.auto_start, m.ordinal,
 (coalesce(p.state IN ('STARTING','RUNNING','STOPPING') AND NOT p.fence_only,false) OR
  (m.agent_id IS NULL AND x.auto_start AND a.phase='PROVISIONING') OR EXISTS(SELECT FROM platform_operations o WHERE o.agent_id=a.id AND o.kind='wake' AND o.status IN ('PENDING','RUNNING'))) AS committed
 FROM agent_specs x JOIN agents a ON a.id=x.agent_id LEFT JOIN agent_placements p ON p.agent_id=a.id
 LEFT JOIN agent_deployment_members m ON m.agent_id=a.id LEFT JOIN agent_deployments d ON d.id=m.deployment_id WHERE x.host_id=$1
 ), reservations AS (
 SELECT *, committed OR (deployment_id IS NOT NULL AND phase IN ('LIVE','PROVISIONING') AND row_number() OVER
 (PARTITION BY deployment_id ORDER BY (phase IN ('LIVE','PROVISIONING')) DESC,committed DESC,auto_start DESC,ordinal)<=active_count) AS warm FROM members)
 SELECT count(*),coalesce(sum(volume_mib) FILTER(WHERE phase<>'DELETED'),0),count(*) FILTER(WHERE warm),
 coalesce(sum(vcpus) FILTER(WHERE warm),0),coalesce(sum(memory_mib+256) FILTER(WHERE warm),0),
 count(*) FILTER(WHERE warm AND tenant_id=$2),coalesce(sum(vcpus) FILTER(WHERE warm AND tenant_id=$2),0),coalesce(sum(memory_mib) FILTER(WHERE warm AND tenant_id=$2),0) FROM reservations`, host, tenant).Scan(&usedUIDs, &usedStorage, &usedSlots, &usedCPUs, &usedMem, &tenantSlots, &tenantCPUs, &tenantMem)
	if err != nil {
		return plan, err
	}
	r := in.Resources
	add := func(resource string, required int64, available *int64) {
		plan.Checks = append(plan.Checks, ResourceCheck{resource, required, available})
		if available != nil && required > *available {
			plan.Admitted = false
		}
	}
	quota := func(v *int64, used int64) *int64 {
		if v == nil {
			return nil
		}
		remaining := max(*v-used, 0)
		return &remaining
	}
	widen := func(v *int) *int64 {
		if v == nil {
			return nil
		}
		n := int64(*v)
		return &n
	}
	free := func(n int64) *int64 { v := max(n, 0); return &v }
	n, active := int64(in.Count), int64(in.ActiveCount)
	add("max_agents", n, quota(widen(org.Limits.MaxAgents), int64(org.Usage.Agents)))
	add("max_storage_mib", n*int64(r.DataVolumeMiB), quota(org.Limits.MaxStorageMiB, org.Usage.StorageMiB))
	add("max_active_vms", active, quota(widen(org.Limits.MaxActiveVMs), int64(tenantSlots)))
	add("max_vcpus", active*int64(r.VCPUs), quota(widen(org.Limits.MaxVCPUs), int64(tenantCPUs)))
	add("max_memory_mib", active*int64(r.MemoryMiB), quota(org.Limits.MaxMemoryMiB, tenantMem))
	// Even a cold agent must be individually bootable.
	add("agent_vcpus", int64(r.VCPUs), widen(org.Limits.MaxVCPUs))
	add("agent_memory_mib", int64(r.MemoryMiB), org.Limits.MaxMemoryMiB)
	add("host_uid_slots", n, free(int64(uidSlots-usedUIDs)))
	add("host_storage_mib", n*int64(r.DataVolumeMiB), free(storage-usedStorage))
	add("host_active_vms", active, free(int64(slots-usedSlots)))
	add("host_vcpus", active*int64(r.VCPUs), free(int64(vcpus-usedCPUs)))
	add("host_memory_mib", active*int64(r.MemoryMiB+256), free(mem-usedMem))
	add("host_agent_vcpus", int64(r.VCPUs), free(int64(vcpus)))
	add("host_agent_memory_mib", int64(r.MemoryMiB+256), free(mem))
	if err := refuseUnderDataPressure(ctx, tx, host); err != nil {
		return plan, err
	}
	return plan, nil
}

func readTemplate(ctx context.Context, tx pgx.Tx, tenant, name string, rev int) (TemplateSpec, error) {
	var spec TemplateSpec
	err := tx.QueryRow(ctx, "SELECT spec FROM agent_template_revisions WHERE tenant_id=$1 AND name=$2 AND revision=$3", tenant, name, rev).Scan(&spec)
	if errors.Is(err, pgx.ErrNoRows) {
		return spec, ErrNotFound
	}
	return spec, err
}
func (c *AgentCatalog) PlanDeployment(ctx context.Context, p Principal, key string, in DeploymentRequest) (APIReceipt, error) {
	return c.templateMutation(ctx, p, key, "deployment.plan", in, func(tx pgx.Tx) (int, any, error) {
		name, rev, err := templateRef(in.Template)
		if err != nil || in.Count < 1 || in.Count > 100000 || in.ActiveCount < 0 || in.ActiveCount > in.Count {
			return 0, nil, ErrInput
		}
		s, err := readTemplate(ctx, tx, p.TenantID, name, rev)
		if err != nil {
			return 0, nil, err
		}
		if in.Resources != nil {
			s.Resources = *in.Resources
		}
		in.Resources = &s.Resources
		if _, err = validateTemplate(ctx, tx, p.TenantID, c.host, s); err != nil {
			return 0, nil, err
		}
		plan, err := planCapacity(ctx, tx, p.TenantID, c.host, in)
		if err != nil {
			return 0, nil, err
		}
		plan.ID = newID("dep")
		_, err = tx.Exec(ctx, `INSERT INTO agent_deployments(id,tenant_id,template_name,revision,host_id,requested_count,active_count,resources,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, plan.ID, p.TenantID, name, rev, c.host, in.Count, in.ActiveCount, s.Resources, p.ID)
		if err == nil {
			err = auditDeployment(ctx, tx, p, "deployment.planned", plan.ID)
		}
		return 201, plan, err
	})
}

type DeploymentStatus struct {
	ID              string `json:"id"`
	Template        string `json:"template"`
	Status          string `json:"status"`
	Count           int    `json:"count"`
	DesiredActive   int    `json:"active_count"`
	Provisioned     int    `json:"provisioned"`
	Active          int    `json:"active"`
	Pending         int    `json:"pending"`
	WaitingCapacity int    `json:"waiting_capacity"`
	Failed          int    `json:"failed"`
}

func deploymentStatus(ctx context.Context, tx pgx.Tx, tenant, id string) (DeploymentStatus, error) {
	var d DeploymentStatus
	var applied bool
	err := tx.QueryRow(ctx, `SELECT id,template_name||'@'||revision,requested_count,active_count,applied_at IS NOT NULL FROM agent_deployments WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&d.ID, &d.Template, &d.Count, &d.DesiredActive, &applied)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.Status = "planned"
	if !applied {
		return d, nil
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE e.stage='READY'),count(*) FILTER (WHERE p.state='RUNNING' AND NOT p.fence_only AND pc.agent_id IS NOT NULL),
 count(*) FILTER (WHERE q.agent_id IS NOT NULL OR (e.stage IN ('INSTALLING','FENCING') AND w.capacity_wait)),
 count(*) FILTER (WHERE a.id IS NULL OR a.phase IN ('QUIESCING','DELETING','DELETED') OR f.agent_id IS NOT NULL)
 FROM agent_deployment_members m LEFT JOIN agents a ON a.id=m.agent_id LEFT JOIN store_enrollments e ON e.agent_id=a.id
 LEFT JOIN agent_placements p ON p.agent_id=a.id LEFT JOIN placement_control_contracts pc ON pc.agent_id=a.id AND pc.generation=p.generation AND pc.vm_id=p.vm_id AND pc.host_id=p.host_id AND pc.incarnation=e.incarnation
 LEFT JOIN capacity_waits q ON q.agent_id=a.id LEFT JOIN failed_agents f ON f.agent_id=a.id
 LEFT JOIN worker_jobs w ON w.agent_id=a.id AND w.kind='provision' AND w.object_id=e.operation_id WHERE m.deployment_id=$1`, id).Scan(&d.Provisioned, &d.Active, &d.WaitingCapacity, &d.Failed)
	d.Pending = d.Count - d.Provisioned
	switch {
	case d.Failed > 0:
		d.Status = "failed"
	case d.Pending > 0:
		d.Status = "provisioning"
	case d.Active < d.DesiredActive:
		d.Status = "starting"
	default:
		d.Status = "ready"
	}
	return d, err
}

func (c *AgentCatalog) GetDeployment(ctx context.Context, p Principal, id string) (DeploymentStatus, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return DeploymentStatus{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.CreateAgent); err != nil {
		return DeploymentStatus{}, err
	}
	return deploymentStatus(ctx, tx, p.TenantID, id)
}

type reservationPlan struct {
	DeploymentRequest
	spec          TemplateSpec
	host, release string
}

func pinnedPlan(ctx context.Context, tx pgx.Tx, tenant, id string) (reservationPlan, bool, error) {
	var plan reservationPlan
	var name string
	var rev int
	var applied bool
	var r AgentResources
	err := tx.QueryRow(ctx, `SELECT host_id,template_name,revision,requested_count,active_count,resources,applied_at IS NOT NULL FROM agent_deployments WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&plan.host, &name, &rev, &plan.Count, &plan.ActiveCount, &r, &applied)
	if errors.Is(err, pgx.ErrNoRows) {
		return plan, false, ErrNotFound
	}
	if err != nil {
		return plan, false, err
	}
	plan.Template = fmt.Sprintf("%s@%d", name, rev)
	plan.spec, err = readTemplate(ctx, tx, tenant, name, rev)
	plan.spec.Resources = r
	plan.Resources = &plan.spec.Resources
	return plan, applied, err
}
func (plan *reservationPlan) admit(ctx context.Context, tx pgx.Tx, tenant string) error {
	var err error
	plan.release, err = validateTemplate(ctx, tx, tenant, plan.host, plan.spec)
	if err != nil {
		return err
	}
	status, err := planCapacity(ctx, tx, tenant, plan.host, plan.DeploymentRequest)
	if err != nil {
		return err
	}
	for _, v := range status.Checks {
		if v.Available != nil && *v.Available < v.Required {
			e := DeploymentShortfall(v)
			return &e
		}
	}
	return nil
}

// reserveAgents publishes all logical identities, immutable volume enrollments and
// provision operations atomically. Physical work uses the existing leased queue.
// The set-based inserts keep a thousand-agent campaign independent of SQL latency.
func (plan *reservationPlan) reserveAgents(ctx context.Context, tx pgx.Tx, p Principal) ([]string, error) {
	ids, ops, vols := make([]string, plan.Count), make([]string, plan.Count), make([]string, plan.Count)
	for i := range ids {
		ids[i] = newID("agt")
		ops[i] = newID("op")
		vols[i] = newID("vol")
	}
	r := plan.Resources
	b := &pgx.Batch{}
	b.Queue("INSERT INTO agents(id,tenant_id,phase) SELECT id,$2,'PROVISIONING' FROM unnest($1::text[]) id", ids, p.TenantID)
	b.Queue(`INSERT INTO agent_specs(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start,system_image) SELECT id,$2||'-'||ord,$3,$4,$5,$6,$7,ord>$8,$9 FROM unnest($1::text[]) WITH ORDINALITY i(id,ord)`, ids, plan.spec.Name, plan.release, plan.host, r.VCPUs, r.MemoryMiB, r.DataVolumeMiB, plan.Count-plan.ActiveCount, plan.spec.SystemImage)
	b.Queue(`INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind) SELECT op,$3,id,$4,1,'provision' FROM unnest($1::text[],$2::text[]) i(id,op)`, ids, ops, p.ID, plan.host)
	b.Queue(`INSERT INTO store_enrollments(agent_id,operation_id,volume_id) SELECT * FROM unnest($1::text[],$2::text[],$3::text[])`, ids, ops, vols)
	b.Queue(`INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action) SELECT audit,$2,$3,id,'agent.created' FROM unnest($1::text[],$4::text[]) i(id,audit)`, ids, p.TenantID, p.ID, deploymentIDs("audit", len(ids)))
	if plan.spec.Capabilities != nil {
		b.Queue(`INSERT INTO agent_capability_policies(agent_id,allowed,updated_by) SELECT id,$2,$3 FROM unnest($1::text[]) id`, ids, plan.spec.Capabilities, p.ID)
	}
	if alias := plan.spec.LLMProfile; alias != "" {
		grants := deploymentIDs("grant", len(ids))
		b.Queue(`INSERT INTO llm_alias_grants(id,tenant_id,alias,agent_id,created_by) SELECT grant_id,$2,$3,id,$4 FROM unnest($1::text[],$5::text[]) i(id,grant_id)`, ids, p.TenantID, alias, p.ID, grants)
		b.Queue(`UPDATE agent_specs x SET template_grant_id=v.grant_id FROM unnest($1::text[],$2::text[]) v(id,grant_id) WHERE x.agent_id=v.id`, ids, grants)
	}
	return ids, tx.SendBatch(ctx, b).Close()
}
func (c *AgentCatalog) ApplyDeployment(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	return c.templateMutation(ctx, p, key, "deployment.apply/"+id, struct{}{}, func(tx pgx.Tx) (int, any, error) {
		plan, applied, err := pinnedPlan(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if !applied {
			if err = plan.admit(ctx, tx, p.TenantID); err != nil {
				return 0, nil, err
			}
			ids, err := plan.reserveAgents(ctx, tx, p)
			if err != nil {
				return 0, nil, err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO agent_deployment_members(tenant_id,deployment_id,ordinal,agent_id) SELECT $1,$2,ord,id FROM unnest($3::text[]) WITH ORDINALITY i(id,ord)`, p.TenantID, id, ids); err != nil {
				return 0, nil, err
			}
			if _, err = tx.Exec(ctx, "UPDATE agent_deployments SET applied_at=clock_timestamp() WHERE id=$1", id); err != nil {
				return 0, nil, err
			}
		}
		if !applied {
			if err := auditDeployment(ctx, tx, p, "deployment.applied", id); err != nil {
				return 0, nil, err
			}
		}
		out, err := deploymentStatus(ctx, tx, p.TenantID, id)
		return 202, out, err
	})
}

type PoolInput struct {
	Name         string `json:"name"`
	DeploymentID string `json:"deployment_id"`
}
type AgentPool struct {
	ID string `json:"id"`
	PoolInput
	Total     int `json:"total"`
	Available int `json:"available"`
	Preparing int `json:"preparing"`
}

func poolInventory(ctx context.Context, tx pgx.Tx, tenant, id string) (AgentPool, error) {
	var p AgentPool
	err := tx.QueryRow(ctx, `SELECT p.id,p.name,p.deployment_id,count(m.agent_id),count(v.agent_id) FILTER(WHERE a.phase='LIVE'),count(v.agent_id) FILTER(WHERE a.phase='PROVISIONING')
 FROM agent_pools p LEFT JOIN agent_pool_members m ON m.pool_id=p.id LEFT JOIN `+assignablePoolInventory+` v ON v.agent_id=m.agent_id LEFT JOIN agents a ON a.id=m.agent_id
 WHERE p.tenant_id=$1 AND p.id=$2 GROUP BY p.id`, tenant, id).Scan(&p.ID, &p.Name, &p.DeploymentID, &p.Total, &p.Available, &p.Preparing)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}
func (c *AgentCatalog) CreatePool(ctx context.Context, p Principal, key string, in PoolInput) (APIReceipt, error) {
	return c.templateMutation(ctx, p, key, "pool.create", in, func(tx pgx.Tx) (int, any, error) {
		if !catalogName(in.Name) {
			return 0, nil, ErrInput
		}
		_, applied, err := pinnedPlan(ctx, tx, p.TenantID, in.DeploymentID)
		if err != nil {
			return 0, nil, err
		}
		if !applied {
			return 0, nil, ErrTransition
		}
		id := newID("pool")
		tag, err := tx.Exec(ctx, "INSERT INTO agent_pools(id,tenant_id,name,deployment_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", id, p.TenantID, in.Name, in.DeploymentID)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, ErrTransition
		}
		if _, err = tx.Exec(ctx, `INSERT INTO agent_pool_members SELECT tenant_id,$2,agent_id FROM agent_deployment_members WHERE deployment_id=$1`, in.DeploymentID, id); err != nil {
			return 0, nil, err
		}
		if err := auditDeployment(ctx, tx, p, "pool.created", id); err != nil {
			return 0, nil, err
		}
		out, err := poolInventory(ctx, tx, p.TenantID, id)
		return 201, out, err
	})
}
func (c *AgentCatalog) GetPool(ctx context.Context, p Principal, id string) (AgentPool, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return AgentPool{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.CreateAgent); err != nil {
		return AgentPool{}, err
	}
	return poolInventory(ctx, tx, p.TenantID, id)
}

type ExpandPoolInput struct {
	Count int `json:"count"`
}

func (c *AgentCatalog) ExpandPool(ctx context.Context, p Principal, id, key string, in ExpandPoolInput) (APIReceipt, error) {
	return c.templateMutation(ctx, p, key, "pool.expand/"+id, in, func(tx pgx.Tx) (int, any, error) {
		if _, err := reservePoolAgents(ctx, tx, p, id, in.Count); err != nil {
			return 0, nil, err
		}
		out, err := poolInventory(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return 200, out, auditApplication(ctx, tx, p, id, "pool.expanded")
	})
}

func reservePoolAgents(ctx context.Context, tx pgx.Tx, p Principal, poolID string, count int) ([]string, error) {
	if count < 1 || count > 100000 {
		return nil, ErrInput
	}
	var id string
	err := tx.QueryRow(ctx, "SELECT deployment_id FROM agent_pools WHERE tenant_id=$1 AND id=$2", p.TenantID, poolID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plan, _, err := pinnedPlan(ctx, tx, p.TenantID, id)
	if err != nil {
		return nil, err
	}
	plan.Count, plan.ActiveCount = count, 0
	if err = plan.admit(ctx, tx, p.TenantID); err != nil {
		return nil, err
	}
	ids, err := plan.reserveAgents(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO agent_pool_members(tenant_id,pool_id,agent_id) SELECT $1,$2,unnest($3::text[])", p.TenantID, poolID, ids)
	return ids, err
}

func deploymentIDs(kind string, n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = newID(kind)
	}
	return ids
}
