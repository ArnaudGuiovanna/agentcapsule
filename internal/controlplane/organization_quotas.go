package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Organization quotas (TEN-007, ADR 021, migration 0046).
//
// The platform operator sets, per organization, how many agents it may hold,
// how much volume storage they reserve, how many of their VMs may run at once
// and the vCPUs and RAM those VMs reserve. Without a quota there is no limit,
// so an installation keeps working as before.
//
//   - Creating an agent past the agents or storage quota, or an agent that
//     alone needs more vCPUs or RAM than the organization may run, is refused
//     with OrganizationQuotaError before anything is reserved.
//   - Booting an agent for work past the active VMs, vCPUs or RAM is refused
//     in the transaction that reserves the boot (claimPlacement). Work does
//     not fail for it: it waits in its host's capacity queue (ADR 017) until
//     the organization has room, or dies at its deadline with
//     capacity_unavailable, like work that waits for a full host.
//
// Every check and every change of an organization's quotas takes the same
// advisory lock, so concurrent creations and boots of one organization, on
// one host or several, never exceed a quota. A boot only for a barrier (a
// fence, a provisioning, a restore) is the platform's, not the
// organization's: it is neither counted nor refused.

// ErrOrganizationQuota is what OrganizationQuotaError matches.
var ErrOrganizationQuota = errors.New("organization quota exceeded")

// ErrQuotaBelowAgent refuses a vCPU or RAM quota smaller than what one of the
// organization's agents needs: that agent could never boot.
var ErrQuotaBelowAgent = errors.New("an agent of the organization needs more than this quota")

// OrganizationQuotaError names the quota that refused, by its field name:
// max_agents, max_storage_mib, max_active_vms, max_vcpus or max_memory_mib.
type OrganizationQuotaError struct{ Quota string }

func (e *OrganizationQuotaError) Error() string {
	return "organization quota exceeded: " + e.Quota
}

func (e *OrganizationQuotaError) Is(target error) bool { return target == ErrOrganizationQuota }

// QuotaBelowAgentError names the quota that one of the organization's agents
// does not fit.
type QuotaBelowAgentError struct{ Quota string }

func (e *QuotaBelowAgentError) Error() string {
	return "an agent of the organization needs more than " + e.Quota
}

func (e *QuotaBelowAgentError) Is(target error) bool { return target == ErrQuotaBelowAgent }

// OrganizationQuotas are an organization's limits; nil is no limit.
type OrganizationQuotas struct {
	MaxAgents     *int   `json:"max_agents"`
	MaxActiveVMs  *int   `json:"max_active_vms"`
	MaxVCPUs      *int   `json:"max_vcpus"`
	MaxMemoryMiB  *int64 `json:"max_memory_mib"`
	MaxStorageMiB *int64 `json:"max_storage_mib"`
}

// OrganizationUsage is what the organization holds now. Agents and storage
// count every agent not yet deleted, the one being provisioned or deleted
// included. Active VMs, vCPUs and RAM count its VMs booted for work that are
// starting, running or stopping, on every host.
type OrganizationUsage struct {
	Agents     int   `json:"agents"`
	StorageMiB int64 `json:"storage_mib"`
	ActiveVMs  int   `json:"active_vms"`
	VCPUs      int   `json:"vcpus"`
	MemoryMiB  int64 `json:"memory_mib"`
}

// OrganizationQuotaStatus is an organization's limits and usage.
type OrganizationQuotaStatus struct {
	OrganizationID string             `json:"organization_id"`
	Limits         OrganizationQuotas `json:"limits"`
	Usage          OrganizationUsage  `json:"usage"`
	// UpdatedAt is when the operator last set the quotas; absent if never.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (q OrganizationQuotas) valid() bool {
	within := func(v *int64, lo, hi int64) bool { return v == nil || (*v >= lo && *v <= hi) }
	small := func(v *int, lo, hi int) bool { return v == nil || (*v >= lo && *v <= hi) }
	return small(q.MaxAgents, 1, 100000) && small(q.MaxActiveVMs, 1, 100000) && small(q.MaxVCPUs, 1, 1000000) &&
		within(q.MaxMemoryMiB, 128, 1<<30) && within(q.MaxStorageMiB, 64, 1<<40)
}

// lockOrganizationQuota serializes the quota checks and changes of tenant. It
// is the last lock its callers take.
func lockOrganizationQuota(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "organization-quota/"+tenant)
	return err
}

// organizationQuotas reads tenant's quotas, and when the operator set them.
func organizationQuotas(ctx context.Context, tx pgx.Tx, tenant string) (OrganizationQuotas, *time.Time, error) {
	var q OrganizationQuotas
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT max_agents,max_active_vms,max_vcpus,max_memory_mib,max_storage_mib,updated_at
        FROM organization_quotas WHERE tenant_id=$1`, tenant).Scan(&q.MaxAgents, &q.MaxActiveVMs, &q.MaxVCPUs, &q.MaxMemoryMiB, &q.MaxStorageMiB, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return q, nil, nil
	}
	return q, &at, err
}

// workVMs are the placements that count against an organization's active VMs,
// vCPUs and RAM: VMs booted for work, starting, running or stopping.
const workVMs = `p.state IN ('STARTING','RUNNING','STOPPING') AND NOT p.fence_only`

// organizationUsage reads what tenant holds; except is an agent whose own VM
// is left out (the one about to boot).
func organizationUsage(ctx context.Context, tx pgx.Tx, tenant, except string) (OrganizationUsage, error) {
	var u OrganizationUsage
	err := tx.QueryRow(ctx, `SELECT
        (SELECT count(*) FROM agents a WHERE a.tenant_id=$1 AND a.phase<>'DELETED'),
        (SELECT coalesce(sum(x.volume_mib),0) FROM agents a JOIN agent_specs x ON x.agent_id=a.id WHERE a.tenant_id=$1 AND a.phase<>'DELETED'),
        count(*),coalesce(sum(x.vcpus),0),coalesce(sum(x.memory_mib),0)
        FROM agents a JOIN agent_specs x ON x.agent_id=a.id JOIN agent_placements p ON p.agent_id=a.id
        WHERE a.tenant_id=$1 AND a.id<>$2 AND `+workVMs, tenant, except).
		Scan(&u.Agents, &u.StorageMiB, &u.ActiveVMs, &u.VCPUs, &u.MemoryMiB)
	return u, err
}

// over says which quota a total exceeds, or "".
func over(limit *int64, total int64, name string) string {
	if limit != nil && total > *limit {
		return name
	}
	return ""
}

func overInt(limit *int, total int, name string) string {
	if limit != nil && total > *limit {
		return name
	}
	return ""
}

func firstOf(names ...string) string {
	for _, n := range names {
		if n != "" {
			return n
		}
	}
	return ""
}

// checkCreationQuota refuses, before any reservation, a new agent of tenant
// with resources r past the agents or storage quota, or one that alone needs
// more vCPUs or RAM than the organization may run. The caller holds the
// organization's row; this takes its quota lock.
func checkCreationQuota(ctx context.Context, tx pgx.Tx, tenant string, r AgentResources) error {
	if err := lockOrganizationQuota(ctx, tx, tenant); err != nil {
		return err
	}
	q, set, err := organizationQuotas(ctx, tx, tenant)
	if err != nil || set == nil {
		return err
	}
	u, err := organizationUsage(ctx, tx, tenant, "")
	if err != nil {
		return err
	}
	if name := firstOf(overInt(q.MaxAgents, u.Agents+1, "max_agents"),
		over(q.MaxStorageMiB, u.StorageMiB+int64(r.DataVolumeMiB), "max_storage_mib"),
		over(q.MaxMemoryMiB, int64(r.MemoryMiB), "max_memory_mib"),
		overInt(q.MaxVCPUs, r.VCPUs, "max_vcpus")); name != "" {
		return &OrganizationQuotaError{Quota: name}
	}
	return nil
}

// checkBootQuota refuses to boot agent a for work when its organization would
// then run more VMs, vCPUs or RAM than its quotas. The caller holds the
// agent's and its placement's locks, and reserves the boot in the same
// transaction when this passes.
func checkBootQuota(ctx context.Context, tx pgx.Tx, a agent) error {
	if a.Tenant == "" {
		return nil
	}
	if err := lockOrganizationQuota(ctx, tx, a.Tenant); err != nil {
		return err
	}
	q, set, err := organizationQuotas(ctx, tx, a.Tenant)
	if err != nil || set == nil || (q.MaxActiveVMs == nil && q.MaxVCPUs == nil && q.MaxMemoryMiB == nil) {
		return err
	}
	u, err := organizationUsage(ctx, tx, a.Tenant, a.ID)
	if err != nil {
		return err
	}
	var vcpus int
	var memory int64
	if err = tx.QueryRow(ctx, "SELECT vcpus,memory_mib FROM agent_specs WHERE agent_id=$1", a.ID).Scan(&vcpus, &memory); err != nil {
		return err
	}
	if name := firstOf(overInt(q.MaxActiveVMs, u.ActiveVMs+1, "max_active_vms"),
		overInt(q.MaxVCPUs, u.VCPUs+vcpus, "max_vcpus"),
		over(q.MaxMemoryMiB, u.MemoryMiB+memory, "max_memory_mib")); name != "" {
		return &OrganizationQuotaError{Quota: name}
	}
	return nil
}

// OrganizationQuotaStatus gives the platform operator an organization's
// quotas and usage.
func (a *Accounts) OrganizationQuotaStatus(ctx context.Context, p Principal, id string) (OrganizationQuotaStatus, error) {
	if !validOrganizationText(id, 100) {
		return OrganizationQuotaStatus{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return OrganizationQuotaStatus{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return OrganizationQuotaStatus{}, err
	}
	if _, err = scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1`, id)); err != nil {
		return OrganizationQuotaStatus{}, err
	}
	out, err := quotaStatus(ctx, tx, id)
	if err != nil {
		return OrganizationQuotaStatus{}, err
	}
	return out, commit(ctx, tx)
}

// CurrentOrganizationQuotas gives an organization's owners, administrators
// and auditors (usage:read) their own quotas and usage.
func (a *Accounts) CurrentOrganizationQuotas(ctx context.Context, p Principal) (OrganizationQuotaStatus, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return OrganizationQuotaStatus{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeUsageRead)
	if err != nil {
		return OrganizationQuotaStatus{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadUsage) {
		return OrganizationQuotaStatus{}, ErrForbidden
	}
	out, err := quotaStatus(ctx, tx, p.TenantID)
	if err != nil {
		return OrganizationQuotaStatus{}, err
	}
	return out, commit(ctx, tx)
}

func quotaStatus(ctx context.Context, tx pgx.Tx, tenant string) (OrganizationQuotaStatus, error) {
	out := OrganizationQuotaStatus{OrganizationID: tenant}
	var err error
	if out.Limits, out.UpdatedAt, err = organizationQuotas(ctx, tx, tenant); err != nil {
		return out, err
	}
	out.Usage, err = organizationUsage(ctx, tx, tenant, "")
	return out, err
}

// SetOrganizationQuotas replaces an organization's quotas: the platform
// operator's act, audited in the organization's trail. A quota below the
// current usage is accepted: nothing running stops and nothing is deleted;
// new creations are refused and new boots wait until usage falls under it.
// A vCPU or RAM quota smaller than one live agent's own need is refused
// (QuotaBelowAgentError): that agent could never boot.
func (a *Accounts) SetOrganizationQuotas(ctx context.Context, p Principal, id, key string, in OrganizationQuotas) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !in.valid() {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withReceipt(ctx, tx, scope(p, "PUT", "/v1/organizations/"+id+"/quotas", key), in, func() (int, any, error) {
		// The same row creations hold, then the same lock boots take.
		if _, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1 FOR UPDATE`, id)); err != nil {
			return 0, nil, err
		}
		if err := lockOrganizationQuota(ctx, tx, id); err != nil {
			return 0, nil, err
		}
		var vcpus int
		var memory int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(x.vcpus),0),coalesce(max(x.memory_mib),0)
            FROM agents a JOIN agent_specs x ON x.agent_id=a.id WHERE a.tenant_id=$1 AND a.phase IN ('PROVISIONING','LIVE')`, id).Scan(&vcpus, &memory); err != nil {
			return 0, nil, err
		}
		if name := firstOf(overInt(in.MaxVCPUs, vcpus, "max_vcpus"), over(in.MaxMemoryMiB, memory, "max_memory_mib")); name != "" {
			return 0, nil, &QuotaBelowAgentError{Quota: name}
		}
		before, set, err := organizationQuotas(ctx, tx, id)
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO organization_quotas(tenant_id,max_agents,max_active_vms,max_vcpus,max_memory_mib,max_storage_mib,updated_by)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id) DO UPDATE SET max_agents=EXCLUDED.max_agents,
            max_active_vms=EXCLUDED.max_active_vms,max_vcpus=EXCLUDED.max_vcpus,max_memory_mib=EXCLUDED.max_memory_mib,
            max_storage_mib=EXCLUDED.max_storage_mib,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`,
			id, in.MaxAgents, in.MaxActiveVMs, in.MaxVCPUs, in.MaxMemoryMiB, in.MaxStorageMiB, p.ID); err != nil {
			return 0, nil, err
		}
		if err = auditOrganization(ctx, tx, p, id, "organization.quotas_set", set == nil || !sameQuotas(before, in)); err != nil {
			return 0, nil, err
		}
		return 200, in, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func sameQuotas(a, b OrganizationQuotas) bool {
	eq := func(x, y *int) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	eq64 := func(x, y *int64) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return eq(a.MaxAgents, b.MaxAgents) && eq(a.MaxActiveVMs, b.MaxActiveVMs) && eq(a.MaxVCPUs, b.MaxVCPUs) &&
		eq64(a.MaxMemoryMiB, b.MaxMemoryMiB) && eq64(a.MaxStorageMiB, b.MaxStorageMiB)
}
