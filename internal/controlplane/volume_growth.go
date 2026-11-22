package controlplane

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/workqueue"
	"github.com/jackc/pgx/v5"
)

func auditDeployment(ctx context.Context, tx pgx.Tx, p Principal, action, target string) error {
	_, err := tx.Exec(ctx, "INSERT INTO deployment_audit(id,tenant_id,actor,action,target) VALUES($1,$2,$3,$4,$5)", newID("audit"), p.TenantID, p.ID, action, target)
	return err
}

type GrowthInput struct {
	SizeMiB int `json:"size_mib"`
}
type VolumeGrowth struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	ArchiveID string `json:"archive_id"`
	RestoreID string `json:"restore_id"`
	Previous  int    `json:"previous_mib"`
	Target    int    `json:"target_mib"`
	Stage     string `json:"stage"`
	Reason    string `json:"reason,omitempty"`
}

const growthColumns = "id,agent_id,archive_id,restore_id,old_mib,target_mib,stage,reason"

func scanGrowth(row pgx.Row) (VolumeGrowth, error) {
	var g VolumeGrowth
	err := row.Scan(&g.ID, &g.AgentID, &g.ArchiveID, &g.RestoreID, &g.Previous, &g.Target, &g.Stage, &g.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return g, err
}
func (c *AgentCatalog) RequestGrowth(ctx context.Context, p Principal, agent, key string, in GrowthInput) (APIReceipt, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	host, err := maintenanceHost(ctx, tx, p, agent)
	if err != nil {
		return APIReceipt{}, err
	}
	out, err := c.accounts.withTenantReceipt(ctx, tx, p, "volume.grow/"+agent, key, in, func() (int, any, error) {
		a, err := lockMaintenanceAgent(ctx, tx, p, agent, host)
		if err != nil {
			return 0, nil, err
		}
		if in.SizeMiB < 64 || in.SizeMiB > 32768 {
			return 0, nil, ErrInput
		}
		var size int
		if err := tx.QueryRow(ctx, "SELECT volume_mib FROM agent_specs WHERE agent_id=$1", agent).Scan(&size); err != nil {
			return 0, nil, err
		}
		if a.Phase != "LIVE" || in.SizeMiB <= size {
			return 0, nil, ErrTransition
		}
		var busy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM agent_rollout_steps m JOIN agent_rollouts u ON u.id=m.rollout_id WHERE m.agent_id=$1 AND (m.stage IN ('draining','validating','verified') OR (u.target_agent=$1 AND u.status<>'completed'))) OR EXISTS(SELECT FROM store_enrollments WHERE agent_id=$1 AND stage<>'READY')`, agent).Scan(&busy); err != nil {
			return 0, nil, err
		}
		if busy {
			return 0, nil, ErrTransition
		}
		if err := refuseUnderDataPressure(ctx, tx, host); err != nil {
			return 0, nil, err
		}
		if err := lockOrganizationQuota(ctx, tx, p.TenantID); err != nil {
			return 0, nil, err
		}
		status, err := quotaStatus(ctx, tx, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		delta := int64(in.SizeMiB - size)
		if q := status.Limits.MaxStorageMiB; q != nil && delta+status.Usage.StorageMiB > *q {
			return 0, nil, &OrganizationQuotaError{Quota: "max_storage_mib"}
		}
		var room bool
		if err = tx.QueryRow(ctx, `SELECT storage_limit_mib >= $2::bigint+(SELECT coalesce(sum(x.volume_mib+x.reserved_growth_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=$1 AND a.phase<>'DELETED') FROM worker_hosts WHERE host_id=$1`, host, delta).Scan(&room); err != nil {
			return 0, nil, err
		}
		if !room {
			return 0, nil, ErrStorageCapacity
		}
		g, err := scanGrowth(tx.QueryRow(ctx, `INSERT INTO agent_volume_growth(id,tenant_id,agent_id,host_id,old_mib,target_mib,archive_id,restore_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING `+growthColumns, newID("grow"), p.TenantID, agent, host, size, in.SizeMiB, newID("arc"), newID("rst")))
		if errors.Is(err, ErrNotFound) {
			return 0, nil, ErrTransition
		}
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, "UPDATE agent_specs SET reserved_growth_mib=$2 WHERE agent_id=$1", agent, delta); err != nil {
			return 0, nil, err
		}
		return 202, g, auditDeployment(ctx, tx, p, "volume.growth_requested", agent)
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}
func (c *AgentCatalog) GetGrowth(ctx context.Context, p Principal, id string) (VolumeGrowth, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return VolumeGrowth{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return VolumeGrowth{}, err
	}
	return scanGrowth(tx.QueryRow(ctx, "SELECT "+growthColumns+" FROM agent_volume_growth WHERE tenant_id=$1 AND id=$2", p.TenantID, id))
}
func (s *Store) NextGrowth(ctx context.Context, host string) (VolumeGrowth, error) {
	return scanGrowth(s.pool.QueryRow(ctx, `UPDATE agent_volume_growth SET attempted_at=clock_timestamp() WHERE id=(SELECT id FROM agent_volume_growth WHERE host_id=$1 AND stage IN ('pending','capturing','restoring') ORDER BY attempted_at NULLS FIRST,created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+growthColumns, host))
}
func (s *Store) AdvanceGrowth(ctx context.Context, g VolumeGrowth, to string) error {
	return s.advanceGrowth(ctx, g, to, "")
}
func (s *Store) RefuseGrowth(ctx context.Context, g VolumeGrowth, reason string) error {
	if reason != "guest_incompatible" && reason != "archive_unconfigured" {
		return ErrInput
	}
	return s.advanceGrowth(ctx, g, "refused", reason)
}
func (s *Store) advanceGrowth(ctx context.Context, g VolumeGrowth, to, reason string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, g.AgentID)
	if err != nil {
		return err
	}
	_, ok := agents[g.AgentID]
	if !ok {
		return ErrNotFound
	}
	legal := (g.Stage == "pending" && (to == "capturing" || to == "refused")) || (g.Stage == "capturing" && to == "restoring") || (g.Stage == "restoring" && to == "succeeded")
	if !legal || (to == "refused" && reason == "") {
		return ErrTransition
	}
	if to == "capturing" {
		var busy bool
		if err := tx.QueryRow(ctx, `SELECT `+workqueue.WorkInProgress+` OR a.phase<>'LIVE' FROM agents a WHERE a.id=$1`, g.AgentID).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return ErrNoWork
		}
	}
	if to == "succeeded" {
		var restored bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM volume_restores WHERE restore_id=$1 AND step='SUCCEEDED' AND grow_to_mib=$2)", g.RestoreID, g.Target).Scan(&restored); err != nil {
			return err
		}
		if !restored {
			return ErrRestore
		}
	}
	tag, err := tx.Exec(ctx, "UPDATE agent_volume_growth SET stage=$2,reason=$4 WHERE id=$1 AND stage=$3", g.ID, to, g.Stage, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrTransition
	}
	if to == "refused" {
		if _, err = tx.Exec(ctx, "UPDATE agent_specs SET reserved_growth_mib=0 WHERE agent_id=$1", g.AgentID); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}
func (s *Store) GrowthForRestore(ctx context.Context, id string) (VolumeGrowth, error) {
	return scanGrowth(s.pool.QueryRow(ctx, "SELECT "+growthColumns+" FROM agent_volume_growth WHERE restore_id=$1 AND stage='restoring'", id))
}

// CommitRestoredSize records the expanded container and the transition to
// restricted verification together. A crash can replay the install until then.
func (s *Store) CommitRestoredSize(ctx context.Context, id, host string, target int) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	plan, a, err := restorePlan(ctx, tx, id, host)
	if err != nil {
		return err
	}
	if plan.Restore.Step != RestoreInstalling || plan.Placement.State != "STOPPED" || (a.Phase != "LIVE" && a.Phase != "QUIESCING") {
		return ErrRestore
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_specs SET volume_mib=$2,reserved_growth_mib=0
 WHERE agent_id=$1 AND (volume_mib=$2 OR (volume_mib+reserved_growth_mib=$2 AND EXISTS(SELECT FROM agent_volume_growth WHERE restore_id=$3 AND agent_id=$1 AND stage='restoring' AND target_mib=$2)))`, a.ID, target, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrRestore
	}
	if _, err = tx.Exec(ctx, "UPDATE volume_restores SET grow_to_mib=$2,step=$3 WHERE restore_id=$1", id, target, RestoreReconciling); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// PreviouslyGrownSize identifies an earlier capacity of the same immutable agent.
func (s *Store) PreviouslyGrownSize(ctx context.Context, agent string, old int) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM agent_volume_growth WHERE agent_id=$1 AND old_mib=$2 AND stage='succeeded')", agent, old).Scan(&ok)
	return ok, err
}
