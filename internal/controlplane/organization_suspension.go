package controlplane

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// A disabled organization's work stops (docs/api/organizations.md,
// "Disabling"). Its members and tokens lose access at once, through the
// tenant routes' authentication; here the work that runs without a tenant
// request stops too: a scheduled invocation is not released, a wake is
// canceled, an agent of the organization cannot send to another, a delivery
// to one of its agents is not claimed and boots no VM, and its running VMs
// are put to sleep through the ordinary sleep command. Disabling is
// permanent: what is held never runs, and expires as usual.

// ErrOrganizationDisabled means that the agent's organization is disabled:
// its work does not run.
var ErrOrganizationDisabled = errors.New("the agent's organization is disabled")

// CauseOrganizationDisabled is the cause of the sleep command that puts a
// disabled organization's running agent to sleep.
const CauseOrganizationDisabled = "organization_disabled"

// organizationDisabled reports whether tenant is a disabled organization.
// An agent of the historical owner domain has none.
func organizationDisabled(ctx context.Context, q rowQuerier, tenant string) (bool, error) {
	if tenant == "" {
		return false, nil
	}
	var disabled bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND status='disabled')`, tenant).Scan(&disabled)
	return disabled, err
}

// agentSuspended reports whether agent belongs to a disabled organization.
// It reads without locks, before a VM is booted for a delivery: the claim
// checks again under the agent's lock.
func agentSuspended(ctx context.Context, q rowQuerier, agent string) (bool, error) {
	var disabled bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents a JOIN organizations o ON o.id=a.tenant_id
        WHERE a.id=$1 AND o.status='disabled')`, agent).Scan(&disabled)
	return disabled, err
}

// suspendedRunning selects the agents of disabled organizations whose VM
// runs on host $1 for work, and that have no wake or sleep command open.
// $2 an agent, or empty for all; $3 the limit.
const suspendedRunning = `
SELECT a.id FROM organizations o JOIN agents a ON a.tenant_id=o.id
  JOIN agent_placements p ON p.agent_id=a.id
 WHERE o.status='disabled' AND a.phase='LIVE' AND p.host_id=$1 AND p.state='RUNNING' AND NOT p.fence_only
   AND ($2='' OR a.id=$2)
   AND NOT EXISTS(SELECT 1 FROM platform_operations op WHERE op.agent_id=a.id
                   AND op.kind IN ('wake','sleep') AND op.status IN ('PENDING','RUNNING'))
 ORDER BY a.id LIMIT $3`

// ScheduleSuspensionSleeps asks every running agent of a disabled
// organization on host to go to sleep. Like the idle policy, it writes the
// ordinary sleep command, which the worker executes with the guest's
// acknowledged quiescence; repeating it is harmless, since an open command
// leaves the agent out. The command names, as its requester, the platform
// account that disabled the organization.
func (s *Store) ScheduleSuspensionSleeps(ctx context.Context, host string, limit int) (int, error) {
	if limit < 1 || limit > 1024 || host == "" {
		return 0, ErrInput
	}
	rows, err := s.pool.Query(ctx, suspendedRunning, host, "", limit)
	if err != nil {
		return 0, err
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	n := 0
	var result error
	for _, id := range found {
		ok, err := s.suspensionSleepOne(ctx, host, id)
		if err != nil {
			result = errors.Join(result, err)
		} else if ok {
			n++
		}
	}
	return n, result
}

// suspensionSleepOne checks again under the agent's lock, the one every
// lifecycle command takes, then writes the sleep command.
func (s *Store) suspensionSleepOne(ctx context.Context, host, id string) (bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, id); err != nil {
		return false, err
	}
	var due string
	err = tx.QueryRow(ctx, `SELECT c.id FROM (`+suspendedRunning+`) c`, host, id, 1).Scan(&due)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var seq int64
	if err = tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
        WHERE agent_id=$1 AND next_operation_seq<9223372036854775807 RETURNING next_operation_seq`, id).Scan(&seq); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind,cause)
        SELECT $1,coalesce((SELECT u.actor_account FROM organization_audit u WHERE u.tenant_id=a.tenant_id
                              AND u.action='organization.disabled' AND u.changed ORDER BY u.created_at DESC LIMIT 1),'platform'),
               a.id,$3,$4,'sleep',$5 FROM agents a WHERE a.id=$2`, newID("op"), id, host, seq, CauseOrganizationDisabled); err != nil {
		return false, err
	}
	return true, commit(ctx, tx)
}
