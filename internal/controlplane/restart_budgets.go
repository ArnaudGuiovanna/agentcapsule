package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrAgentFailed: the agent spent its restart budget (CAP-03, ADR 012). It is
// FAILED and does not boot until a wake requested for it, or the operator,
// clears it. Work for it waits, without a boot, until then or its deadline.
var ErrAgentFailed = errors.New("agent failed: its restart budget is spent")

// RestartBudget is how many guest failures of an agent (failed boots,
// crashes and unresponsive guests, together) a host allows within Window
// before the agent is FAILED.
type RestartBudget struct {
	Failures int
	Window   time.Duration
}

// DefaultRestartBudget applies when the operator sets none (ADR 012).
var DefaultRestartBudget = RestartBudget{Failures: 5, Window: time.Hour}

func (b RestartBudget) Valid() bool {
	return b.Failures >= 1 && b.Failures <= 100 && b.Window >= time.Minute && b.Window <= 24*time.Hour
}

// Guest failure kinds: a boot whose guest failed before it was ready, a
// confirmed guest whose VMM went away without a stop, and a running guest
// that did not answer the fence of a delivery past its attempts, whose VM
// the worker stopped (ADR 012, question 7).
const (
	GuestBootFailed   = "boot"
	GuestCrashed      = "crash"
	GuestUnresponsive = "unresponsive"
)

// GuestFailure is one guest failure, at its boot generation.
type GuestFailure struct {
	AgentID, HostID, Kind string
	Generation            uint64
}

// ObserveGuestFailure may ONLY be called after the trusted host retired the
// failed generation, like ObservePlacementStopped, which it includes: the
// placement becomes STOPPED, unclean. In the same transaction, the failure
// counts against the agent's restart budget if the agent is live and its
// volume is not being restored; a generation counts once, so a retry is
// harmless. It reports whether this failure made the agent FAILED.
func (s *Store) ObserveGuestFailure(ctx context.Context, f GuestFailure, budget RestartBudget) (bool, error) {
	if FailureReason(f.Kind) == "" || f.Generation == 0 || !budget.Valid() {
		return false, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, f.AgentID, f.HostID)
	if err != nil {
		return false, err
	}
	if p.Generation != f.Generation {
		return false, ErrPlacement
	}
	if p.State != "STOPPED" {
		if _, err = tx.Exec(ctx, `UPDATE agent_placements SET state='STOPPED',lease_until=NULL,
            worker_id='',vm_id='',unclean_stop=true WHERE agent_id=$1`, f.AgentID); err != nil {
			return false, err
		}
	}
	restoring, err := volumeRestoring(ctx, tx, f.AgentID)
	if err != nil {
		return false, err
	}
	if a.Phase != "LIVE" || restoring {
		return false, commit(ctx, tx)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO guest_failures(agent_id,generation,kind) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
		f.AgentID, int64(f.Generation), f.Kind); err != nil {
		return false, err
	}
	window := budget.Window.Microseconds()
	// Older failures no longer count; the agent's lock keeps this bounded.
	if _, err = tx.Exec(ctx, `DELETE FROM guest_failures WHERE agent_id=$1 AND failed_at<=clock_timestamp()-$2*interval '1 microsecond'`,
		f.AgentID, window); err != nil {
		return false, err
	}
	var failures int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM guest_failures WHERE agent_id=$1`, f.AgentID).Scan(&failures); err != nil {
		return false, err
	}
	failed := false
	if failures >= budget.Failures {
		tag, err := tx.Exec(ctx, `INSERT INTO failed_agents(agent_id,reason,failures) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, f.AgentID, FailureReason(f.Kind), failures)
		if err != nil {
			return false, err
		}
		failed = tag.RowsAffected() == 1
	}
	return failed, commit(ctx, tx)
}

// FailureReason is the failure_reason of an agent whose last guest failure,
// of that kind, spent its restart budget: boot_failed, crashed or
// unresponsive. It is empty for an unknown kind.
func FailureReason(kind string) string {
	switch kind {
	case GuestBootFailed:
		return "boot_failed"
	case GuestCrashed:
		return "crashed"
	case GuestUnresponsive:
		return "unresponsive"
	}
	return ""
}

func volumeRestoring(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	var restoring bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM store_enrollments WHERE agent_id=$1 AND stage='RESTORING')`, id).Scan(&restoring)
	return restoring, err
}

// bootAllowed refuses a new boot of a FAILED live agent. A restore of its
// volume still boots it, restricted: the restore is the operator's own act.
func bootAllowed(ctx context.Context, tx pgx.Tx, a agent) error {
	if a.Phase != "LIVE" {
		return nil
	}
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM failed_agents WHERE agent_id=$1)
        AND NOT EXISTS(SELECT 1 FROM store_enrollments WHERE agent_id=$1 AND stage='RESTORING')`, a.ID).Scan(&held); err != nil {
		return err
	}
	if held {
		return ErrAgentFailed
	}
	return nil
}

// clearAgentFailure gives the agent a new restart budget: it is no longer
// FAILED and its earlier failures no longer count. The caller holds the
// agent's lock. It reports whether the agent was FAILED.
func clearAgentFailure(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM failed_agents WHERE agent_id=$1`, id)
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM guest_failures WHERE agent_id=$1`, id); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ClearAgentFailure is the operator's command (agentcapsule-admin
// clear-agent-failure): the agent may boot again, with a new restart budget.
// It reports whether the agent was FAILED.
func (s *Store) ClearAgentFailure(ctx context.Context, id string) (bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if _, ok := agents[id]; !ok {
		return false, ErrNotFound
	}
	cleared, err := clearAgentFailure(ctx, tx, id)
	if err != nil {
		return false, err
	}
	return cleared, commit(ctx, tx)
}

// FailedAgents counts the host's FAILED live agents, for the operator's
// metrics.
func (s *Store) FailedAgents(ctx context.Context, host string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM failed_agents f JOIN agents a ON a.id=f.agent_id
        JOIN agent_placements p ON p.agent_id=f.agent_id WHERE p.host_id=$1 AND a.phase='LIVE'`, host).Scan(&n)
	return n, err
}

// FailWakeOfFailedAgent ends a wake that cannot boot its FAILED agent:
// FAILED, error restart_budget_exhausted. A later wake request clears the
// agent and boots it. If the agent was cleared meanwhile, the wake stays
// open and ErrTransition makes its job try again.
func (s *Store) FailWakeOfFailedAgent(ctx context.Context, wanted LifecycleOperation) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	op, a, err := lifecycleOperation(ctx, tx, wanted.ID, wanted.AgentID, wanted.HostID)
	if err != nil {
		return err
	}
	if op.Status != "PENDING" && op.Status != "RUNNING" {
		return nil
	}
	if op.Kind != "wake" {
		return ErrInput
	}
	if a.Phase != "LIVE" {
		if err = cancelLifecycle(ctx, tx, op.ID); err != nil {
			return err
		}
		return commit(ctx, tx)
	}
	if err = bootAllowed(ctx, tx, a); !errors.Is(err, ErrAgentFailed) {
		if err == nil {
			err = ErrTransition
		}
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE platform_operations SET status='FAILED',error_code='restart_budget_exhausted',completed_at=clock_timestamp()
        WHERE id=$1`, op.ID); err != nil {
		return err
	}
	return commit(ctx, tx)
}
