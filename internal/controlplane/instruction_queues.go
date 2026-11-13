package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

const (
	DefaultInstructionTTL = time.Hour
	MinInstructionTTL     = time.Second
	MaxInstructionTTL     = 24 * time.Hour

	defaultMaxPendingPerAgent = 100
	defaultMaxPendingTenant   = 1000

	// Attachment storage an organization may hold at once (pending and attached,
	// not yet purged). Matches the column default of migration 0017.
	defaultMaxAttachmentBytes int64 = 512 << 20
	minMaxAttachmentBytes     int64 = 1 << 20
	maxMaxAttachmentBytes     int64 = 64 << 30
)

// QueueLimits bound how many instructions may wait, not how fast they run. They
// are checked at admission, so a refused request creates no operation, no
// payload and no mailbox entry. Order inside one agent stays FIFO: there is no
// priority, because the delivery model verified for this product has none.
type QueueLimits struct {
	MaxPendingPerAgent int `json:"max_pending_per_agent"`
	MaxPendingTenant   int `json:"max_pending_tenant"`
	// MaxAttachmentBytes bounds stored attachment bytes; 0 on input keeps the default.
	MaxAttachmentBytes int64 `json:"max_attachment_bytes"`
	// MaxPeerWakesPerHour bounds how many sleeping agents the organization's
	// agents may wake through requests in a rolling hour (ReservePeerWake);
	// 0 on input keeps the default.
	MaxPeerWakesPerHour int  `json:"max_peer_wakes_per_hour"`
	Default             bool `json:"default"`
}

type QueueAgentDepth struct {
	AgentID string `json:"agent_id"`
	Pending int    `json:"pending"`
}

type QueueStatus struct {
	Limits        QueueLimits       `json:"limits"`
	PendingTenant int               `json:"pending_tenant"`
	Agents        []QueueAgentDepth `json:"agents"`
	// PeerWakesLastHour: sleeping agents woken by requests in the last hour.
	PeerWakesLastHour int `json:"peer_wakes_last_hour"`
}

// waitingInstructionsSQL lists, per agent of tenant $1, every instruction that
// still occupies a queue slot: delivered-pending ones and scheduled ones not yet
// released. A scheduled instruction counts from admission, so the limit cannot be
// bypassed by scheduling.
const waitingInstructionsSQL = `SELECT m.dest_agent_id AS agent_id FROM agent_mailboxes m JOIN agents a ON a.id=m.dest_agent_id
    WHERE a.tenant_id=$1 AND m.kind='instruction' AND m.delivery_state='PENDING'
  UNION ALL
  SELECT o.agent_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id JOIN agents a ON a.id=o.agent_id
    WHERE a.tenant_id=$1 AND i.run_at IS NOT NULL AND i.released_at IS NULL AND o.status='PENDING'`

func queueLimits(ctx context.Context, tx pgx.Tx, tenant string) (QueueLimits, error) {
	l := QueueLimits{MaxPendingPerAgent: defaultMaxPendingPerAgent, MaxPendingTenant: defaultMaxPendingTenant,
		MaxAttachmentBytes: defaultMaxAttachmentBytes, MaxPeerWakesPerHour: defaultMaxPeerWakesPerHour, Default: true}
	err := tx.QueryRow(ctx, `SELECT max_pending_per_agent,max_pending_tenant,max_attachment_bytes,max_peer_wakes_per_hour FROM queue_limits WHERE tenant_id=$1`, tenant).
		Scan(&l.MaxPendingPerAgent, &l.MaxPendingTenant, &l.MaxAttachmentBytes, &l.MaxPeerWakesPerHour)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, nil
	}
	l.Default = false
	return l, err
}

// checkQueueRoom serializes admissions of one organization so two agents of the
// same tenant cannot each take the last slot. The caller already holds the
// agent row lock. Only waiting instructions count: delivered and dead ones free
// their slot, which is how capacity "comes back".
func checkQueueRoom(ctx context.Context, tx pgx.Tx, tenant, agentID string) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "instruction-queue/"+tenant); err != nil {
		return err
	}
	limits, err := queueLimits(ctx, tx, tenant)
	if err != nil {
		return err
	}
	var forAgent, forTenant int
	if err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE agent_id=$2),count(*) FROM (`+waitingInstructionsSQL+`) w`, tenant, agentID).Scan(&forAgent, &forTenant); err != nil {
		return err
	}
	if forAgent >= limits.MaxPendingPerAgent || forTenant >= limits.MaxPendingTenant {
		return ErrQueueFull
	}
	return nil
}

// SetQueueLimits replaces the organization's limits. Lowering them never drops
// work already accepted; it only refuses new admissions until the queue drains.
func (a *Accounts) SetQueueLimits(ctx context.Context, p Principal, key string, in QueueLimits) (APIReceipt, error) {
	if in.MaxAttachmentBytes == 0 {
		in.MaxAttachmentBytes = defaultMaxAttachmentBytes
	}
	if in.MaxPeerWakesPerHour == 0 {
		in.MaxPeerWakesPerHour = defaultMaxPeerWakesPerHour
	}
	if in.MaxPendingPerAgent < 1 || in.MaxPendingPerAgent > 100000 || in.MaxPendingTenant < in.MaxPendingPerAgent || in.MaxPendingTenant > 1000000 ||
		in.MaxAttachmentBytes < minMaxAttachmentBytes || in.MaxAttachmentBytes > maxMaxAttachmentBytes ||
		in.MaxPeerWakesPerHour < 1 || in.MaxPeerWakesPerHour > 100000 {
		return APIReceipt{}, ErrInput
	}
	in.Default = false
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "queue.limits.set", key, in, func() (int, any, error) {
		// Admissions of this organization wait here, so no one admits against
		// the old limits while the change commits.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "instruction-queue/"+p.TenantID); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO queue_limits(tenant_id,max_pending_per_agent,max_pending_tenant,max_attachment_bytes,max_peer_wakes_per_hour,updated_by)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id) DO UPDATE SET max_pending_per_agent=EXCLUDED.max_pending_per_agent,
            max_pending_tenant=EXCLUDED.max_pending_tenant,max_attachment_bytes=EXCLUDED.max_attachment_bytes,
            max_peer_wakes_per_hour=EXCLUDED.max_peer_wakes_per_hour,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`,
			p.TenantID, in.MaxPendingPerAgent, in.MaxPendingTenant, in.MaxAttachmentBytes, in.MaxPeerWakesPerHour, p.ID); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO queue_audit(id,tenant_id,actor_principal_id,action) VALUES($1,$2,$3,'limits.set')`,
			newID("audit"), p.TenantID, p.ID); err != nil {
			return 0, nil, err
		}
		return 200, in, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// QueueStatus shows limits and current depth. Counts only; never content.
func (a *Accounts) QueueStatus(ctx context.Context, p Principal) (QueueStatus, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return QueueStatus{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeUsageRead)
	if err != nil {
		return QueueStatus{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadUsage) {
		return QueueStatus{}, ErrForbidden
	}
	out := QueueStatus{Agents: []QueueAgentDepth{}}
	if out.Limits, err = queueLimits(ctx, tx, p.TenantID); err != nil {
		return QueueStatus{}, err
	}
	rows, err := tx.Query(ctx, `SELECT agent_id,count(*) FROM (`+waitingInstructionsSQL+`) w GROUP BY agent_id ORDER BY agent_id`, p.TenantID)
	if err != nil {
		return QueueStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var d QueueAgentDepth
		if err = rows.Scan(&d.AgentID, &d.Pending); err != nil {
			return QueueStatus{}, err
		}
		out.PendingTenant += d.Pending
		out.Agents = append(out.Agents, d)
	}
	if err = rows.Err(); err != nil {
		return QueueStatus{}, err
	}
	rows.Close()
	if out.PeerWakesLastHour, err = peerWakesLastHour(ctx, tx, p.TenantID); err != nil {
		return QueueStatus{}, err
	}
	return out, commit(ctx, tx)
}
