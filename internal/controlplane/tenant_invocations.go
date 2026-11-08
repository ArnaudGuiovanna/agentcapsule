package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Invocation is the metadata of one request to a tenant agent. It never carries
// the instruction or the result: those stay in the encrypted transit area and are
// read only through the result route, by their requester.
type Invocation struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	State           string     `json:"state"`
	ErrorCode       string     `json:"error_code,omitempty"`
	RequestedBy     string     `json:"requested_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at,omitzero"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	ResultAvailable bool       `json:"result_available"`
	// ExpiresAt is when an instruction still waiting stops being deliverable.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// RunAt is the due time of a scheduled invocation; it is delivered no earlier.
	RunAt *time.Time `json:"run_at,omitempty"`
	// CloseReason says why a queued instruction ended without running:
	// "expired", "attempts_exhausted" or "closed". Empty when it did not.
	CloseReason string `json:"close_reason,omitempty"`
	// Attachments are the files sent with the invocation, in the order given.
	Attachments []string `json:"attachments,omitempty"`
	// ResultDueAt is set once the agent acknowledged "working": its outcome must
	// arrive before then, or the invocation fails with work_timeout.
	ResultDueAt *time.Time `json:"result_due_at,omitempty"`
}

// InvocationInput is the body of a new invocation. TTLSeconds bounds how long
// the instruction may wait to be delivered; it does not bound execution.
type InvocationInput struct {
	OwnerInstruction
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// RunAt delays delivery until that time (at least one second ahead, at most
	// 30 days). TTLSeconds then counts from the due time, not from admission.
	RunAt *time.Time `json:"run_at,omitempty"`
	// Attachments names files the requester uploaded for this agent beforehand
	// (POST /v1/agents/{id}/attachments). They are bound atomically: one unusable
	// reference refuses the whole invocation.
	Attachments []string `json:"attachments,omitempty"`
	// WorkTimeoutSeconds bounds how long the agent may work after acknowledging
	// "working" (60 to 86400, 3600 by default). It does not bound delivery.
	WorkTimeoutSeconds int `json:"work_timeout_seconds,omitempty"`
}

// MaxScheduleHorizon bounds how far ahead an invocation may be scheduled.
const MaxScheduleHorizon = 30 * 24 * time.Hour

// invocationState names what the platform actually knows. "accepted" means the
// request is durably queued; only "completed" says the agent answered. A
// delivery acknowledgement is never presented as business success.
func invocationState(status, closeReason string, waiting bool) string {
	if status == "FAILED" && closeReason == "expired" {
		return "expired"
	}
	if status == "PENDING" && waiting {
		return "scheduled"
	}
	switch status {
	case "PENDING":
		return "accepted"
	case "RUNNING":
		return "working"
	case "SUCCEEDED":
		return "completed"
	case "FAILED":
		return "failed"
	case "CANCELED":
		return "canceled"
	}
	return "unknown"
}

// CreateInvocation admits a request to a tenant agent. The right to invoke comes
// only from an assignment, exactly as on the messages route.
func (c *AgentCatalog) CreateInvocation(ctx context.Context, p Principal, id, key string, in InvocationInput) (APIReceipt, error) {
	ttl := DefaultInstructionTTL
	if in.TTLSeconds != 0 {
		ttl = time.Duration(in.TTLSeconds) * time.Second
		if in.TTLSeconds < 0 || ttl < MinInstructionTTL || ttl > MaxInstructionTTL {
			return APIReceipt{}, ErrInput
		}
	}
	work := time.Duration(in.WorkTimeoutSeconds) * time.Second
	if in.Validate() != nil || p.Kind != "tenant" || !validAttachmentList(in.Attachments) ||
		in.WorkTimeoutSeconds != 0 && (in.WorkTimeoutSeconds < 0 || work < MinWorkTimeout || work > MaxWorkTimeout) {
		return APIReceipt{}, ErrInput
	}
	if c.transit == nil {
		return APIReceipt{}, ErrTransitKey
	}
	return c.admitTenantInvocation(ctx, p, id, key, in.OwnerInstruction, invocationAdmission{
		ttl: ttl, runAt: in.RunAt, attachments: in.Attachments, work: work, request: in, resource: true})
}

const invocationSelect = `SELECT o.id,o.agent_id,o.status,o.error_code,coalesce(o.requested_by_principal_id,''),o.created_at,o.completed_at,
        (o.status='SUCCEEDED' AND i.result_payload_id IS NOT NULL),m.expires_at,i.close_reason,i.run_at,
        (i.run_at IS NOT NULL AND i.released_at IS NULL),
        array(SELECT f.id FROM attachments f WHERE f.operation_id=o.id ORDER BY f.position),i.result_due_at
    FROM platform_operations o JOIN owner_instructions i ON i.operation_id=o.id JOIN agents a ON a.id=o.agent_id
    LEFT JOIN agent_mailboxes m ON m.instruction_id=o.id `

func scanInvocation(row pgx.Row, administrative bool) (Invocation, error) {
	var v Invocation
	var status string
	var expires *time.Time
	var waiting bool
	if err := row.Scan(&v.ID, &v.AgentID, &status, &v.ErrorCode, &v.RequestedBy, &v.CreatedAt, &v.CompletedAt, &v.ResultAvailable, &expires, &v.CloseReason, &v.RunAt, &waiting, &v.Attachments, &v.ResultDueAt); err != nil {
		return Invocation{}, err
	}
	if expires != nil {
		v.ExpiresAt = *expires
	}
	v.State = invocationState(status, v.CloseReason, waiting)
	if !administrative {
		v.RequestedBy = ""
	}
	return v, nil
}

// GetInvocation shows metadata to the requester, or to a role allowed to read
// agent metadata. Neither path exposes content (D-02).
func (c *AgentCatalog) GetInvocation(ctx context.Context, p Principal, id string) (Invocation, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return Invocation{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return Invocation{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return Invocation{}, err
	}
	administrative := authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata)
	v, err := scanInvocation(tx.QueryRow(ctx, invocationSelect+`WHERE a.tenant_id=$1 AND o.id=$2 AND o.kind='instruction'
        AND ($3 OR o.requested_by_principal_id=$4)`, p.TenantID, id, administrative, p.ID), administrative)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invocation{}, ErrNotFound
	}
	if err != nil {
		return Invocation{}, err
	}
	return v, commit(ctx, tx)
}

// ListInvocations returns the newest first. A requester sees only their own;
// an administrative reader sees every invocation of the agent.
func (c *AgentCatalog) ListInvocations(ctx context.Context, p Principal, agentID, after, state string, limit int) ([]Invocation, error) {
	if p.Kind != "tenant" || !validOrganizationText(agentID, 100) || len(after) > 100 || limit < 1 || limit > 200 {
		return nil, ErrInput
	}
	filter, ok := invocationFilters[state]
	if !ok {
		return nil, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return nil, err
	}
	administrative := authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata)
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1 AND tenant_id=$2)", agentID, p.TenantID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, invocationSelect+`WHERE a.tenant_id=$1 AND o.agent_id=$2 AND o.kind='instruction'
        AND ($3 OR o.requested_by_principal_id=$4)
        AND ($5='' OR o.seq<(SELECT seq FROM platform_operations WHERE id=$5 AND agent_id=$2))`+filter+`
        ORDER BY o.seq DESC LIMIT $6`, p.TenantID, agentID, administrative, p.ID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Invocation{}
	for rows.Next() {
		v, err := scanInvocation(rows, administrative)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, commit(ctx, tx)
}

// invocationFilters are fixed SQL fragments, never built from input. The empty
// key lists everything; "failed" and "expired" are disjoint, together they are
// the dead letters of the queue.
var invocationFilters = map[string]string{
	"":          "",
	"scheduled": " AND o.status='PENDING' AND i.run_at IS NOT NULL AND i.released_at IS NULL",
	"accepted":  " AND o.status='PENDING' AND NOT (i.run_at IS NOT NULL AND i.released_at IS NULL)",
	"working":   " AND o.status='RUNNING'",
	"completed": " AND o.status='SUCCEEDED'",
	"failed":    " AND o.status='FAILED' AND i.close_reason<>'expired'",
	"expired":   " AND o.status='FAILED' AND i.close_reason='expired'",
	"canceled":  " AND o.status='CANCELED'",
}
