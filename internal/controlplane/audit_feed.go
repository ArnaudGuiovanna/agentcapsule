package controlplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// AuditEvent is metadata only: who did what to which resource, and when. It
// never carries a token, a secret, a prompt or any conversation content.
type AuditEvent struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Action    string    `json:"action"`
	// Actor is a principal ID, "platform:<account>" or "operator".
	Actor string `json:"actor"`
	// Target is the principal, agent, service account or tenant concerned.
	Target string `json:"target"`
	// Reference is the team, assignment or token the action refers to, if any.
	Reference string `json:"reference,omitempty"`
}

type AuditPage struct {
	Items []AuditEvent `json:"items"`
	// Next is an opaque cursor, present only when more events may follow.
	Next string `json:"next,omitempty"`
}

const auditUnion = `
    SELECT id,created_at,action,actor_principal_id AS actor,target_principal_id AS target,'' AS reference FROM tenant_member_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,action,actor_principal_id,coalesce(target_principal_id,team_id),team_id FROM tenant_team_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,action,actor_principal_id,agent_id,coalesce(assignment_id,'') FROM tenant_agent_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,service_principal_id,coalesce(token_id,'') FROM tenant_service_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,'llm.'||action,actor_principal_id,coalesce(provider_id,budget_id),coalesce(alias,'') FROM llm_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,'platform:'||actor_account,tenant_id,'' FROM organization_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,'delegation.'||action,'operator',tenant_id,'' FROM delegation_audit WHERE tenant_id=$1 AND changed`

func encodeAuditCursor(e AuditEvent) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", e.CreatedAt.UTC().UnixMicro(), e.ID)))
}

func decodeAuditCursor(cursor string) (time.Time, string, bool) {
	if cursor == "" {
		return time.Unix(0, 0).UTC(), "", true
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", false
	}
	var micro int64
	var id string
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", false
	}
	if _, err = fmt.Sscanf(parts[0], "%d", &micro); err != nil || len(parts[1]) > 100 {
		return time.Time{}, "", false
	}
	id = parts[1]
	return time.UnixMicro(micro).UTC(), id, true
}

// ListAudit returns the tenant's audit events in a stable order. It requires
// audit:read and a role that may read the audit trail. Events of other tenants
// are never selected, and no event discloses content.
func (a *Accounts) ListAudit(ctx context.Context, p Principal, cursor string, limit int) (AuditPage, error) {
	after, afterID, ok := decodeAuditCursor(cursor)
	if !ok || limit < 1 || limit > 200 {
		return AuditPage{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return AuditPage{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAuditRead)
	if err != nil {
		return AuditPage{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAudit) {
		return AuditPage{}, ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT id,created_at,action,actor,target,reference FROM (`+auditUnion+`) e
        WHERE (created_at,id) > ($2::timestamptz,$3::text) ORDER BY created_at,id LIMIT $4`, p.TenantID, after, afterID, limit)
	if err != nil {
		return AuditPage{}, err
	}
	defer rows.Close()
	page := AuditPage{Items: []AuditEvent{}}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.CreatedAt, &e.Action, &e.Actor, &e.Target, &e.Reference); err != nil {
			return AuditPage{}, err
		}
		page.Items = append(page.Items, e)
	}
	if err = rows.Err(); err != nil {
		return AuditPage{}, err
	}
	rows.Close()
	if len(page.Items) == limit {
		page.Next = encodeAuditCursor(page.Items[len(page.Items)-1])
	}
	return page, commit(ctx, tx)
}
