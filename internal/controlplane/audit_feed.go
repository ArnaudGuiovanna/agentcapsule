package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// AuditEvent is metadata only: who did what to which resource, when, and
// with what outcome. It never carries a token, a secret, a prompt or any
// conversation content.
type AuditEvent struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Action    string    `json:"action"`
	// Actor is a principal ID, "platform:<account>" or "operator".
	Actor string `json:"actor"`
	// Target is the principal, agent, service account or tenant concerned.
	Target string `json:"target"`
	// Reference is the team, assignment, request, token or invocation the
	// action refers to, if any.
	Reference string `json:"reference,omitempty"`
	// Outcome is done, or refused for an attempt that an audited route
	// refused (TEN-009); Reason is then the refusal's code.
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// Attempts is how many refused attempts a refusal stands for: 1 for an
	// attempt recorded in full, more for the attempts its window counted
	// (v0.1.0 audit, L-04). Absent when done.
	Attempts int `json:"attempts,omitempty"`
}

type AuditPage struct {
	Items []AuditEvent `json:"items"`
	// Next is an opaque cursor, present only when more events may follow.
	Next string `json:"next,omitempty"`
}

// auditUnion is the organization's trail: the events of its audit tables,
// the replays of its dead letters, by its administrators or the operator,
// and its refused administrative attempts.
const auditUnion = `
    SELECT id,created_at,action,actor_principal_id AS actor,target_principal_id AS target,'' AS reference,'done' AS outcome,'' AS reason,0 AS attempts FROM tenant_member_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,action,actor,target,'','done','',0 FROM application_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,coalesce(target_principal_id,team_id),team_id,'done','',0 FROM tenant_team_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,action,actor_principal_id,agent_id,coalesce(assignment_id,request_id,''),'done','',0 FROM tenant_agent_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,service_principal_id,coalesce(token_id,''),'done','',0 FROM tenant_service_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,'llm.'||action,actor_principal_id,coalesce(subject_id,provider_id,budget_id),coalesce(alias,usage_id,''),'done','',0 FROM llm_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,'platform:'||actor_account,tenant_id,'','done','',0 FROM organization_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,'delegation.'||action,'operator',tenant_id,'','done','',0 FROM delegation_audit WHERE tenant_id=$1 AND changed
    UNION ALL SELECT id,created_at,action,actor,target,'','done','',0 FROM deployment_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,coalesce(agent_id,tenant_id),'','done','',0 FROM capability_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,'queue.'||action,actor_principal_id,tenant_id,'','done','',0 FROM queue_audit WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,coalesce(extension_id,enricher_id,agent_id,release_id,build_id,corpus_id,source_credential_id),
      coalesce(CASE WHEN extension_id IS NOT NULL OR agent_id IS NOT NULL OR release_id IS NOT NULL THEN build_id END,CASE WHEN build_id IS NOT NULL THEN corpus_id END,''),'done','',0 FROM corpus_audit WHERE tenant_id=$1
    UNION ALL SELECT id,replayed_at,'invocation.replayed',coalesce(actor_principal_id,'operator'),agent_id,operation_id,'done','',0 FROM instruction_replays WHERE tenant_id=$1
    UNION ALL SELECT id,created_at,action,actor_principal_id,target,reference,'refused',reason,attempts FROM tenant_refusal_audit WHERE tenant_id=$1`

const auditColumns = `id,created_at,action,actor,target,reference,outcome,reason,attempts`

func scanAuditEvent(rows pgx.Rows) (AuditEvent, error) {
	var e AuditEvent
	err := rows.Scan(&e.ID, &e.CreatedAt, &e.Action, &e.Actor, &e.Target, &e.Reference, &e.Outcome, &e.Reason, &e.Attempts)
	return e, err
}

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

// mayReadAudit checks that p may read its organization's trail: audit:read
// and a role that may read it. Under a snapshotTx it takes no row lock.
func mayReadAudit(ctx context.Context, tx pgx.Tx, p Principal) error {
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAuditRead)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAudit) {
		return ErrForbidden
	}
	return nil
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
	// The caller's rights first, read without the organization's row lock: a
	// caller who may not read the trail is refused before it waits (FIX-2).
	if err = mayReadAudit(ctx, snapshotTx{tx}, p); err != nil {
		return AuditPage{}, err
	}
	// The page ends at the trail's horizon (audit_horizon.go): an event that
	// commits late is never behind its cursor. Its wait holds no row lock, so
	// that it holds up no revocation. The rights are then checked again under
	// the row lock, as every read does: a revocation that committed during
	// the wait refuses the page.
	horizon, err := auditHorizon(ctx, tx, p.TenantID)
	if err != nil {
		return AuditPage{}, err
	}
	if err = mayReadAudit(ctx, tx, p); err != nil {
		return AuditPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+auditColumns+` FROM (`+auditUnion+`) e
        WHERE (created_at,id) > ($2::timestamptz,$3::text) AND created_at < $5 ORDER BY created_at,id LIMIT $4`, p.TenantID, after, afterID, limit, horizon)
	if err != nil {
		return AuditPage{}, err
	}
	defer rows.Close()
	page := AuditPage{Items: []AuditEvent{}}
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
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

// MaxAuditExport bounds one export; a larger range is refused with
// ErrAuditExportTooLarge, and the auditor asks for shorter ranges.
const MaxAuditExport = 100000

// ErrAuditExportTooLarge: the range holds more than MaxAuditExport events.
var ErrAuditExportTooLarge = errors.New("audit export range holds too many events")

// AuditExport is the organization's audit trail over [From, To), for its
// auditors (TEN-06). RetentionDays is the retention in force: events older
// than it were deleted. Without it, every event is kept.
type AuditExport struct {
	OrganizationID string       `json:"organization_id"`
	From           time.Time    `json:"from"`
	To             time.Time    `json:"to"`
	ExportedAt     time.Time    `json:"exported_at"`
	RetentionDays  *int         `json:"retention_days,omitempty"`
	Items          []AuditEvent `json:"items"`
}

// ExportAudit returns every audit event of the caller's organization created
// in [from, to), at most 366 days, in the order of ListAudit and under the
// same rights: audit:read and a role that may read the audit trail.
func (a *Accounts) ExportAudit(ctx context.Context, p Principal, from, to time.Time) (AuditExport, error) {
	if from.IsZero() || !to.After(from) || to.Sub(from) > 366*24*time.Hour {
		return AuditExport{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return AuditExport{}, err
	}
	defer rollback(tx)
	if err = mayReadAudit(ctx, tx, p); err != nil {
		return AuditExport{}, err
	}
	out := AuditExport{OrganizationID: p.TenantID, From: from.UTC(), To: to.UTC(), Items: []AuditEvent{}}
	err = tx.QueryRow(ctx, "SELECT clock_timestamp(),(SELECT retention_days FROM audit_retention)").Scan(&out.ExportedAt, &out.RetentionDays)
	if err != nil {
		return AuditExport{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+auditColumns+` FROM (`+auditUnion+`) e
        WHERE created_at >= $2 AND created_at < $3 ORDER BY created_at,id LIMIT $4`, p.TenantID, from, to, MaxAuditExport+1)
	if err != nil {
		return AuditExport{}, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return AuditExport{}, err
		}
		out.Items = append(out.Items, e)
	}
	if err = rows.Err(); err != nil {
		return AuditExport{}, err
	}
	rows.Close()
	if len(out.Items) > MaxAuditExport {
		return AuditExport{}, ErrAuditExportTooLarge
	}
	return out, commit(ctx, tx)
}

// RefusedAttempt is an administrative attempt that an audited route refused
// (TEN-009): the action it attempted, the identifiers its path named and the
// refusal's code (the API's problem code).
type RefusedAttempt struct {
	Action    string
	Target    string
	Reference string
	Reason    string
	// Attempts is how many refused attempts the event stands for; 0 is one.
	Attempts int
}

// maxRefusalAttempts bounds the attempts one refusal event stands for
// (migration 0074).
const maxRefusalAttempts = 1000000000

var (
	refusalAction = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+){1,2}$`)
	refusalReason = regexp.MustCompile(`^[a-z_]{1,64}$`)
	// refusalIdentifier is the platform's identifier: a prefix and 128
	// random bits. Anything else a path named, an alias or a guess, is not
	// kept: it could carry text of the caller's choosing.
	refusalIdentifier = regexp.MustCompile(`^[a-z][a-z_]{0,31}_[0-9a-f]{32}$`)
)

// RecordRefusal adds to the organization's trail an administrative attempt
// of one of its members or technical accounts that was refused, with outcome
// refused. The refused change rolled back: the record is its own
// transaction. It keeps only identifiers and codes: a target that is not a
// platform identifier is recorded as the organization, a reference that is
// not one is dropped. Only the API calls it, with a principal it
// authenticated; the attempts its windows counted come with no target.
func (a *Accounts) RecordRefusal(ctx context.Context, p Principal, r RefusedAttempt) error {
	if p.TenantID == "" || !validOrganizationText(p.ID, 100) || !refusalAction.MatchString(r.Action) || !refusalReason.MatchString(r.Reason) ||
		r.Attempts < 0 || r.Attempts > maxRefusalAttempts {
		return ErrInput
	}
	attempts := max(1, r.Attempts)
	target, reference := r.Target, r.Reference
	if !refusalIdentifier.MatchString(target) {
		target = p.TenantID
	}
	if !refusalIdentifier.MatchString(reference) {
		reference = ""
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `INSERT INTO tenant_refusal_audit(id,tenant_id,actor_principal_id,action,target,reference,reason,attempts) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		newID("audit"), p.TenantID, p.ID, r.Action, target, reference, r.Reason, attempts); err != nil {
		return err
	}
	return commit(ctx, tx)
}
