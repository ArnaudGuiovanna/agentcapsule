// Package audit reads a tenant’s metadata-only audit trail in chronological order.
package audit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Event is metadata only: who did what to which resource, when, and
// with what outcome. It never carries a token, a secret, a prompt or any
// conversation content.
type Event struct {
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

type Page struct {
	Items []Event `json:"items"`
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

func scanAuditEvent(rows pgx.Rows) (Event, error) {
	var e Event
	err := rows.Scan(&e.ID, &e.CreatedAt, &e.Action, &e.Actor, &e.Target, &e.Reference, &e.Outcome, &e.Reason, &e.Attempts)
	return e, err
}

func encodeAuditCursor(e Event) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", e.CreatedAt.UTC().UnixMicro(), e.ID)))
}

func DecodeCursor(cursor string) (time.Time, string, bool) {
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

// MaxExport bounds one export; a larger range is refused with
// ErrExportTooLarge, and the auditor asks for shorter ranges.
const MaxExport = 100000

// ErrExportTooLarge: the range holds more than MaxExport events.
var ErrExportTooLarge = errors.New("audit export range holds too many events")

// Export is the organization's audit trail over [From, To), for its
// auditors (TEN-06). RetentionDays is the retention in force: events older
// than it were deleted. Without it, every event is kept.
type Export struct {
	OrganizationID string    `json:"organization_id"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	ExportedAt     time.Time `json:"exported_at"`
	RetentionDays  *int      `json:"retention_days,omitempty"`
	Items          []Event   `json:"items"`
}

// ListEvents reads one page below the horizon through the caller's transaction.
func ListEvents(ctx context.Context, tx pgx.Tx, tenant string, after time.Time, afterID string, limit int, horizon time.Time) (Page, error) {
	rows, err := tx.Query(ctx, `SELECT `+auditColumns+` FROM (`+auditUnion+`) e
        WHERE (created_at,id) > ($2::timestamptz,$3::text) AND created_at < $5 ORDER BY created_at,id LIMIT $4`, tenant, after, afterID, limit, horizon)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{Items: []Event{}}
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, e)
	}
	if err = rows.Err(); err != nil {
		return Page{}, err
	}
	rows.Close()
	if len(page.Items) == limit {
		page.Next = encodeAuditCursor(page.Items[len(page.Items)-1])
	}
	return page, nil
}

// ExportEvents reads a bounded time range and the retention in force.
func ExportEvents(ctx context.Context, tx pgx.Tx, tenant string, from, to time.Time) (Export, error) {
	out := Export{OrganizationID: tenant, From: from.UTC(), To: to.UTC(), Items: []Event{}}
	err := tx.QueryRow(ctx, "SELECT clock_timestamp(),(SELECT retention_days FROM audit_retention)").Scan(&out.ExportedAt, &out.RetentionDays)
	if err != nil {
		return Export{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+auditColumns+` FROM (`+auditUnion+`) e
        WHERE created_at >= $2 AND created_at < $3 ORDER BY created_at,id LIMIT $4`, tenant, from, to, MaxExport+1)
	if err != nil {
		return Export{}, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return Export{}, err
		}
		out.Items = append(out.Items, e)
	}
	if err = rows.Err(); err != nil {
		return Export{}, err
	}
	rows.Close()
	if len(out.Items) > MaxExport {
		return Export{}, ErrExportTooLarge
	}
	return out, nil
}
