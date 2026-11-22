package controlplane

import (
	"context"
	"regexp"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/audit"
	"github.com/jackc/pgx/v5"
)

var ErrAuditBusy = audit.ErrBusy
var ErrAuditExportTooLarge = audit.ErrExportTooLarge

const MaxAuditExport = audit.MaxExport

type AuditPage = audit.Page
type AuditEvent = audit.Event
type AuditExport = audit.Export

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
	after, afterID, ok := audit.DecodeCursor(cursor)
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
	if err = mayReadAudit(ctx, snapshotTx{Tx: tx}, p); err != nil {
		return AuditPage{}, err
	}
	// The page ends at the trail's horizon (audit/horizon.go): an event that
	// commits late is never behind its cursor. Its wait holds no row lock, so
	// that it holds up no revocation. The rights are then checked again under
	// the row lock, as every read does: a revocation that committed during
	// the wait refuses the page.
	horizon, err := audit.Horizon(ctx, tx, p.TenantID)
	if err != nil {
		return AuditPage{}, err
	}
	if err = mayReadAudit(ctx, tx, p); err != nil {
		return AuditPage{}, err
	}
	page, err := audit.ListEvents(ctx, tx, p.TenantID, after, afterID, limit, horizon)
	if err != nil {
		return AuditPage{}, err
	}
	return page, commit(ctx, tx)
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
	out, err := audit.ExportEvents(ctx, tx, p.TenantID, from, to)
	if err != nil {
		return AuditExport{}, err
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
