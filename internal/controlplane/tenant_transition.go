package controlplane

import (
	"context"
	"time"
)

// CloseLegacyOwnerDomain makes Authenticate refuse every acp_ token: the user
// and service accounts of the historical single-owner model. agentcapsule-api
// calls it before serving, so that an installation runs only the organization
// model (ADR 001, D-01). No shipped installation holds legacy owner data, and
// no command creates it any more; its code remains for the tests that still
// use it, until they move to organizations.
func (s *Store) CloseLegacyOwnerDomain() { s.legacyClosed.Store(true) }

type operatorKey struct{}

// WithOperator names the local operator in the audit of the trusted operations
// run with ctx. agentcapsule-admin passes local-uid:<uid>.
func WithOperator(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, operatorKey{}, actor)
}

func operatorFrom(ctx context.Context) string {
	if actor, ok := ctx.Value(operatorKey{}).(string); ok && validOrganizationText(actor, 100) {
		return actor
	}
	return "local-operator"
}

// OperatorAuditEvent is one operator action, with metadata only: the platform
// credential, organizations and their identity trusts, harness imports and
// releases, the operator's replays of dead letters and guarded commands. It
// never carries a token, a key or a secret.
type OperatorAuditEvent struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	TenantID  string    `json:"tenant_id,omitempty"`
	// Target is the credential, the organization, the trust's issuer, the
	// harness import or release, or the replayed invocation's agent.
	Target string `json:"target"`
	// Reference is the trust's audience, and the key or token ID it
	// concerns; the platform credential that requested a harness import or
	// deprecated a release; the replayed invocation.
	Reference string `json:"reference,omitempty"`
	Changed   bool   `json:"changed"`
	// Outcome is a guarded command's (ADR 014): done, unchanged, or refused
	// with its reason in Reference.
	Outcome string `json:"outcome,omitempty"`
}

// ListOperatorAudit returns the latest operator actions, newest first, for the
// local operator: the platform credential, organizations, their identity
// trusts, harness imports and release deprecations, the operator's replays
// of dead letters, and the guarded commands with their outcome, refusals
// included (ADR 014). Each organization's own view is GET /v1/audit.
func (s *Store) ListOperatorAudit(ctx context.Context, limit int) ([]OperatorAuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT id,created_at,action,actor,tenant_id,target,reference,changed,outcome FROM (
        SELECT id,created_at,action,actor,'' AS tenant_id,credential_id AS target,'' AS reference,changed,'' AS outcome FROM platform_audit
        UNION ALL SELECT id,created_at,action,'platform:'||actor_account,tenant_id,tenant_id,'',changed,'' FROM organization_audit
        UNION ALL SELECT id,created_at,'delegation.'||action,actor,tenant_id,issuer,btrim(concat_ws(' ',audience,nullif(key_id,''),nullif(token_id,''))),changed,'' FROM delegation_audit
        UNION ALL SELECT id,created_at,action,actor,'',target,reason,outcome='done',outcome FROM operator_audit
        UNION ALL SELECT id,created_at,'harness.'||action,'platform:'||actor_account,'',coalesce(import_id,release_id),credential_id,true,'' FROM harness_audit
        UNION ALL SELECT id,replayed_at,'invocation.replayed','operator',coalesce(tenant_id,''),agent_id,operation_id,true,'' FROM instruction_replays WHERE actor_kind='operator'
    ) e ORDER BY created_at DESC,id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []OperatorAuditEvent{}
	for rows.Next() {
		var e OperatorAuditEvent
		if err = rows.Scan(&e.ID, &e.CreatedAt, &e.Action, &e.Actor, &e.TenantID, &e.Target, &e.Reference, &e.Changed, &e.Outcome); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return events, commit(ctx, tx)
}
