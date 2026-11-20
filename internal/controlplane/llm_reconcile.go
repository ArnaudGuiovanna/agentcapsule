package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// unresolvedSQL selects the calls whose outcome no process will settle: those
// left unknown after a timeout, and reservations older than any call can last
// (the bridge's 300 s), whose worker died between reservation and outcome.
// Both keep counting against budgets until the organization resolves them.
const unresolvedSQL = `(state='unknown' OR (state='reserved' AND created_at < clock_timestamp() - interval '15 minutes'))`

// LLMCall is one metered call as the organization reconciles it: no request
// key, prompt or answer. A transcription reserves and settles seconds of
// audio, an OCR call pages; neither counts tokens (ADR 023 §12).
type LLMCall struct {
	ID                   string     `json:"id"`
	AgentID              string     `json:"agent_id"`
	Alias                string     `json:"alias"`
	Operation            string     `json:"operation"`
	State                string     `json:"state"`
	ReservedTokens       int64      `json:"reserved_tokens"`
	ReservedAudioSeconds int64      `json:"reserved_audio_seconds,omitempty"`
	ReservedPages        int64      `json:"reserved_pages,omitempty"`
	ReservedCostMicro    int64      `json:"reserved_cost_micro"`
	InputTokens          *int64     `json:"input_tokens,omitempty"`
	OutputTokens         *int64     `json:"output_tokens,omitempty"`
	AudioSeconds         *int64     `json:"audio_seconds,omitempty"`
	Pages                *int64     `json:"pages,omitempty"`
	EstimatedCostMicro   *int64     `json:"estimated_cost_micro,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	ResolvedAt           *time.Time `json:"resolved_at,omitempty"`
}

// SettleLLMOutcomeInput is the usage the organization read in its provider's
// account for one call, in the call's units: tokens for chat and embed
// (an embedding has no output), seconds of audio for a transcription, pages
// for OCR.
type SettleLLMOutcomeInput struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	AudioSeconds int64 `json:"audio_seconds,omitempty"`
	Pages        int64 `json:"pages,omitempty"`
}

const callColumns = `id,agent_id,alias,operation,state,reserved_tokens,reserved_audio_seconds,reserved_pages,reserved_cost_micro,input_tokens,output_tokens,
    audio_seconds,pages,estimated_cost_micro,created_at,resolved_at`

func scanCall(row pgx.Row) (LLMCall, error) {
	var c LLMCall
	err := row.Scan(&c.ID, &c.AgentID, &c.Alias, &c.Operation, &c.State, &c.ReservedTokens, &c.ReservedAudioSeconds, &c.ReservedPages, &c.ReservedCostMicro,
		&c.InputTokens, &c.OutputTokens, &c.AudioSeconds, &c.Pages, &c.EstimatedCostMicro, &c.CreatedAt, &c.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

// ListLLMUnresolved lists the organization's calls of unknown outcome
// (usage:read), oldest identifier first.
func (a *Accounts) ListLLMUnresolved(ctx context.Context, p Principal, after string, limit int) ([]LLMCall, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizeUsageRead(ctx, tx, p); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+callColumns+` FROM llm_usage WHERE tenant_id=$1 AND `+unresolvedSQL+` AND id>$2 ORDER BY id LIMIT $3`, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []LLMCall{}
	for rows.Next() {
		c, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

// SettleLLMOutcome settles a call of unknown outcome at the usage the
// organization read in its provider's account, at the prices of its
// reservation (quota:manage). A call already resolved, or still possibly
// running, is refused with ErrTransition.
func (a *Accounts) SettleLLMOutcome(ctx context.Context, p Principal, id, key string, in SettleLLMOutcomeInput) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !validUsage(in.InputTokens, in.OutputTokens) || !validUsage(in.AudioSeconds, in.Pages) {
		return APIReceipt{}, ErrInput
	}
	// A settlement in tokens keeps the request hash it had before seconds and
	// pages existed.
	var hashed any = struct {
		ID            string
		Input, Output int64
	}{id, in.InputTokens, in.OutputTokens}
	if in.AudioSeconds != 0 || in.Pages != 0 {
		hashed = struct {
			ID                            string
			Input, Output, Seconds, Pages int64
		}{id, in.InputTokens, in.OutputTokens, in.AudioSeconds, in.Pages}
	}
	return a.resolveLLMOutcome(ctx, p, id, key, "llm.usage.settle", hashed, func(tx pgx.Tx) error {
		_, err := settleCall(ctx, tx, p.TenantID, id, llmAmounts{Input: in.InputTokens, Output: in.OutputTokens, AudioSeconds: in.AudioSeconds, Pages: in.Pages}, &p.ID)
		return err
	}, "usage.settled")
}

// ReleaseLLMOutcome records that the provider billed nothing for a call of
// unknown outcome (quota:manage): its reservation stops counting.
func (a *Accounts) ReleaseLLMOutcome(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	return a.resolveLLMOutcome(ctx, p, id, key, "llm.usage.release", struct{ ID string }{id}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE llm_usage SET state='released',resolved_by=$3,resolved_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, p.TenantID, id, p.ID)
		return err
	}, "usage.released")
}

func (a *Accounts) resolveLLMOutcome(ctx context.Context, p Principal, id, key, operation string, hashed any, apply func(pgx.Tx) error, action string) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, operation, key, hashed, func() (int, any, error) {
		var unresolved bool
		var agent, alias, provider string
		err := tx.QueryRow(ctx, `SELECT `+unresolvedSQL+`,agent_id,alias FROM llm_usage WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id).
			Scan(&unresolved, &agent, &alias)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		}
		if err != nil {
			return 0, nil, err
		}
		if !unresolved {
			return 0, nil, ErrTransition
		}
		if err = tx.QueryRow(ctx, `SELECT provider_id FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2`, p.TenantID, alias).Scan(&provider); err != nil {
			return 0, nil, err
		}
		if err = apply(tx); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO llm_audit(id,tenant_id,actor_principal_id,provider_id,usage_id,subject_id,action) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			newID("audit"), p.TenantID, p.ID, provider, id, agent, action); err != nil {
			return 0, nil, err
		}
		c, err := scanCall(tx.QueryRow(ctx, `SELECT `+callColumns+` FROM llm_usage WHERE tenant_id=$1 AND id=$2`, p.TenantID, id))
		return 200, c, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// LLMUnresolvedCalls counts, across the installation, the calls of unknown
// outcome that wait for their organization (a technical metric: no tenant).
func (s *Store) LLMUnresolvedCalls(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM llm_usage WHERE `+unresolvedSQL).Scan(&n)
	return n, err
}
