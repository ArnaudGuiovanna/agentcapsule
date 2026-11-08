package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// ErrBudgetExceeded is returned before any upstream call when a hard budget
// cannot cover the reservation.
var ErrBudgetExceeded = errors.New("llm budget exceeded")

type LLMBudget struct {
	ID          string    `json:"id"`
	AgentID     *string   `json:"agent_id,omitempty"`
	Alias       *string   `json:"alias,omitempty"`
	Period      string    `json:"period"`
	LimitTokens int64     `json:"limit_tokens"`
	Mode        string    `json:"mode"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateLLMBudgetInput struct {
	AgentID     string `json:"agent_id,omitempty"`
	Alias       string `json:"alias,omitempty"`
	Period      string `json:"period"`
	LimitTokens int64  `json:"limit_tokens"`
	Mode        string `json:"mode"`
}

const budgetColumns = `id,agent_id,alias,period,limit_tokens,mode,status,created_at`

func scanBudget(row pgx.Row) (LLMBudget, error) {
	var b LLMBudget
	err := row.Scan(&b.ID, &b.AgentID, &b.Alias, &b.Period, &b.LimitTokens, &b.Mode, &b.Status, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return b, err
}

func auditBudget(ctx context.Context, tx pgx.Tx, p Principal, budget, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO llm_audit(id,tenant_id,actor_principal_id,budget_id,action) VALUES($1,$2,$3,$4,$5)`,
		newID("audit"), p.TenantID, p.ID, budget, action)
	return err
}

func (a *Accounts) CreateLLMBudget(ctx context.Context, p Principal, key string, in CreateLLMBudgetInput) (APIReceipt, error) {
	if (in.Period != "day" && in.Period != "month") || (in.Mode != "hard" && in.Mode != "soft") || in.LimitTokens < 1 || in.LimitTokens > 1e15 ||
		(in.AgentID != "" && !validOrganizationText(in.AgentID, 100)) || (in.Alias != "" && !validOrganizationText(in.Alias, 100)) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.budget.create", key, in, func() (int, any, error) {
		if in.AgentID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, p.TenantID, in.AgentID).Scan(&ok); err != nil {
				return 0, nil, err
			}
			if !ok {
				return 0, nil, ErrNotFound
			}
		}
		if in.Alias != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2)`, p.TenantID, in.Alias).Scan(&ok); err != nil {
				return 0, nil, err
			}
			if !ok {
				return 0, nil, ErrNotFound
			}
		}
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_budgets WHERE tenant_id=$1 AND coalesce(agent_id,'')=$2 AND coalesce(alias,'')=$3 AND period=$4 AND status='active')`,
			p.TenantID, in.AgentID, in.Alias, in.Period).Scan(&taken); err != nil {
			return 0, nil, err
		}
		if taken {
			return 0, nil, ErrConflict
		}
		b, err := scanBudget(tx.QueryRow(ctx, `INSERT INTO llm_budgets(id,tenant_id,agent_id,alias,period,limit_tokens,mode,created_by)
            VALUES($1,$2,nullif($3,''),nullif($4,''),$5,$6,$7,$8) RETURNING `+budgetColumns, newID("bud"), p.TenantID, in.AgentID, in.Alias, in.Period, in.LimitTokens, in.Mode, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditBudget(ctx, tx, p, b.ID, "budget.created"); err != nil {
			return 0, nil, err
		}
		return 201, b, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) DisableLLMBudget(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageQuotas); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.budget.disable", key, struct{ ID string }{id}, func() (int, any, error) {
		cur, err := scanBudget(tx.QueryRow(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id))
		if err != nil {
			return 0, nil, err
		}
		if cur.Status == "disabled" {
			return 200, cur, nil
		}
		b, err := scanBudget(tx.QueryRow(ctx, `UPDATE llm_budgets SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING `+budgetColumns, p.TenantID, id))
		if err != nil {
			return 0, nil, err
		}
		if err = auditBudget(ctx, tx, p, id, "budget.disabled"); err != nil {
			return 0, nil, err
		}
		return 200, b, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) ListLLMBudgets(ctx context.Context, p Principal, after string, limit int) ([]LLMBudget, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeQuotaManage)
	if err != nil {
		return nil, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ManageQuotas) {
		return nil, ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []LLMBudget{}
	for rows.Next() {
		b, err := scanBudget(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, b)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// LLMReservation is the gateway's handle on one planned upstream call.
type LLMReservation struct {
	ID             string `json:"id"`
	State          string `json:"state"`
	ReservedTokens int64  `json:"reserved_tokens"`
	// SoftExceeded is true when a soft budget was already over its limit. The
	// call is allowed; the caller should surface the warning.
	SoftExceeded bool `json:"soft_exceeded"`
	// Replayed means this request key already had a reservation; the caller must
	// not issue the upstream call again unless State is "reserved".
	Replayed bool `json:"replayed"`
}

// usedTokens is what a budget window currently counts: actual tokens for a
// settled call, the reservation for a call in flight or of unknown outcome,
// nothing for a released one.
const usedTokensSQL = `coalesce(sum(CASE state WHEN 'settled' THEN input_tokens+output_tokens WHEN 'released' THEN 0 ELSE reserved_tokens END),0)`

func windowStart(period string) string {
	if period == "day" {
		return `date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
	}
	return `date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
}

// ReserveLLM must precede every upstream call. It serializes with other calls
// that share a budget by locking the applicable budget rows in a fixed order, so
// concurrent reservations never overshoot a hard limit. A repeated request key
// returns the existing reservation and never counts twice.
func (a *Accounts) ReserveLLM(ctx context.Context, tenantID, agentID, alias, requestKey string, tokens int64) (LLMReservation, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(agentID, 100) || !validOrganizationText(alias, 100) ||
		!validOrganizationText(requestKey, 200) || tokens < 1 || tokens > 1e12 {
		return LLMReservation{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return LLMReservation{}, err
	}
	defer rollback(tx)
	var orgActive bool
	if err = tx.QueryRow(ctx, `SELECT status='active' FROM organizations WHERE id=$1 FOR SHARE`, tenantID).Scan(&orgActive); errors.Is(err, pgx.ErrNoRows) || (err == nil && !orgActive) {
		return LLMReservation{}, ErrNotFound
	} else if err != nil {
		return LLMReservation{}, err
	}
	var agentOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$3 AND status='active')`,
		tenantID, agentID, alias).Scan(&agentOK); err != nil {
		return LLMReservation{}, err
	}
	if !agentOK {
		return LLMReservation{}, ErrNotFound
	}
	// Lock every applicable budget (fixed id order) before reading usage.
	rows, err := tx.Query(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND status='active'
        AND (agent_id IS NULL OR agent_id=$2) AND (alias IS NULL OR alias=$3) ORDER BY id FOR UPDATE`, tenantID, agentID, alias)
	if err != nil {
		return LLMReservation{}, err
	}
	budgets := []LLMBudget{}
	for rows.Next() {
		b, err := scanBudget(rows)
		if err != nil {
			rows.Close()
			return LLMReservation{}, err
		}
		budgets = append(budgets, b)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return LLMReservation{}, err
	}
	var existing LLMReservation
	err = tx.QueryRow(ctx, `SELECT id,state,reserved_tokens FROM llm_usage WHERE tenant_id=$1 AND agent_id=$2 AND request_key=$3`, tenantID, agentID, requestKey).
		Scan(&existing.ID, &existing.State, &existing.ReservedTokens)
	if err == nil {
		existing.Replayed = true
		return existing, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LLMReservation{}, err
	}
	out := LLMReservation{ID: newID("use"), State: "reserved", ReservedTokens: tokens}
	for _, b := range budgets {
		var used int64
		if err = tx.QueryRow(ctx, `SELECT `+usedTokensSQL+` FROM llm_usage WHERE tenant_id=$1 AND created_at >= `+windowStart(b.Period)+`
            AND ($2::text IS NULL OR agent_id=$2) AND ($3::text IS NULL OR alias=$3)`, tenantID, b.AgentID, b.Alias).Scan(&used); err != nil {
			return LLMReservation{}, err
		}
		if used+tokens > b.LimitTokens {
			if b.Mode == "hard" {
				return LLMReservation{}, ErrBudgetExceeded
			}
			out.SoftExceeded = true
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO llm_usage(id,tenant_id,agent_id,alias,request_key,reserved_tokens) VALUES($1,$2,$3,$4,$5,$6)`,
		out.ID, tenantID, agentID, alias, requestKey, tokens); err != nil {
		return LLMReservation{}, err
	}
	return out, commit(ctx, tx)
}

// SettleLLM records the provider-reported usage. It also resolves a call left
// 'unknown', which is how a late report corrects the uncertain amount. Settling
// twice with the same numbers is a no-op; different numbers conflict.
func (a *Accounts) SettleLLM(ctx context.Context, tenantID, reservationID string, input, output int64) error {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(reservationID, 100) || input < 0 || output < 0 || input > 1e12 || output > 1e12 {
		return ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var state, alias string
	var in, out *int64
	err = tx.QueryRow(ctx, `SELECT state,alias,input_tokens,output_tokens FROM llm_usage WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, reservationID).Scan(&state, &alias, &in, &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch state {
	case "settled":
		if *in == input && *out == output {
			return commit(ctx, tx)
		}
		return ErrConflict
	case "released":
		return ErrTransition
	}
	var ip, op int64
	if err = tx.QueryRow(ctx, `SELECT input_micro_per_mtok,output_micro_per_mtok FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2`, tenantID, alias).Scan(&ip, &op); err != nil {
		return err
	}
	var cost *int64
	if ip > 0 || op > 0 {
		c := (input*ip + output*op + 999_999) / 1_000_000 // rounded up: an estimate never under-reports
		cost = &c
	}
	if _, err = tx.Exec(ctx, `UPDATE llm_usage SET state='settled',input_tokens=$3,output_tokens=$4,estimated_cost_micro=$5,settled_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`,
		tenantID, reservationID, input, output, cost); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// MarkLLMUnknown records that the call may have been processed. The reserved
// amount keeps counting against budgets until a settlement or an operator
// decision replaces it.
func (a *Accounts) MarkLLMUnknown(ctx context.Context, tenantID, reservationID string) error {
	return a.moveReservation(ctx, tenantID, reservationID, "unknown")
}

// ReleaseLLM frees a reservation whose call definitely never reached the
// provider. It refuses a call of unknown outcome.
func (a *Accounts) ReleaseLLM(ctx context.Context, tenantID, reservationID string) error {
	return a.moveReservation(ctx, tenantID, reservationID, "released")
}

func (a *Accounts) moveReservation(ctx context.Context, tenantID, reservationID, to string) error {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(reservationID, 100) {
		return ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var state string
	if err = tx.QueryRow(ctx, `SELECT state FROM llm_usage WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, reservationID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if state == to {
		return commit(ctx, tx)
	}
	if state != "reserved" {
		return ErrTransition
	}
	if _, err = tx.Exec(ctx, `UPDATE llm_usage SET state=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, reservationID, to); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// LLMUsageLine is one aggregate of the current window. Uncertain tokens are
// reported apart from settled ones, and cost is an estimate from the alias
// prices, never an invoice.
type LLMUsageLine struct {
	AgentID           string `json:"agent_id"`
	Alias             string `json:"alias"`
	Calls             int64  `json:"calls"`
	SettledInput      int64  `json:"settled_input_tokens"`
	SettledOutput     int64  `json:"settled_output_tokens"`
	PendingTokens     int64  `json:"pending_tokens"`
	UnknownTokens     int64  `json:"unknown_outcome_tokens"`
	EstimatedCostMicr int64  `json:"estimated_cost_micro"`
}

type LLMUsageReport struct {
	Period    string         `json:"period"`
	Since     time.Time      `json:"since"`
	Lines     []LLMUsageLine `json:"lines"`
	Estimated bool           `json:"cost_is_estimate"`
}

func (a *Accounts) LLMUsage(ctx context.Context, p Principal, period string) (LLMUsageReport, error) {
	if period != "day" && period != "month" {
		return LLMUsageReport{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return LLMUsageReport{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeUsageRead)
	if err != nil {
		return LLMUsageReport{}, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadUsage) {
		return LLMUsageReport{}, ErrForbidden
	}
	rep := LLMUsageReport{Period: period, Estimated: true, Lines: []LLMUsageLine{}}
	if err = tx.QueryRow(ctx, `SELECT `+windowStart(period)).Scan(&rep.Since); err != nil {
		return LLMUsageReport{}, err
	}
	rows, err := tx.Query(ctx, `SELECT agent_id,alias,count(*) FILTER (WHERE state<>'released'),
        coalesce(sum(input_tokens) FILTER (WHERE state='settled'),0),coalesce(sum(output_tokens) FILTER (WHERE state='settled'),0),
        coalesce(sum(reserved_tokens) FILTER (WHERE state='reserved'),0),coalesce(sum(reserved_tokens) FILTER (WHERE state='unknown'),0),
        coalesce(sum(estimated_cost_micro) FILTER (WHERE state='settled'),0)
        FROM llm_usage WHERE tenant_id=$1 AND created_at >= $2 GROUP BY agent_id,alias ORDER BY agent_id,alias`, p.TenantID, rep.Since)
	if err != nil {
		return LLMUsageReport{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var l LLMUsageLine
		if err = rows.Scan(&l.AgentID, &l.Alias, &l.Calls, &l.SettledInput, &l.SettledOutput, &l.PendingTokens, &l.UnknownTokens, &l.EstimatedCostMicr); err != nil {
			return LLMUsageReport{}, err
		}
		rep.Lines = append(rep.Lines, l)
	}
	if err = rows.Err(); err != nil {
		return LLMUsageReport{}, err
	}
	return rep, nil
}
