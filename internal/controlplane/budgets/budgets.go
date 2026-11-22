// Package budgets records and reconciles model usage against organization budgets in the caller's transaction.
package budgets

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmpolicy"
	"github.com/jackc/pgx/v5"
)

var ErrAlreadyProcessed = errors.New("llm request key already used")
var ErrAliasDenied = errors.New("llm alias not granted to this agent")

// ErrBudgetExceeded is returned before any upstream call when a hard budget
// cannot cover the reservation. The error is a *Refusal that says which.
var ErrBudgetExceeded = errors.New("llm budget exceeded")

// Refusal is a typed refusal of a model call before any reservation or
// provider call. Reason is budget_tokens or budget_cost (a hard budget would be
// exceeded), unpriced (a hard cost budget applies to an alias without prices
// for the call's unit), alias_access (the alias is listed and not granted to
// the agent) or unsupported (the alias does not declare the call's
// operation). Period and Scope describe the budget, never by its identifiers.
type Refusal struct {
	Reason string
	Period string
	Scope  string
}

func (e *Refusal) Error() string { return "llm call refused: " + e.Reason }

func (e *Refusal) Is(target error) bool {
	switch e.Reason {
	case "alias_access":
		return target == ErrAliasDenied
	case "unsupported":
		return target == llmpolicy.ErrUnsupported
	}
	return target == ErrBudgetExceeded
}

// Budget limits the tokens (LimitTokens) or the estimated cost
// (LimitCostMicro, in micro-units of the organization's currency) of an
// organization, an agent, an alias, or an agent and an alias, per UTC day or
// month. Used is what its current window counts, in its own unit; a list gives
// it for active budgets.
type Budget struct {
	ID             string    `json:"id"`
	AgentID        *string   `json:"agent_id,omitempty"`
	Alias          *string   `json:"alias,omitempty"`
	Period         string    `json:"period"`
	LimitTokens    *int64    `json:"limit_tokens,omitempty"`
	LimitCostMicro *int64    `json:"limit_cost_micro,omitempty"`
	Mode           string    `json:"mode"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	Used           *int64    `json:"used,omitempty"`
}

// CreateBudgetInput sets exactly one of LimitTokens and LimitCostMicro.
type CreateBudgetInput struct {
	AgentID        string `json:"agent_id,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Period         string `json:"period"`
	LimitTokens    int64  `json:"limit_tokens"`
	LimitCostMicro int64  `json:"limit_cost_micro,omitempty"`
	Mode           string `json:"mode"`
}

const budgetColumns = `id,agent_id,alias,period,limit_tokens,limit_cost_micro,mode,status,created_at`

func scanBudget(row pgx.Row) (Budget, error) {
	var b Budget
	err := row.Scan(&b.ID, &b.AgentID, &b.Alias, &b.Period, &b.LimitTokens, &b.LimitCostMicro, &b.Mode, &b.Status, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = persistence.ErrNotFound
	}
	return b, err
}

func (b Budget) costs() bool { return b.LimitCostMicro != nil }

func (b Budget) unit() string {
	if b.costs() {
		return "cost"
	}
	return "tokens"
}

func (b Budget) limit() int64 {
	if b.costs() {
		return *b.LimitCostMicro
	}
	return *b.LimitTokens
}

// scope says what a budget covers, for refusals, metrics and logs.
func (b Budget) scope() string {
	switch {
	case b.AgentID != nil && b.Alias != nil:
		return "agent_alias"
	case b.AgentID != nil:
		return "agent"
	case b.Alias != nil:
		return "alias"
	}
	return "organization"
}

// CreateBudget creates a budget and initializes its current window under the caller's organization lock.
func CreateBudget(ctx context.Context, tx pgx.Tx, tenant, actor string, in CreateBudgetInput) (Budget, error) {
	if in.AgentID != "" {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, tenant, in.AgentID).Scan(&ok); err != nil {
			return Budget{}, err
		}
		if !ok {
			return Budget{}, persistence.ErrNotFound
		}
	}
	if in.Alias != "" {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2)`, tenant, in.Alias).Scan(&ok); err != nil {
			return Budget{}, err
		}
		if !ok {
			return Budget{}, persistence.ErrNotFound
		}
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_budgets WHERE tenant_id=$1 AND coalesce(agent_id,'')=$2 AND coalesce(alias,'')=$3 AND period=$4
	            AND (limit_cost_micro IS NOT NULL)=$5 AND status='active')`, tenant, in.AgentID, in.Alias, in.Period, in.LimitCostMicro > 0).Scan(&taken); err != nil {
		return Budget{}, err
	}
	if taken {
		return Budget{}, persistence.ErrConflict
	}
	b, err := scanBudget(tx.QueryRow(ctx, `INSERT INTO llm_budgets(id,tenant_id,agent_id,alias,period,limit_tokens,limit_cost_micro,mode,created_by)
	            VALUES($1,$2,nullif($3,''),nullif($4,''),$5,nullif($6::bigint,0),nullif($7::bigint,0),$8,$9) RETURNING `+budgetColumns,
		persistence.ID("bud"), tenant, in.AgentID, in.Alias, in.Period, in.LimitTokens, in.LimitCostMicro, in.Mode, actor))
	if err != nil {
		return Budget{}, err
	}
	if err = countNewBudget(ctx, tx, tenant, b); err != nil {
		return Budget{}, err
	}
	return b, nil
}

// DisableBudget reports whether the budget changed in this transaction.
func DisableBudget(ctx context.Context, tx pgx.Tx, tenant, id string) (Budget, bool, error) {
	cur, err := scanBudget(tx.QueryRow(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id))
	if err != nil {
		return Budget{}, false, err
	}
	if cur.Status == "disabled" {
		return cur, false, nil
	}
	b, err := scanBudget(tx.QueryRow(ctx, `UPDATE llm_budgets SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING `+budgetColumns, tenant, id))
	if err != nil {
		return Budget{}, false, err
	}
	return b, true, nil
}

// ListBudgets reads a page with the current count of each active budget.
func ListBudgets(ctx context.Context, tx pgx.Tx, tenant, after string, limit int) ([]Budget, error) {
	rows, err := tx.Query(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Budget, error) { return scanBudget(row) })
	if err != nil {
		return nil, err
	}
	for i, b := range items {
		if b.Status != "active" {
			continue
		}
		used, err := budgetUsed(ctx, tx, tenant, b)
		if err != nil {
			return nil, err
		}
		items[i].Used = &used
	}
	return items, nil
}
