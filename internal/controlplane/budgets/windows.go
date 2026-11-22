package budgets

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// usedTokensSQL is what a token budget's window counts: actual tokens for a
// settled call, the reservation for a call in flight or of unknown outcome,
// nothing for a released one. usedCostSQL is the same in micro-units: a
// settled call without an estimate (an unpriced alias) counts nothing.
const (
	usedTokensSQL = `coalesce(sum(CASE state WHEN 'settled' THEN input_tokens+output_tokens WHEN 'released' THEN 0 ELSE reserved_tokens END),0)`
	usedCostSQL   = `coalesce(sum(CASE state WHEN 'settled' THEN coalesce(estimated_cost_micro,0) WHEN 'released' THEN 0 ELSE reserved_cost_micro END),0)`
)

func windowStart(period string) string {
	return windowOf(period, "clock_timestamp()")
}

// windowOf is the start of the UTC day or month of period that holds the
// time at, an SQL expression.
func windowOf(period, at string) string {
	if period == "day" {
		return `date_trunc('day', (` + at + `) AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
	}
	return `date_trunc('month', (` + at + `) AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
}

// The counters of the budgets (v0.1.0 audit, P-05, migration
// llm-budget-windows). A row of llm_budget_windows holds what a budget's
// UTC day or month counts, in its unit: what usedTokensSQL or usedCostSQL
// sums over the calls of its scope created in that window. A reservation
// adds its amounts to the windows of the budgets it locked (countReservation),
// a settlement or a release adds the change of its call's amounts to the
// windows that exist (countCall), and a new budget counts its current window
// once (CreateLLMBudget). A reservation reads its budgets' windows, never
// the calls: its cost no longer grows with the month's calls. Every change
// locks its windows in budget order, after its call's row.

// budgetUsed is what a budget's current window counts, in its unit.
func budgetUsed(ctx context.Context, tx pgx.Tx, tenant string, b Budget) (int64, error) {
	var used int64
	err := tx.QueryRow(ctx, `SELECT coalesce((SELECT used FROM llm_budget_windows WHERE tenant_id=$1 AND budget_id=$2
        AND window_start=`+windowStart(b.Period)+`),0)`, tenant, b.ID).Scan(&used)
	return used, err
}

// countNewBudget counts the current window of b, a budget its transaction
// creates: the calls of its scope made since the window began. The calls of
// the window still in flight are locked first, so that none settles or is
// released between the count and the commit without countCall finding the
// window. No call is reserved meanwhile: a reservation holds the
// organization's row, which the creation holds FOR UPDATE.
func countNewBudget(ctx context.Context, tx pgx.Tx, tenant string, b Budget) error {
	var start time.Time
	if err := tx.QueryRow(ctx, `SELECT `+windowStart(b.Period)).Scan(&start); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM llm_usage WHERE tenant_id=$1 AND state IN ('reserved','unknown') AND created_at>=$2
        AND ($3::text IS NULL OR agent_id=$3) AND ($4::text IS NULL OR alias=$4) ORDER BY id FOR SHARE`, tenant, start, b.AgentID, b.Alias); err != nil {
		return err
	}
	sum := usedTokensSQL
	if b.costs() {
		sum = usedCostSQL
	}
	_, err := tx.Exec(ctx, `INSERT INTO llm_budget_windows(tenant_id,budget_id,window_start,used)
        SELECT $1,$2,$3,`+sum+` FROM llm_usage WHERE tenant_id=$1 AND created_at>=$3
        AND ($4::text IS NULL OR agent_id=$4) AND ($5::text IS NULL OR alias=$5)`, tenant, b.ID, start, b.AgentID, b.Alias)
	return err
}

// countReservation adds amount to b's window that holds created, and returns
// what the window counts with it.
func countReservation(ctx context.Context, tx pgx.Tx, tenant string, b Budget, created time.Time, amount int64) (int64, error) {
	var used int64
	err := tx.QueryRow(ctx, `INSERT INTO llm_budget_windows(tenant_id,budget_id,window_start,used) VALUES($1,$2,`+windowOf(b.Period, "$3::timestamptz")+`,$4)
        ON CONFLICT (budget_id,window_start) DO UPDATE SET used=llm_budget_windows.used+EXCLUDED.used RETURNING used`, tenant, b.ID, created, amount).Scan(&used)
	return used, err
}

// countCall adds to the windows of the budgets that count a call (of agent
// and alias, created at created) the change of its amounts: tokens to token
// budgets, micro-units to cost budgets. A window that does not exist counts
// nothing that the call's change concerns: its budget did not exist, or was
// not active, when the call was reserved.
func countCall(ctx context.Context, tx pgx.Tx, tenant, agent, alias string, created time.Time, tokens, cost int64) error {
	if tokens == 0 && cost == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `WITH w AS (
        SELECT w.budget_id,w.window_start,CASE WHEN b.limit_cost_micro IS NULL THEN $5::bigint ELSE $6::bigint END AS change
          FROM llm_budgets b JOIN llm_budget_windows w ON w.budget_id=b.id
         WHERE b.tenant_id=$1 AND (b.agent_id IS NULL OR b.agent_id=$2) AND (b.alias IS NULL OR b.alias=$3)
           AND w.window_start=CASE b.period WHEN 'day' THEN `+windowOf("day", "$4::timestamptz")+` ELSE `+windowOf("month", "$4::timestamptz")+` END
         ORDER BY w.budget_id FOR UPDATE OF w)
        UPDATE llm_budget_windows v SET used=v.used+w.change FROM w WHERE (v.budget_id,v.window_start)=(w.budget_id,w.window_start)`,
		tenant, agent, alias, created, tokens, cost)
	return err
}
