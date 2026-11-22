package budgets

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/accounting"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// BudgetHit names a budget a call went past: its unit (tokens or cost),
// period and scope.
type BudgetHit struct {
	Unit   string
	Period string
	Scope  string
}

// Reservation is the gateway's handle on one planned upstream call.
type Reservation struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	ReservedTokens    int64  `json:"reserved_tokens"`
	ReservedCostMicro int64  `json:"reserved_cost_micro"`
	// SoftExceeded is true when a soft budget is over its limit with this
	// call. The call is allowed; the caller should surface the warning.
	SoftExceeded bool `json:"soft_exceeded"`
	// SoftBudgets lists those soft budgets.
	SoftBudgets []BudgetHit `json:"-"`
	// Replayed means this request key already had a reservation; the caller must
	// not issue the upstream call again unless State is "reserved".
	Replayed bool `json:"replayed"`
}

// ReserveCall locks applicable budgets, writes the reservation and updates their UTC windows.
// The caller holds the organization lock and has checked the route, access grant and operation.
func ReserveCall(ctx context.Context, tx pgx.Tx, tenantID, agentID, alias, requestKey string, q accounting.Amounts, prices accounting.Prices) (Reservation, error) {
	// Lock every applicable budget (fixed id order) before reading usage.
	rows, err := tx.Query(ctx, `SELECT `+budgetColumns+` FROM llm_budgets WHERE tenant_id=$1 AND status='active'
        AND (agent_id IS NULL OR agent_id=$2) AND (alias IS NULL OR alias=$3) ORDER BY id FOR UPDATE`, tenantID, agentID, alias)
	if err != nil {
		return Reservation{}, err
	}
	budgets, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Budget, error) { return scanBudget(row) })
	if err != nil {
		return Reservation{}, err
	}
	var existing Reservation
	var existingOperation string
	err = tx.QueryRow(ctx, `SELECT id,state,reserved_tokens,reserved_cost_micro,operation FROM llm_usage WHERE tenant_id=$1 AND agent_id=$2 AND request_key=$3`, tenantID, agentID, requestKey).
		Scan(&existing.ID, &existing.State, &existing.ReservedTokens, &existing.ReservedCostMicro, &existingOperation)
	if err == nil {
		if existingOperation != q.Operation {
			return Reservation{}, ErrAlreadyProcessed
		}
		existing.Replayed = true
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, err
	}
	out := Reservation{ID: persistence.ID("use"), State: "reserved", ReservedTokens: q.Tokens()}
	if prices.Priced {
		var ok bool
		if out.ReservedCostMicro, ok = prices.Cost(q); !ok {
			return Reservation{}, persistence.ErrInput
		}
	}
	// The call is written first: the time it is created at is the one each
	// budget's window is taken at. A refusal below rolls it back with the
	// counts.
	var created time.Time
	if err = tx.QueryRow(ctx, `INSERT INTO llm_usage(id,tenant_id,agent_id,alias,request_key,reserved_tokens,reserved_cost_micro,priced,input_micro_per_mtok,output_micro_per_mtok,
        operation,reserved_audio_seconds,reserved_pages,audio_micro_per_minute,ocr_micro_per_page)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING created_at`, out.ID, tenantID, agentID, alias, requestKey, out.ReservedTokens, out.ReservedCostMicro, prices.Priced,
		prices.InputPerMillion, prices.OutputPerMillion, q.Operation, q.AudioSeconds, q.Pages, prices.AudioPerMinute, prices.PerPage).Scan(&created); err != nil {
		return Reservation{}, err
	}
	for _, b := range budgets {
		if !b.costs() && out.ReservedTokens == 0 {
			continue // seconds and pages count only in cost budgets
		}
		if b.costs() && !prices.Priced {
			// No estimate exists: a hard cap could not hold, a soft one counts
			// nothing for this call.
			if b.Mode == "hard" {
				return Reservation{}, &Refusal{Reason: "unpriced", Period: b.Period, Scope: b.scope()}
			}
			continue
		}
		need := out.ReservedTokens
		if b.costs() {
			need = out.ReservedCostMicro
		}
		// The budget's row lock above serializes this count with every other
		// reservation of the budget; a settlement changes it under its own row
		// lock, which the count waits for.
		used, err := countReservation(ctx, tx, tenantID, b, created, need)
		if err != nil {
			return Reservation{}, err
		}
		if used > b.limit() {
			if b.Mode == "hard" {
				return Reservation{}, &Refusal{Reason: "budget_" + b.unit(), Period: b.Period, Scope: b.scope()}
			}
			out.SoftExceeded = true
			out.SoftBudgets = append(out.SoftBudgets, BudgetHit{Unit: b.unit(), Period: b.Period, Scope: b.scope()})
		}
	}
	return out, nil
}

// SettleUsage settles one call in tx at its reservation's prices. The amounts
// take the call's operation; another unit's amount is refused. resolver, when
// set, is the principal who settled a call of unknown outcome.
func SettleUsage(ctx context.Context, tx pgx.Tx, tenantID, id string, q accounting.Amounts, resolver *string) (*int64, error) {
	var state, agent, alias string
	var in, out, seconds, pages, cost *int64
	var reservedTokens, reservedCost int64
	var created time.Time
	var p accounting.Prices
	err := tx.QueryRow(ctx, `SELECT state,operation,input_tokens,output_tokens,audio_seconds,pages,estimated_cost_micro,priced,input_micro_per_mtok,output_micro_per_mtok,
        audio_micro_per_minute,ocr_micro_per_page,agent_id,alias,created_at,reserved_tokens,reserved_cost_micro FROM llm_usage WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id).
		Scan(&state, &q.Operation, &in, &out, &seconds, &pages, &cost, &p.Priced, &p.InputPerMillion, &p.OutputPerMillion, &p.AudioPerMinute, &p.PerPage,
			&agent, &alias, &created, &reservedTokens, &reservedCost)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, persistence.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !q.Valid(false) {
		return nil, persistence.ErrInput
	}
	switch state {
	case "settled":
		if resolver == nil && *in == q.Input && *out == q.Output && equalAmount(seconds, q.AudioSeconds) && equalAmount(pages, q.Pages) {
			return cost, nil
		}
		if resolver == nil {
			return nil, persistence.ErrConflict
		}
		return nil, persistence.ErrTransition
	case "released":
		return nil, persistence.ErrTransition
	}
	cost = nil
	if p.Priced {
		c, ok := p.Cost(q)
		if !ok {
			return nil, persistence.ErrInput
		}
		cost = &c
	}
	seconds, pages = nil, nil
	switch q.Operation {
	case accounting.Transcribe:
		seconds = &q.AudioSeconds
	case accounting.OCR:
		pages = &q.Pages
	}
	if _, err = tx.Exec(ctx, `UPDATE llm_usage SET state='settled',input_tokens=$3,output_tokens=$4,estimated_cost_micro=$5,settled_at=clock_timestamp(),
        resolved_by=$6,resolved_at=CASE WHEN $6::text IS NULL THEN NULL ELSE clock_timestamp() END,audio_seconds=$7,pages=$8 WHERE tenant_id=$1 AND id=$2`,
		tenantID, id, q.Input, q.Output, cost, resolver, seconds, pages); err != nil {
		return nil, err
	}
	// The budgets counted the reservation (a call in flight or of unknown
	// outcome); they now count what the call used.
	var settledCost int64
	if cost != nil {
		settledCost = *cost
	}
	if err = countCall(ctx, tx, tenantID, agent, alias, created, q.Input+q.Output-reservedTokens, settledCost-reservedCost); err != nil {
		return nil, err
	}
	return cost, nil
}

// ReleaseUsage releases call id of tenant, in a state that counts its
// reservation (reserved or unknown), and takes its reservation off its
// budgets' windows. resolver, when set, is the principal who released a call
// of unknown outcome.
func ReleaseUsage(ctx context.Context, tx pgx.Tx, tenantID, id string, resolver *string) error {
	var agent, alias string
	var created time.Time
	var tokens, cost int64
	err := tx.QueryRow(ctx, `UPDATE llm_usage SET state='released',resolved_by=$3,resolved_at=CASE WHEN $3::text IS NULL THEN NULL ELSE clock_timestamp() END
        WHERE tenant_id=$1 AND id=$2 RETURNING agent_id,alias,created_at,reserved_tokens,reserved_cost_micro`, tenantID, id, resolver).
		Scan(&agent, &alias, &created, &tokens, &cost)
	if errors.Is(err, pgx.ErrNoRows) {
		return persistence.ErrNotFound
	}
	if err != nil {
		return err
	}
	return countCall(ctx, tx, tenantID, agent, alias, created, -tokens, -cost)
}

// equalAmount compares a settled amount in seconds or pages, null when the
// call does not count that unit, with a reported one.
func equalAmount(settled *int64, reported int64) bool {
	if settled == nil {
		return reported == 0
	}
	return *settled == reported
}
