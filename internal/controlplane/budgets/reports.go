package budgets

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// UsageLine is one aggregate of the current window. Uncertain amounts are
// reported apart from settled ones, and cost is an estimate from the prices of
// each call's reservation, never an invoice.
type UsageLine struct {
	AgentID           string `json:"agent_id"`
	Alias             string `json:"alias"`
	Calls             int64  `json:"calls"`
	SettledInput      int64  `json:"settled_input_tokens"`
	SettledOutput     int64  `json:"settled_output_tokens"`
	PendingTokens     int64  `json:"pending_tokens"`
	UnknownTokens     int64  `json:"unknown_outcome_tokens"`
	EstimatedCostMicr int64  `json:"estimated_cost_micro"`
	PendingCostMicro  int64  `json:"pending_cost_micro"`
	UnknownCostMicro  int64  `json:"unknown_outcome_cost_micro"`
	// Seconds of audio and OCR pages of settled calls (ADR 023 §12).
	SettledAudioSeconds int64 `json:"settled_audio_seconds"`
	SettledPages        int64 `json:"settled_pages"`
}

// UsageTotals is the organization's sum of the lines.
type UsageTotals struct {
	Calls              int64 `json:"calls"`
	SettledInput       int64 `json:"settled_input_tokens"`
	SettledOutput      int64 `json:"settled_output_tokens"`
	PendingTokens      int64 `json:"pending_tokens"`
	UnknownTokens      int64 `json:"unknown_outcome_tokens"`
	EstimatedCostMicro int64 `json:"estimated_cost_micro"`
	PendingCostMicro   int64 `json:"pending_cost_micro"`
	UnknownCostMicro   int64 `json:"unknown_outcome_cost_micro"`
	// Seconds of audio and OCR pages of settled calls.
	SettledAudioSeconds int64 `json:"settled_audio_seconds"`
	SettledPages        int64 `json:"settled_pages"`
}

type UsageReport struct {
	Period    string      `json:"period"`
	Since     time.Time   `json:"since"`
	Lines     []UsageLine `json:"lines"`
	Totals    UsageTotals `json:"totals"`
	Estimated bool        `json:"cost_is_estimate"`
}

// ReadUsage aggregates the tenant's reservations and settled calls for the UTC period.
func ReadUsage(ctx context.Context, tx pgx.Tx, tenant, period string) (UsageReport, error) {
	rep := UsageReport{Period: period, Estimated: true, Lines: []UsageLine{}}
	if err := tx.QueryRow(ctx, `SELECT `+windowStart(period)).Scan(&rep.Since); err != nil {
		return UsageReport{}, err
	}
	rows, err := tx.Query(ctx, `SELECT agent_id,alias,count(*) FILTER (WHERE state<>'released'),
        coalesce(sum(input_tokens) FILTER (WHERE state='settled'),0),coalesce(sum(output_tokens) FILTER (WHERE state='settled'),0),
        coalesce(sum(reserved_tokens) FILTER (WHERE state='reserved'),0),coalesce(sum(reserved_tokens) FILTER (WHERE state='unknown'),0),
        coalesce(sum(estimated_cost_micro) FILTER (WHERE state='settled'),0),
        coalesce(sum(reserved_cost_micro) FILTER (WHERE state='reserved'),0),coalesce(sum(reserved_cost_micro) FILTER (WHERE state='unknown'),0),
        coalesce(sum(audio_seconds) FILTER (WHERE state='settled'),0),coalesce(sum(pages) FILTER (WHERE state='settled'),0)
        FROM llm_usage WHERE tenant_id=$1 AND created_at >= $2 GROUP BY agent_id,alias ORDER BY agent_id,alias`, tenant, rep.Since)
	if err != nil {
		return UsageReport{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var l UsageLine
		if err = rows.Scan(&l.AgentID, &l.Alias, &l.Calls, &l.SettledInput, &l.SettledOutput, &l.PendingTokens, &l.UnknownTokens,
			&l.EstimatedCostMicr, &l.PendingCostMicro, &l.UnknownCostMicro, &l.SettledAudioSeconds, &l.SettledPages); err != nil {
			return UsageReport{}, err
		}
		rep.Lines = append(rep.Lines, l)
		t := &rep.Totals
		t.Calls += l.Calls
		t.SettledInput += l.SettledInput
		t.SettledOutput += l.SettledOutput
		t.PendingTokens += l.PendingTokens
		t.UnknownTokens += l.UnknownTokens
		t.EstimatedCostMicro += l.EstimatedCostMicr
		t.PendingCostMicro += l.PendingCostMicro
		t.UnknownCostMicro += l.UnknownCostMicro
		t.SettledAudioSeconds += l.SettledAudioSeconds
		t.SettledPages += l.SettledPages
	}
	if err = rows.Err(); err != nil {
		return UsageReport{}, err
	}
	return rep, nil
}
