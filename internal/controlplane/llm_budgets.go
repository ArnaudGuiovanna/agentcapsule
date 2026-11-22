package controlplane

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmpolicy"
	"github.com/jackc/pgx/v5"
)

// ErrBudgetExceeded is returned before any upstream call when a hard budget
// cannot cover the reservation. The error is an *LLMRefusal that says which.
var ErrBudgetExceeded = errors.New("llm budget exceeded")

// LLMRefusal is a typed refusal of a model call before any reservation or
// provider call. Reason is budget_tokens or budget_cost (a hard budget would be
// exceeded), unpriced (a hard cost budget applies to an alias without prices
// for the call's unit), alias_access (the alias is listed and not granted to
// the agent) or unsupported (the alias does not declare the call's
// operation). Period and Scope describe the budget, never by its identifiers.
type LLMRefusal struct {
	Reason string
	Period string
	Scope  string
}

func (e *LLMRefusal) Error() string { return "llm call refused: " + e.Reason }

func (e *LLMRefusal) Is(target error) bool {
	switch e.Reason {
	case "alias_access":
		return target == ErrLLMAliasDenied
	case "unsupported":
		return target == llmpolicy.ErrUnsupported
	}
	return target == ErrBudgetExceeded
}

// LLMBudget limits the tokens (LimitTokens) or the estimated cost
// (LimitCostMicro, in micro-units of the organization's currency) of an
// organization, an agent, an alias, or an agent and an alias, per UTC day or
// month. Used is what its current window counts, in its own unit; a list gives
// it for active budgets.
type LLMBudget struct {
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

// CreateLLMBudgetInput sets exactly one of LimitTokens and LimitCostMicro.
type CreateLLMBudgetInput struct {
	AgentID        string `json:"agent_id,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Period         string `json:"period"`
	LimitTokens    int64  `json:"limit_tokens"`
	LimitCostMicro int64  `json:"limit_cost_micro,omitempty"`
	Mode           string `json:"mode"`
}

const budgetColumns = `id,agent_id,alias,period,limit_tokens,limit_cost_micro,mode,status,created_at`

func scanBudget(row pgx.Row) (LLMBudget, error) {
	var b LLMBudget
	err := row.Scan(&b.ID, &b.AgentID, &b.Alias, &b.Period, &b.LimitTokens, &b.LimitCostMicro, &b.Mode, &b.Status, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return b, err
}

func (b LLMBudget) costs() bool { return b.LimitCostMicro != nil }

func (b LLMBudget) unit() string {
	if b.costs() {
		return "cost"
	}
	return "tokens"
}

func (b LLMBudget) limit() int64 {
	if b.costs() {
		return *b.LimitCostMicro
	}
	return *b.LimitTokens
}

// scope says what a budget covers, for refusals, metrics and logs.
func (b LLMBudget) scope() string {
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

func auditBudget(ctx context.Context, tx pgx.Tx, p Principal, budget, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO llm_audit(id,tenant_id,actor_principal_id,budget_id,action) VALUES($1,$2,$3,$4,$5)`,
		newID("audit"), p.TenantID, p.ID, budget, action)
	return err
}

func (a *Accounts) CreateLLMBudget(ctx context.Context, p Principal, key string, in CreateLLMBudgetInput) (APIReceipt, error) {
	if (in.Period != "day" && in.Period != "month") || (in.Mode != "hard" && in.Mode != "soft") ||
		(in.LimitTokens > 0) == (in.LimitCostMicro > 0) || in.LimitTokens < 0 || in.LimitCostMicro < 0 || in.LimitTokens > 1e15 || in.LimitCostMicro > 1e15 ||
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
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_budgets WHERE tenant_id=$1 AND coalesce(agent_id,'')=$2 AND coalesce(alias,'')=$3 AND period=$4
            AND (limit_cost_micro IS NOT NULL)=$5 AND status='active')`, p.TenantID, in.AgentID, in.Alias, in.Period, in.LimitCostMicro > 0).Scan(&taken); err != nil {
			return 0, nil, err
		}
		if taken {
			return 0, nil, ErrConflict
		}
		b, err := scanBudget(tx.QueryRow(ctx, `INSERT INTO llm_budgets(id,tenant_id,agent_id,alias,period,limit_tokens,limit_cost_micro,mode,created_by)
            VALUES($1,$2,nullif($3,''),nullif($4,''),$5,nullif($6::bigint,0),nullif($7::bigint,0),$8,$9) RETURNING `+budgetColumns,
			newID("bud"), p.TenantID, in.AgentID, in.Alias, in.Period, in.LimitTokens, in.LimitCostMicro, in.Mode, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = countNewBudget(ctx, tx, p.TenantID, b); err != nil {
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
	items := []LLMBudget{}
	for rows.Next() {
		b, err := scanBudget(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, b)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for i, b := range items {
		if b.Status != "active" {
			continue
		}
		used, err := budgetUsed(ctx, tx, p.TenantID, b)
		if err != nil {
			return nil, err
		}
		items[i].Used = &used
	}
	return items, commit(ctx, tx)
}

// LLMBudgetHit names a budget a call went past: its unit (tokens or cost),
// period and scope.
type LLMBudgetHit struct {
	Unit   string
	Period string
	Scope  string
}

// LLMReservation is the gateway's handle on one planned upstream call.
type LLMReservation struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	ReservedTokens    int64  `json:"reserved_tokens"`
	ReservedCostMicro int64  `json:"reserved_cost_micro"`
	// SoftExceeded is true when a soft budget is over its limit with this
	// call. The call is allowed; the caller should surface the warning.
	SoftExceeded bool `json:"soft_exceeded"`
	// SoftBudgets lists those soft budgets.
	SoftBudgets []LLMBudgetHit `json:"-"`
	// Replayed means this request key already had a reservation; the caller must
	// not issue the upstream call again unless State is "reserved".
	Replayed bool `json:"replayed"`
}

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
func budgetUsed(ctx context.Context, tx pgx.Tx, tenant string, b LLMBudget) (int64, error) {
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
func countNewBudget(ctx context.Context, tx pgx.Tx, tenant string, b LLMBudget) error {
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
func countReservation(ctx context.Context, tx pgx.Tx, tenant string, b LLMBudget, created time.Time, amount int64) (int64, error) {
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

// costMicro is the estimated cost, in micro-units, of input and output tokens
// at prices in micro-units per million tokens, rounded up once so that an
// estimate never under-reports. It is exact: the products do not fit in 64
// bits at the accepted bounds (10^12 tokens, 10^12 per million), so they are
// computed on big integers. ok is false if the cost does not fit in an int64.
func costMicro(input, output, inputPrice, outputPrice int64) (int64, bool) {
	sum := new(big.Int).Mul(big.NewInt(input), big.NewInt(inputPrice))
	sum.Add(sum, new(big.Int).Mul(big.NewInt(output), big.NewInt(outputPrice)))
	sum.Add(sum, big.NewInt(999_999))
	sum.Quo(sum, big.NewInt(1_000_000))
	if !sum.IsInt64() {
		return 0, false
	}
	return sum.Int64(), true
}

// ReserveLLM must precede every upstream chat call. input and output are the
// call's estimated input tokens and its output cap. It refuses an agent the
// alias is not granted to, and an alias that does not serve chat, then
// serializes with the other calls that share a budget by locking the
// applicable budget rows in a fixed order, so concurrent reservations never
// overshoot a hard limit, in tokens or in cost. The call keeps the alias's
// current prices. A repeated request key returns the existing reservation and
// never counts twice. The alias's provider must still be active.
func (a *Accounts) ReserveLLM(ctx context.Context, tenantID, agentID, alias, requestKey string, input, output int64) (LLMReservation, error) {
	return a.reserveLLM(ctx, tenantID, agentID, alias, requestKey, llmAmounts{Operation: LLMChat, Input: input, Output: output}, nil)
}

// errLLMRouteChanged: the provider's credential changed between the route's
// resolution and its reservation. Nothing was reserved; resolve again.
var errLLMRouteChanged = errors.New("llm route changed before its reservation")

// reserveLLM is ReserveLLM for any operation: the alias must declare it
// (refused with reason unsupported otherwise), token budgets count its tokens
// (none for a transcription or OCR call) and cost budgets its cost at the
// price of its unit. A request key that names a call of another operation is
// refused with ErrLLMAlreadyProcessed. The alias's provider is read again in
// the reservation's transaction (audit finding L-08): a provider disabled
// since via was resolved refuses the call (ErrNotFound), and a credential
// rotated since then gives errLLMRouteChanged, so that a route resolved
// before either change is never used.
func (a *Accounts) reserveLLM(ctx context.Context, tenantID, agentID, alias, requestKey string, q llmAmounts, via *LLMRoute) (LLMReservation, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(agentID, 100) || !validOrganizationText(alias, 100) ||
		!validOrganizationText(requestKey, 200) || !q.valid(true) {
		return LLMReservation{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return LLMReservation{}, err
	}
	defer rollback(tx)
	var orgActive bool
	if err = tx.QueryRow(ctx, `SELECT status='active' FROM organizations WHERE id=$1 FOR KEY SHARE`, tenantID).Scan(&orgActive); errors.Is(err, pgx.ErrNoRows) || (err == nil && !orgActive) {
		return LLMReservation{}, ErrNotFound
	} else if err != nil {
		return LLMReservation{}, err
	}
	var agentOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, tenantID, agentID).Scan(&agentOK); err != nil {
		return LLMReservation{}, err
	}
	var access string
	var tokensPriced bool
	var inputPrice, outputPrice int64
	var operations []string
	var audioPrice, pagePrice *int64
	var providerID string
	var generation int64
	// The organization's row lock above serializes this read with every
	// change of a provider or an alias, which takes that row FOR UPDATE first
	// (authorizeTenantAdminMutation): a change committed before it is seen,
	// one after it waits for this reservation. FOR KEY SHARE is enough: it
	// conflicts with FOR UPDATE (P-07).
	err = tx.QueryRow(ctx, `SELECT m.access,m.priced,m.input_micro_per_mtok,m.output_micro_per_mtok,m.operations,m.audio_micro_per_minute,m.ocr_micro_per_page,
        p.id,p.secret_generation FROM llm_model_aliases m JOIN llm_providers p ON (p.tenant_id,p.id)=(m.tenant_id,m.provider_id)
        WHERE m.tenant_id=$1 AND m.alias=$2 AND m.status='active' AND p.status='active'`,
		tenantID, alias).Scan(&access, &tokensPriced, &inputPrice, &outputPrice, &operations, &audioPrice, &pagePrice, &providerID, &generation)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !agentOK) || (err == nil && via != nil && via.ProviderID != providerID) {
		return LLMReservation{}, ErrNotFound
	}
	if err != nil {
		return LLMReservation{}, err
	}
	if via != nil && via.Generation != generation {
		return LLMReservation{}, errLLMRouteChanged
	}
	// Access is checked before the request key: a revoked grant also refuses
	// the replay of a key, and nothing is reserved.
	if access == "listed" {
		granted, err := aliasGranted(ctx, tx, tenantID, alias, agentID)
		if err != nil {
			return LLMReservation{}, err
		}
		if !granted {
			return LLMReservation{}, &LLMRefusal{Reason: "alias_access"}
		}
	}
	// So is the operation: nothing is reserved for a route the alias does not
	// serve.
	if !slices.Contains(operations, q.Operation) {
		return LLMReservation{}, &LLMRefusal{Reason: "unsupported"}
	}
	prices := aliasPrices(q.Operation, tokensPriced, inputPrice, outputPrice, audioPrice, pagePrice)
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
	var existingOperation string
	err = tx.QueryRow(ctx, `SELECT id,state,reserved_tokens,reserved_cost_micro,operation FROM llm_usage WHERE tenant_id=$1 AND agent_id=$2 AND request_key=$3`, tenantID, agentID, requestKey).
		Scan(&existing.ID, &existing.State, &existing.ReservedTokens, &existing.ReservedCostMicro, &existingOperation)
	if err == nil {
		if existingOperation != q.Operation {
			return LLMReservation{}, ErrLLMAlreadyProcessed
		}
		existing.Replayed = true
		return existing, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LLMReservation{}, err
	}
	out := LLMReservation{ID: newID("use"), State: "reserved", ReservedTokens: q.tokens()}
	if prices.priced {
		var ok bool
		if out.ReservedCostMicro, ok = prices.cost(q); !ok {
			return LLMReservation{}, ErrInput
		}
	}
	// The call is written first: the time it is created at is the one each
	// budget's window is taken at. A refusal below rolls it back with the
	// counts.
	var created time.Time
	if err = tx.QueryRow(ctx, `INSERT INTO llm_usage(id,tenant_id,agent_id,alias,request_key,reserved_tokens,reserved_cost_micro,priced,input_micro_per_mtok,output_micro_per_mtok,
        operation,reserved_audio_seconds,reserved_pages,audio_micro_per_minute,ocr_micro_per_page)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING created_at`, out.ID, tenantID, agentID, alias, requestKey, out.ReservedTokens, out.ReservedCostMicro, prices.priced,
		inputPrice, outputPrice, q.Operation, q.AudioSeconds, q.Pages, prices.audioPerMinute, prices.perPage).Scan(&created); err != nil {
		return LLMReservation{}, err
	}
	for _, b := range budgets {
		if !b.costs() && out.ReservedTokens == 0 {
			continue // seconds and pages count only in cost budgets
		}
		if b.costs() && !prices.priced {
			// No estimate exists: a hard cap could not hold, a soft one counts
			// nothing for this call.
			if b.Mode == "hard" {
				return LLMReservation{}, &LLMRefusal{Reason: "unpriced", Period: b.Period, Scope: b.scope()}
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
			return LLMReservation{}, err
		}
		if used > b.limit() {
			if b.Mode == "hard" {
				return LLMReservation{}, &LLMRefusal{Reason: "budget_" + b.unit(), Period: b.Period, Scope: b.scope()}
			}
			out.SoftExceeded = true
			out.SoftBudgets = append(out.SoftBudgets, LLMBudgetHit{Unit: b.unit(), Period: b.Period, Scope: b.scope()})
		}
	}
	return out, commit(ctx, tx)
}

// SettleLLM records the provider-reported usage. It also resolves a call left
// 'unknown', which is how a late report corrects the uncertain amount. Settling
// twice with the same numbers is a no-op; different numbers conflict.
func (a *Accounts) SettleLLM(ctx context.Context, tenantID, reservationID string, input, output int64) error {
	_, err := a.settleLLM(ctx, tenantID, reservationID, input, output)
	return err
}

// settleLLM also returns the call's estimated cost, nil for an unpriced alias.
func (a *Accounts) settleLLM(ctx context.Context, tenantID, reservationID string, input, output int64) (*int64, error) {
	return a.settleLLMCall(ctx, tenantID, reservationID, llmAmounts{Input: input, Output: output})
}

// settleLLMCall settles a call of any operation at the amounts the provider
// reported, in the call's units.
func (a *Accounts) settleLLMCall(ctx context.Context, tenantID, reservationID string, q llmAmounts) (*int64, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(reservationID, 100) {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	cost, err := settleCall(ctx, tx, tenantID, reservationID, q, nil)
	if err != nil {
		return nil, err
	}
	return cost, commit(ctx, tx)
}

func validUsage(input, output int64) bool {
	return input >= 0 && output >= 0 && input <= 1e12 && output <= 1e12
}

// settleCall settles one call in tx at its reservation's prices. The amounts
// take the call's operation; another unit's amount is refused. resolver, when
// set, is the principal who settled a call of unknown outcome.
func settleCall(ctx context.Context, tx pgx.Tx, tenantID, id string, q llmAmounts, resolver *string) (*int64, error) {
	var state, agent, alias string
	var in, out, seconds, pages, cost *int64
	var reservedTokens, reservedCost int64
	var created time.Time
	var p llmPrices
	err := tx.QueryRow(ctx, `SELECT state,operation,input_tokens,output_tokens,audio_seconds,pages,estimated_cost_micro,priced,input_micro_per_mtok,output_micro_per_mtok,
        audio_micro_per_minute,ocr_micro_per_page,agent_id,alias,created_at,reserved_tokens,reserved_cost_micro FROM llm_usage WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id).
		Scan(&state, &q.Operation, &in, &out, &seconds, &pages, &cost, &p.priced, &p.input, &p.output, &p.audioPerMinute, &p.perPage,
			&agent, &alias, &created, &reservedTokens, &reservedCost)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !q.valid(false) {
		return nil, ErrInput
	}
	switch state {
	case "settled":
		if resolver == nil && *in == q.Input && *out == q.Output && equalAmount(seconds, q.AudioSeconds) && equalAmount(pages, q.Pages) {
			return cost, nil
		}
		if resolver == nil {
			return nil, ErrConflict
		}
		return nil, ErrTransition
	case "released":
		return nil, ErrTransition
	}
	cost = nil
	if p.priced {
		c, ok := p.cost(q)
		if !ok {
			return nil, ErrInput
		}
		cost = &c
	}
	seconds, pages = nil, nil
	switch q.Operation {
	case LLMTranscribe:
		seconds = &q.AudioSeconds
	case LLMOCR:
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

// releaseCall releases call id of tenant, in a state that counts its
// reservation (reserved or unknown), and takes its reservation off its
// budgets' windows. resolver, when set, is the principal who released a call
// of unknown outcome.
func releaseCall(ctx context.Context, tx pgx.Tx, tenantID, id string, resolver *string) error {
	var agent, alias string
	var created time.Time
	var tokens, cost int64
	err := tx.QueryRow(ctx, `UPDATE llm_usage SET state='released',resolved_by=$3,resolved_at=CASE WHEN $3::text IS NULL THEN NULL ELSE clock_timestamp() END
        WHERE tenant_id=$1 AND id=$2 RETURNING agent_id,alias,created_at,reserved_tokens,reserved_cost_micro`, tenantID, id, resolver).
		Scan(&agent, &alias, &created, &tokens, &cost)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
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
	if to == "released" {
		err = releaseCall(ctx, tx, tenantID, reservationID, nil)
	} else {
		// A call of unknown outcome keeps counting its reservation.
		_, err = tx.Exec(ctx, `UPDATE llm_usage SET state=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, reservationID, to)
	}
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}

// LLMUsageLine is one aggregate of the current window. Uncertain amounts are
// reported apart from settled ones, and cost is an estimate from the prices of
// each call's reservation, never an invoice.
type LLMUsageLine struct {
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

// LLMUsageTotals is the organization's sum of the lines.
type LLMUsageTotals struct {
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

type LLMUsageReport struct {
	Period    string         `json:"period"`
	Since     time.Time      `json:"since"`
	Lines     []LLMUsageLine `json:"lines"`
	Totals    LLMUsageTotals `json:"totals"`
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
	if err = authorizeUsageRead(ctx, tx, p); err != nil {
		return LLMUsageReport{}, err
	}
	rep := LLMUsageReport{Period: period, Estimated: true, Lines: []LLMUsageLine{}}
	if err = tx.QueryRow(ctx, `SELECT `+windowStart(period)).Scan(&rep.Since); err != nil {
		return LLMUsageReport{}, err
	}
	rows, err := tx.Query(ctx, `SELECT agent_id,alias,count(*) FILTER (WHERE state<>'released'),
        coalesce(sum(input_tokens) FILTER (WHERE state='settled'),0),coalesce(sum(output_tokens) FILTER (WHERE state='settled'),0),
        coalesce(sum(reserved_tokens) FILTER (WHERE state='reserved'),0),coalesce(sum(reserved_tokens) FILTER (WHERE state='unknown'),0),
        coalesce(sum(estimated_cost_micro) FILTER (WHERE state='settled'),0),
        coalesce(sum(reserved_cost_micro) FILTER (WHERE state='reserved'),0),coalesce(sum(reserved_cost_micro) FILTER (WHERE state='unknown'),0),
        coalesce(sum(audio_seconds) FILTER (WHERE state='settled'),0),coalesce(sum(pages) FILTER (WHERE state='settled'),0)
        FROM llm_usage WHERE tenant_id=$1 AND created_at >= $2 GROUP BY agent_id,alias ORDER BY agent_id,alias`, p.TenantID, rep.Since)
	if err != nil {
		return LLMUsageReport{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var l LLMUsageLine
		if err = rows.Scan(&l.AgentID, &l.Alias, &l.Calls, &l.SettledInput, &l.SettledOutput, &l.PendingTokens, &l.UnknownTokens,
			&l.EstimatedCostMicr, &l.PendingCostMicro, &l.UnknownCostMicro, &l.SettledAudioSeconds, &l.SettledPages); err != nil {
			return LLMUsageReport{}, err
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
		return LLMUsageReport{}, err
	}
	return rep, nil
}

func authorizeUsageRead(ctx context.Context, tx pgx.Tx, p Principal) error {
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeUsageRead)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadUsage) {
		return ErrForbidden
	}
	return nil
}
