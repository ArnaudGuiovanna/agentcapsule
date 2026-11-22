package controlplane

import (
	"context"
	"errors"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/accounting"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/budgets"
	"github.com/jackc/pgx/v5"
)

// ErrBudgetExceeded is returned when the planned call exceeds a hard budget.
var ErrBudgetExceeded = budgets.ErrBudgetExceeded

type LLMRefusal = budgets.Refusal

type LLMBudget = budgets.Budget

type CreateLLMBudgetInput = budgets.CreateBudgetInput

type LLMBudgetHit = budgets.BudgetHit

type LLMReservation = budgets.Reservation

type LLMUsageLine = budgets.UsageLine

type LLMUsageTotals = budgets.UsageTotals

type LLMUsageReport = budgets.UsageReport

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
		b, err := budgets.CreateBudget(ctx, tx, p.TenantID, p.ID, in)
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
		b, changed, err := budgets.DisableBudget(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if !changed {
			return 200, b, nil
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
	items, err := budgets.ListBudgets(ctx, tx, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
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
	return a.reserveLLM(ctx, tenantID, agentID, alias, requestKey, LLMAmounts{Operation: LLMChat, Input: input, Output: output}, nil)
}

// ErrLLMRouteChanged: the provider's credential changed between the route's
// resolution and its reservation. Nothing was reserved; resolve again.
var ErrLLMRouteChanged = errors.New("llm route changed before its reservation")

// reserveLLM is ReserveLLM for any operation: the alias must declare it
// (refused with reason unsupported otherwise), token budgets count its tokens
// (none for a transcription or OCR call) and cost budgets its cost at the
// price of its unit. A request key that names a call of another operation is
// refused with ErrLLMAlreadyProcessed. The alias's provider is read again in
// the reservation's transaction (audit finding L-08): a provider disabled
// since via was resolved refuses the call (ErrNotFound), and a credential
// rotated since then gives ErrLLMRouteChanged, so that a route resolved
// before either change is never used.
func (a *Accounts) reserveLLM(ctx context.Context, tenantID, agentID, alias, requestKey string, q LLMAmounts, via *LLMRoute) (LLMReservation, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(agentID, 100) || !validOrganizationText(alias, 100) ||
		!validOrganizationText(requestKey, 200) || !q.Valid(true) {
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
		return LLMReservation{}, ErrLLMRouteChanged
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
	prices := accounting.PricesFor(q.Operation, tokensPriced, inputPrice, outputPrice, audioPrice, pagePrice)
	out, err := budgets.ReserveCall(ctx, tx, tenantID, agentID, alias, requestKey, q, prices)
	if err != nil {
		return LLMReservation{}, err
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
	return a.settleLLMCall(ctx, tenantID, reservationID, LLMAmounts{Input: input, Output: output})
}

// settleLLMCall settles a call of any operation at the amounts the provider
// reported, in the call's units.
func (a *Accounts) settleLLMCall(ctx context.Context, tenantID, reservationID string, q LLMAmounts) (*int64, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(reservationID, 100) {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	cost, err := budgets.SettleUsage(ctx, tx, tenantID, reservationID, q, nil)
	if err != nil {
		return nil, err
	}
	return cost, commit(ctx, tx)
}

func validUsage(input, output int64) bool {
	return input >= 0 && output >= 0 && input <= 1e12 && output <= 1e12
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
		err = budgets.ReleaseUsage(ctx, tx, tenantID, reservationID, nil)
	} else {
		// A call of unknown outcome keeps counting its reservation.
		_, err = tx.Exec(ctx, `UPDATE llm_usage SET state=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, reservationID, to)
	}
	if err != nil {
		return err
	}
	return commit(ctx, tx)
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
	return budgets.ReadUsage(ctx, tx, p.TenantID, period)
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
