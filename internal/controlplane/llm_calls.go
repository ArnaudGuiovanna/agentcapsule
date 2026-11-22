package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/budgets"
)

// The LLM service (internal/llmservice) calls the model providers; the
// control plane keeps what a call needs of PostgreSQL (v0.1.0 audit, finding
// A-02). These are what the service asks of it, in the order of a call: the
// organization's status and the VM's placement, the alias's route, the
// reservation, then the single outcome (SettleLLMCall, MarkLLMUnknown or
// ReleaseLLM). Each is one transaction of its own: no lock is held while the
// provider answers.

// ErrLLMAlreadyProcessed: this request key already has a reservation that is not
// safe to replay. The caller must use a new key to ask again.
var ErrLLMAlreadyProcessed = budgets.ErrAlreadyProcessed

// OrganizationDisabled reports whether the organization tenantID is
// disabled: its agents call no model (organization_suspension.go).
func (a *Accounts) OrganizationDisabled(ctx context.Context, tenantID string) (bool, error) {
	return organizationDisabled(ctx, a.store.pool, tenantID)
}

// VMTenant is the organization of the agent whose running VM caller names,
// once its placement is checked: a stale or foreign VM is refused
// (ErrPlacement, ErrForbidden).
func (a *Accounts) VMTenant(ctx context.Context, caller VMCaller) (string, error) {
	return a.store.vmTenant(ctx, caller)
}

// ReserveLLMCall is ReserveLLM for a call of any operation, at the amounts
// its route's plan gives; via is the route the call was planned on, or nil
// (see reserveLLM: a route resolved before its provider changed is never
// used).
func (a *Accounts) ReserveLLMCall(ctx context.Context, tenantID, agentID, alias, requestKey string, q LLMAmounts, via *LLMRoute) (LLMReservation, error) {
	return a.reserveLLM(ctx, tenantID, agentID, alias, requestKey, q, via)
}

// SettleLLMCall settles a call of any operation at the amounts the provider
// reported, in the call's units, and returns its estimated cost, nil for an
// unpriced alias.
func (a *Accounts) SettleLLMCall(ctx context.Context, tenantID, reservationID string, q LLMAmounts) (*int64, error) {
	return a.settleLLMCall(ctx, tenantID, reservationID, q)
}

// LLMAliasAccess refuses with reason alias_access an agent that may not call
// a listed alias, as the reservation does; nil when it may.
func (a *Accounts) LLMAliasAccess(ctx context.Context, tenantID, agentID, alias string) error {
	return a.llmAliasAccess(ctx, tenantID, agentID, alias)
}
