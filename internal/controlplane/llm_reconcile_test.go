package controlplane

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// A call of unknown outcome keeps counting until the organization, which can
// read its provider's account, settles it at the real usage or releases it.
func TestUnknownOutcomesAreListedThenSettledOrReleasedByTheOrganization(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "h", CreateLLMBudgetInput{Period: "day", LimitTokens: 800, Mode: "hard"})
	lost, err := b.reserveSplit(b.agent, "fast", "lost", 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	cut, err := b.reserveSplit(b.other, "fast", "cut", 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := b.reserveSplit(b.agent, "fast", "stale", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := b.reserveSplit(b.agent, "fast", "fresh", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{lost.ID, cut.ID} {
		if err = b.a.MarkLLMUnknown(t.Context(), b.owner.TenantID, id); err != nil {
			t.Fatal(err)
		}
	}
	// A reservation older than any call is listed too: its call died with its worker.
	if _, err = b.s.pool.Exec(t.Context(), `UPDATE llm_usage SET created_at=created_at-interval '1 hour' WHERE id=$1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	items, err := b.a.ListLLMUnresolved(t.Context(), b.owner, "", 10)
	if err != nil || len(items) != 3 {
		t.Fatal("unresolved", err, items)
	}
	if n, err := b.s.LLMUnresolvedCalls(t.Context()); err != nil || n != 3 {
		t.Fatal("installation count", n, err)
	}
	for _, it := range items {
		if it.ID == fresh.ID {
			t.Fatal("a call that may still be running was listed")
		}
		if it.ID == lost.ID && (it.State != "unknown" || it.AgentID != b.agent || it.Alias != "fast" || it.ReservedTokens != 300 || it.ReservedCostMicro != 700) {
			t.Fatal("item", it)
		}
	}
	if _, err = b.reserveSplit(b.agent, "fast", "full", 1, 0); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("unknown outcomes stopped counting", err)
	}
	r, err := b.a.SettleLLMOutcome(t.Context(), b.owner, lost.ID, "s1", SettleLLMOutcomeInput{InputTokens: 10, OutputTokens: 5})
	var settled LLMCall
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &settled) != nil || settled.State != "settled" {
		t.Fatal("settle", err, r.Status)
	}
	if again, err := b.a.SettleLLMOutcome(t.Context(), b.owner, lost.ID, "s1", SettleLLMOutcomeInput{InputTokens: 10, OutputTokens: 5}); err != nil || !again.Replayed {
		t.Fatal("replay", err)
	}
	if _, err = b.a.SettleLLMOutcome(t.Context(), b.owner, lost.ID, "s2", SettleLLMOutcomeInput{InputTokens: 99, OutputTokens: 5}); !errors.Is(err, ErrTransition) {
		t.Fatal("a resolved outcome rewritten", err)
	}
	if _, err = b.a.ReleaseLLMOutcome(t.Context(), b.owner, cut.ID, "r1"); err != nil {
		t.Fatal("release", err)
	}
	if _, err = b.a.ReleaseLLMOutcome(t.Context(), b.owner, stale.ID, "r2"); err != nil {
		t.Fatal("release stale", err)
	}
	if _, err = b.a.ReleaseLLMOutcome(t.Context(), b.owner, fresh.ID, "r3"); !errors.Is(err, ErrTransition) {
		t.Fatal("a call that may still be running was released", err)
	}
	if _, err = b.a.ReleaseLLMOutcome(t.Context(), b.owner, lost.ID, "r4"); !errors.Is(err, ErrTransition) {
		t.Fatal("a settled call was released", err)
	}
	// 15 settled + 100 in flight + 600 fit in 800: the capacity is back.
	if _, err = b.reserveSplit(b.agent, "fast", "after", 600, 0); err != nil {
		t.Fatal("capacity not returned", err)
	}
	var cost int64
	var by *string
	if err = b.s.pool.QueryRow(t.Context(), `SELECT estimated_cost_micro,resolved_by FROM llm_usage WHERE id=$1`, lost.ID).Scan(&cost, &by); err != nil || cost != 25 || by == nil || *by != b.owner.ID {
		t.Fatal("settled row", err, cost, by)
	}
	var audited int
	if err = b.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_audit WHERE action IN ('usage.settled','usage.released')`).Scan(&audited); err != nil || audited != 3 {
		t.Fatal("audit", audited, err)
	}
	if items, err = b.a.ListLLMUnresolved(t.Context(), b.owner, "", 10); err != nil || len(items) != 0 {
		t.Fatal("still unresolved", items, err)
	}
	if n, err := b.s.LLMUnresolvedCalls(t.Context()); err != nil || n != 0 {
		t.Fatal("installation count after reconciliation", n, err)
	}
	// The audit trail reads it as an action on the agent's call.
	page, err := b.a.ListAudit(t.Context(), b.owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range page.Items {
		if e.Action == "llm.usage.settled" && e.Target == b.agent && e.Reference == lost.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("audit feed", page.Items)
	}
}

func TestReconciliationRights(t *testing.T) {
	b := newBudgetLab(t)
	r, err := b.reserveSplit(b.agent, "fast", "k", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.MarkLLMUnknown(t.Context(), b.owner.TenantID, r.ID); err != nil {
		t.Fatal(err)
	}
	addMember(t, b.tenantLab, b.owner, "auditor", authorization.Auditor)
	auditor := agentPrincipal(t, b.tenantLab, "auditor", agentScopes)
	if items, err := b.a.ListLLMUnresolved(t.Context(), auditor, "", 10); err != nil || len(items) != 1 {
		t.Fatal("an auditor reads usage", err)
	}
	if _, err = b.a.ReleaseLLMOutcome(t.Context(), auditor, r.ID, "a"); !errors.Is(err, ErrForbidden) {
		t.Fatal("an auditor resolved an outcome", err)
	}
	noScope := agentPrincipal(t, b.tenantLab, organizationInput().InitialOwner.Subject, "org:read usage:read")
	if _, err = b.a.SettleLLMOutcome(t.Context(), noScope, r.ID, "n", SettleLLMOutcomeInput{InputTokens: 1}); !errors.Is(err, ErrForbidden) {
		t.Fatal("a credential without quota:manage resolved an outcome", err)
	}
	if _, err = b.a.SettleLLMOutcome(t.Context(), b.owner, "use_unknown", "u", SettleLLMOutcomeInput{InputTokens: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown call", err)
	}
	if _, err = b.a.SettleLLMOutcome(t.Context(), b.owner, r.ID, "neg", SettleLLMOutcomeInput{InputTokens: -1}); !errors.Is(err, ErrInput) {
		t.Fatal("negative tokens", err)
	}
}

// The organization's resolution and the worker's late settlement race on one
// call: one of them wins, the other is refused.
func TestOperatorResolutionRacesTheWorkersSettlement(t *testing.T) {
	b := newBudgetLab(t)
	for _, key := range []string{"a", "b", "c", "d", "e", "f"} {
		r, err := b.reserveSplit(b.agent, "fast", key, 10, 10)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.a.MarkLLMUnknown(t.Context(), b.owner.TenantID, r.ID); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var late, resolved error
		wg.Add(2)
		go func() { defer wg.Done(); late = b.a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, 3, 3) }()
		go func() { defer wg.Done(); _, resolved = b.a.ReleaseLLMOutcome(t.Context(), b.owner, r.ID, "rel-"+key) }()
		wg.Wait()
		if (late == nil) == (resolved == nil) {
			t.Fatal("both or neither outcome applied", late, resolved)
		}
		if late != nil && !errors.Is(late, ErrTransition) || resolved != nil && !errors.Is(resolved, ErrTransition) {
			t.Fatal("loser's error", late, resolved)
		}
	}
}
