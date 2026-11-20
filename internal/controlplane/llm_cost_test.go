package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// The lab's alias "fast" costs 1 micro-unit per input token and 3 per output
// token (1,000,000 and 3,000,000 per million).
func (b *budgetLab) reserveSplit(agent, alias, key string, input, output int64) (LLMReservation, error) {
	return b.a.ReserveLLM(context.Background(), b.owner.TenantID, agent, alias, key, input, output)
}

func (b *budgetLab) refusal(t *testing.T, err error) *LLMRefusal {
	t.Helper()
	var r *LLMRefusal
	if !errors.As(err, &r) {
		t.Fatal("not a typed refusal", err)
	}
	return r
}

func TestHardCostBudgetReservesSettlesAndRefusesBeforeTheProvider(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "c1", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 1000, Mode: "hard"})
	// A cost budget and a token budget on the same scope and period coexist.
	b.budget(t, "t1", CreateLLMBudgetInput{Period: "day", LimitTokens: 100000, Mode: "hard"})
	if _, err := b.a.CreateLLMBudget(t.Context(), b.owner, "c2", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 5, Mode: "soft"}); !errors.Is(err, ErrConflict) {
		t.Fatal("two cost budgets on one scope and period", err)
	}
	if _, err := b.a.CreateLLMBudget(t.Context(), b.owner, "c3", CreateLLMBudgetInput{Period: "day", LimitTokens: 5, LimitCostMicro: 5, Mode: "soft"}); !errors.Is(err, ErrInput) {
		t.Fatal("a budget limiting tokens and cost at once", err)
	}
	r1, err := b.reserveSplit(b.agent, "fast", "k1", 100, 200) // 100 + 600 = 700
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.reserveSplit(b.other, "fast", "k2", 100, 100) // 400: 1100 > 1000
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("hard cost budget exceeded", err)
	}
	if r := b.refusal(t, err); r.Reason != "budget_cost" || r.Period != "day" || r.Scope != "organization" {
		t.Fatal("refusal", r)
	}
	// Settlement replaces the reserved cost with the reported one.
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r1.ID, 50, 50); err != nil { // 50 + 150 = 200
		t.Fatal(err)
	}
	r3, err := b.reserveSplit(b.other, "fast", "k3", 100, 100) // 200 + 400 = 600
	if err != nil {
		t.Fatal("capacity not returned after settlement", err)
	}
	if _, err = b.reserveSplit(b.other, "fast", "k4", 1, 133); err != nil { // 400 = exact fit at 1000
		t.Fatal("exact fit refused", err)
	}
	if _, err = b.reserveSplit(b.other, "fast", "k5", 1, 0); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("over by one micro-unit", err)
	}
	if err = b.a.ReleaseLLM(t.Context(), b.owner.TenantID, r3.ID); err != nil {
		t.Fatal(err)
	}
	rep, err := b.a.LLMUsage(t.Context(), b.owner, "day")
	if err != nil {
		t.Fatal(err)
	}
	var settled, pending int64
	for _, l := range rep.Lines {
		settled += l.EstimatedCostMicr
		pending += l.PendingCostMicro
	}
	if settled != 200 || pending != 400 || rep.Totals.EstimatedCostMicro != 200 || rep.Totals.PendingCostMicro != 400 {
		t.Fatal("usage cost", rep)
	}
	items, err := b.a.ListLLMBudgets(t.Context(), b.owner, "", 10)
	if err != nil || len(items) != 2 {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.LimitCostMicro != nil && (it.Used == nil || *it.Used != 600) {
			t.Fatal("cost budget consumption", it.Used)
		}
		if it.LimitTokens != nil && (it.Used == nil || *it.Used != 100+134) {
			t.Fatal("token budget consumption", it.Used)
		}
	}
}

func TestAgentCostBudgetAndSoftCostCap(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "a", CreateLLMBudgetInput{AgentID: b.agent, Period: "month", LimitCostMicro: 300, Mode: "hard"})
	b.budget(t, "s", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 500, Mode: "soft"})
	if _, err := b.reserveSplit(b.agent, "fast", "k1", 0, 101); !errors.Is(err, ErrBudgetExceeded) { // 303 > 300
		t.Fatal("agent cost budget", err)
	} else if r := b.refusal(t, err); r.Scope != "agent" || r.Period != "month" {
		t.Fatal("refusal", r)
	}
	r, err := b.reserveSplit(b.other, "fast", "k2", 0, 200) // 600 > 500: soft
	if err != nil || !r.SoftExceeded || len(r.SoftBudgets) != 1 || r.SoftBudgets[0] != (LLMBudgetHit{Unit: "cost", Period: "day", Scope: "organization"}) {
		t.Fatal("soft cost cap", err, r)
	}
}

// A hard cost budget cannot hold for a model without prices: it refuses its
// calls until the organization prices the alias, zero included.
func TestHardCostBudgetRefusesAnUnpricedAlias(t *testing.T) {
	b := newBudgetLab(t)
	p := createProvider(t, b.tenantLab, b.owner, "free")
	if _, err := b.a.CreateLLMAlias(t.Context(), b.owner, "fa", CreateLLMAliasInput{Alias: "local", ProviderID: p.ID, UpstreamModel: "m"}); err != nil {
		t.Fatal(err)
	}
	b.budget(t, "s", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 10, Mode: "soft"})
	if _, err := b.reserveSplit(b.agent, "local", "k0", 5, 5); err != nil {
		t.Fatal("a soft cost budget refused an unpriced alias", err)
	}
	b.budget(t, "h", CreateLLMBudgetInput{AgentID: b.agent, Period: "day", LimitCostMicro: 10, Mode: "hard"})
	_, err := b.reserveSplit(b.agent, "local", "k1", 5, 5)
	if !errors.Is(err, ErrBudgetExceeded) || b.refusal(t, err).Reason != "unpriced" {
		t.Fatal("hard cost budget on an unpriced alias", err)
	}
	if _, err = b.reserveSplit(b.other, "local", "k2", 5, 5); err != nil {
		t.Fatal("another agent's cost budget applied", err)
	}
	if r, err := b.a.SetLLMAliasPrices(t.Context(), b.owner, "local", "free", SetLLMAliasPricesInput{InputMicroPerMTok: price(0), OutputMicroPerMTok: price(0)}); err != nil || r.Status != 200 {
		t.Fatal("prices", err)
	}
	if _, err = b.reserveSplit(b.agent, "local", "k3", 5, 5); err != nil {
		t.Fatal("a free alias refused", err)
	}
	if _, err = b.a.SetLLMAliasPrices(t.Context(), b.owner, "local", "half", SetLLMAliasPricesInput{InputMicroPerMTok: price(1)}); !errors.Is(err, ErrInput) {
		t.Fatal("prices set by omission", err)
	}
}

// A call keeps the prices of its reservation; a price change applies to calls
// reserved after it.
func TestPricesAreFixedAtReservation(t *testing.T) {
	b := newBudgetLab(t)
	r1, err := b.reserveSplit(b.agent, "fast", "k1", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.a.SetLLMAliasPrices(t.Context(), b.owner, "fast", "p2", SetLLMAliasPricesInput{InputMicroPerMTok: price(10_000_000), OutputMicroPerMTok: price(10_000_000)}); err != nil {
		t.Fatal(err)
	}
	r2, err := b.reserveSplit(b.agent, "fast", "k2", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r1.ID, 10, 10); err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r2.ID, 10, 10); err != nil {
		t.Fatal(err)
	}
	var costs []int64
	rows, err := b.s.pool.Query(t.Context(), `SELECT estimated_cost_micro FROM llm_usage ORDER BY request_key`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c int64
		_ = rows.Scan(&c)
		costs = append(costs, c)
	}
	rows.Close()
	if fmt.Sprint(costs) != "[40 200]" {
		t.Fatal("costs", costs)
	}
}

// Costs are exact in integer micro-units, rounded up once per call, even at
// the largest prices and token counts accepted.
func TestEstimatedCostIsExactAtTheBounds(t *testing.T) {
	b := newBudgetLab(t)
	p := createProvider(t, b.tenantLab, b.owner, "dear")
	if _, err := b.a.CreateLLMAlias(t.Context(), b.owner, "da", CreateLLMAliasInput{Alias: "dear", ProviderID: p.ID, UpstreamModel: "m",
		InputMicroPerMTok: price(1e12), OutputMicroPerMTok: price(1e12)}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.a.CreateLLMAlias(t.Context(), b.owner, "ca", CreateLLMAliasInput{Alias: "cheap", ProviderID: p.ID, UpstreamModel: "m",
		InputMicroPerMTok: price(1), OutputMicroPerMTok: price(0)}); err != nil {
		t.Fatal(err)
	}
	big, err := b.reserveSplit(b.agent, "dear", "big", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, big.ID, 1e12, 1e12); err != nil {
		t.Fatal(err)
	}
	tiny, err := b.reserveSplit(b.agent, "cheap", "tiny", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, tiny.ID, 1, 7); err != nil {
		t.Fatal(err)
	}
	var dear, cheap int64
	if err = b.s.pool.QueryRow(t.Context(), `SELECT (SELECT estimated_cost_micro FROM llm_usage WHERE request_key='big'),
        (SELECT estimated_cost_micro FROM llm_usage WHERE request_key='tiny')`).Scan(&dear, &cheap); err != nil {
		t.Fatal(err)
	}
	if dear != 2e18 || cheap != 1 {
		t.Fatal("inexact cost", dear, cheap)
	}
}

// Migration 0032 on an installation that has aliases, budgets and calls:
// every alias stays open to the organization, an alias with prices is priced,
// a call still open reserves its cost at the higher price, and the token
// budgets keep their limits. The test reverts the migration's objects and runs
// its SQL again, wherever the ledger places it.
func TestLLMAccessAndCostMigrationKeepsExistingInstallations(t *testing.T) {
	b := newBudgetLab(t)
	p := createProvider(t, b.tenantLab, b.owner, "old")
	if _, err := b.a.CreateLLMAlias(t.Context(), b.owner, "oa", CreateLLMAliasInput{Alias: "local", ProviderID: p.ID, UpstreamModel: "m"}); err != nil {
		t.Fatal(err)
	}
	b.budget(t, "t", CreateLLMBudgetInput{Period: "day", LimitTokens: 1000, Mode: "hard"})
	open, err := b.reserveSplit(b.agent, "fast", "open", 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.MarkLLMUnknown(t.Context(), b.owner.TenantID, open.ID); err != nil {
		t.Fatal(err)
	}
	done, err := b.reserveSplit(b.agent, "fast", "done", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.a.SettleLLM(t.Context(), b.owner.TenantID, done.ID, 5, 5); err != nil {
		t.Fatal(err)
	}
	if _, err = b.s.pool.Exec(t.Context(), `
        ALTER TABLE agent_specs DROP CONSTRAINT agent_specs_template_grant_id_fkey;
        DROP TABLE llm_alias_grants;
        DROP INDEX llm_usage_unresolved;
        ALTER TABLE llm_audit DROP CONSTRAINT llm_audit_references, DROP CONSTRAINT llm_audit_action_check,
          DROP COLUMN grant_id, DROP COLUMN usage_id, DROP COLUMN subject_id,
          ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled','budget.created','budget.disabled'));
        ALTER TABLE llm_usage DROP CONSTRAINT llm_usage_resolution, DROP COLUMN priced, DROP COLUMN input_micro_per_mtok, DROP COLUMN output_micro_per_mtok,
          DROP COLUMN reserved_cost_micro, DROP COLUMN resolved_by, DROP COLUMN resolved_at;
        DROP INDEX llm_budgets_active_scope_unit;
        ALTER TABLE llm_budgets DROP CONSTRAINT llm_budgets_one_limit, DROP COLUMN limit_cost_micro, ALTER COLUMN limit_tokens SET NOT NULL;
        CREATE UNIQUE INDEX llm_budgets_active_scope ON llm_budgets(tenant_id,coalesce(agent_id,''),coalesce(alias,''),period) WHERE status='active';
        ALTER TABLE llm_model_aliases DROP COLUMN access, DROP COLUMN priced`); err != nil {
		t.Fatal("revert", err)
	}
	if _, err = b.s.pool.Exec(t.Context(), llmAccessAndCostSQL); err != nil {
		t.Fatal("migrate", err)
	}
	if _, err = b.s.pool.Exec(t.Context(), "ALTER TABLE agent_specs ADD FOREIGN KEY (template_grant_id) REFERENCES llm_alias_grants(id)"); err != nil {
		t.Fatal("restore later schema dependency", err)
	}
	aliases, err := b.a.ListLLMAliases(t.Context(), b.owner, "", 10)
	if err != nil || len(aliases) != 2 {
		t.Fatal(err, aliases)
	}
	for _, a := range aliases {
		if a.Access != "organization" || a.Priced != (a.Alias == "fast") {
			t.Fatal("alias after migration", a)
		}
	}
	var openCost, doneCost int64
	if err = b.s.pool.QueryRow(t.Context(), `SELECT (SELECT reserved_cost_micro FROM llm_usage WHERE id=$1),(SELECT reserved_cost_micro FROM llm_usage WHERE id=$2)`,
		open.ID, done.ID).Scan(&openCost, &doneCost); err != nil {
		t.Fatal(err)
	}
	if openCost != 900 || doneCost != 0 { // 300 tokens at 3 micro-units, the higher price
		t.Fatal("reserved cost after migration", openCost, doneCost)
	}
	// 300 unknown + 10 settled: 690 tokens are left under the old budget.
	if _, err = b.reserveSplit(b.other, "fast", "after", 691, 0); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("token budget after migration", err)
	}
	if _, err = b.reserveSplit(b.other, "local", "free", 690, 0); err != nil {
		t.Fatal("an unpriced alias without a cost budget", err)
	}
}

func TestConcurrentCostReservationsNeverOvershootAHardCostBudget(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "c", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 1000, Mode: "hard"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			agent := b.agent
			if i%2 == 1 {
				agent = b.other
			}
			_, err := b.reserveSplit(agent, "fast", fmt.Sprintf("c%d", i), 40, 20) // 100
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrBudgetExceeded):
				refused++
			default:
				t.Error("unexpected", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 10 || refused != 20 {
		t.Fatal("organization cost budget not respected", ok, refused)
	}
}

// Reservations and settlements race: each call settles below its
// reservation, so the settled spend never passes the hard cap, and every
// reservation sees the others' settlements.
func TestSettlementsRacingReservationsKeepTheHardCostCap(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "c", CreateLLMBudgetInput{Period: "day", LimitCostMicro: 2000, Mode: "hard"})
	var wg sync.WaitGroup
	var calls sync.Map
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			agent := b.agent
			if w%2 == 1 {
				agent = b.other
			}
			for i := 0; ; i++ {
				if i == 50 {
					t.Error("the hard cost cap never refused") // 20 calls fit at most
					return
				}
				key := fmt.Sprintf("w%d-%d", w, i)
				r, err := b.reserveSplit(agent, "fast", key, 50, 50) // reserves 200
				if errors.Is(err, ErrBudgetExceeded) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				if err = b.a.SettleLLM(context.Background(), b.owner.TenantID, r.ID, 25, 25); err != nil { // costs 100
					t.Error(err)
					return
				}
				calls.Store(key, true)
			}
		}(w)
	}
	wg.Wait()
	var spent, open int64
	if err := b.s.pool.QueryRow(t.Context(), `SELECT coalesce(sum(estimated_cost_micro),0),count(*) FILTER (WHERE state<>'settled') FROM llm_usage`).Scan(&spent, &open); err != nil {
		t.Fatal(err)
	}
	n := 0
	calls.Range(func(any, any) bool { n++; return true })
	// Every worker stopped on a refusal: at most 200 micro-units were free then.
	if spent > 2000 || spent < 2000-200 || open != 0 || int64(n)*100 != spent {
		t.Fatal("cap", spent, open, n)
	}
}

// Two outcomes for one call: the first wins, the other is refused, never
// applied on top.
func TestOneOutcomePerCallUnderRacingSettlements(t *testing.T) {
	b := newBudgetLab(t)
	for round := 0; round < 10; round++ {
		r, err := b.reserveSplit(b.agent, "fast", fmt.Sprintf("r%d", round), 10, 10)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Add(3)
		go func() { defer wg.Done(); errs[0] = b.a.SettleLLM(context.Background(), b.owner.TenantID, r.ID, 1, 1) }()
		go func() { defer wg.Done(); errs[1] = b.a.SettleLLM(context.Background(), b.owner.TenantID, r.ID, 2, 2) }()
		go func() { defer wg.Done(); errs[2] = b.a.ReleaseLLM(context.Background(), b.owner.TenantID, r.ID) }()
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrConflict), errors.Is(err, ErrTransition):
			default:
				t.Fatal(err)
			}
		}
		var state string
		var in, cost *int64
		if err = b.s.pool.QueryRow(t.Context(), `SELECT state,input_tokens,estimated_cost_micro FROM llm_usage WHERE id=$1`, r.ID).Scan(&state, &in, &cost); err != nil {
			t.Fatal(err)
		}
		consistent := (state == "released" && in == nil && errs[2] == nil) ||
			(state == "settled" && *in == 1 && *cost == 4 && errs[0] == nil) || (state == "settled" && *in == 2 && *cost == 8 && errs[1] == nil)
		if won != 1 || !consistent {
			t.Fatal("outcomes", errs, state)
		}
	}
}
