package controlplane

import (
	"errors"
	"testing"
	"time"
)

// LLM-005: a budget on one model (an alias) binds only the calls to that
// alias, alone or for one agent; the refusal and the usage name the alias's
// scope, and the usage is reported per agent and per alias.
func TestAliasBudgetsBindOnlyTheirModel(t *testing.T) {
	b := newBudgetLab(t)
	alias, err := b.a.ListLLMAliases(t.Context(), b.owner, "", 10)
	if err != nil || len(alias) != 1 {
		t.Fatal(alias, err)
	}
	if _, err = b.a.CreateLLMAlias(t.Context(), b.owner, "al2", CreateLLMAliasInput{Alias: "slow", ProviderID: alias[0].ProviderID, UpstreamModel: "m2"}); err != nil {
		t.Fatal(err)
	}
	reserve := func(agent, model, key string, n int64) (LLMReservation, error) {
		return b.a.ReserveLLM(t.Context(), b.owner.TenantID, agent, model, key, n, 0)
	}
	refused := func(err error, scope string) {
		t.Helper()
		var r *LLMRefusal
		if !errors.Is(err, ErrBudgetExceeded) || !errors.As(err, &r) || r.Reason != "budget_tokens" || r.Scope != scope || r.Period != "day" {
			t.Fatal("want a refusal of the", scope, "budget, got", err)
		}
	}
	b.budget(t, "fast", CreateLLMBudgetInput{Alias: "fast", Period: "day", LimitTokens: 100, Mode: "hard"})
	b.budget(t, "slow-a1", CreateLLMBudgetInput{AgentID: b.agent, Alias: "slow", Period: "day", LimitTokens: 50, Mode: "hard"})
	b.budget(t, "slow-soft", CreateLLMBudgetInput{Alias: "slow", Period: "day", LimitTokens: 60, Mode: "soft"})

	// The alias budget counts both agents' calls to "fast", and only them.
	if _, err = reserve(b.agent, "fast", "f1", 60); err != nil {
		t.Fatal(err)
	}
	if _, err = reserve(b.other, "fast", "f2", 40); err != nil {
		t.Fatal(err)
	}
	_, err = reserve(b.other, "fast", "f3", 1)
	refused(err, "alias")
	// The agent's budget on "slow" binds that agent on that alias only.
	if _, err = reserve(b.agent, "slow", "s1", 50); err != nil {
		t.Fatal("the alias budget of fast counted a call to slow", err)
	}
	_, err = reserve(b.agent, "slow", "s2", 1)
	refused(err, "agent_alias")
	// The other agent is bound only by the soft budget of "slow", which
	// flags the call that goes past it.
	r, err := reserve(b.other, "slow", "s3", 5)
	if err != nil || r.SoftExceeded {
		t.Fatal("soft budget flagged under its limit", err, r.SoftExceeded)
	}
	r, err = reserve(b.other, "slow", "s4", 10)
	if err != nil || !r.SoftExceeded || len(r.SoftBudgets) != 1 || r.SoftBudgets[0] != (LLMBudgetHit{Unit: "tokens", Period: "day", Scope: "alias"}) {
		t.Fatal("soft alias budget not flagged", err, r)
	}
	// Each budget shows what its own window counts.
	items, err := b.a.ListLLMBudgets(t.Context(), b.owner, "", 10)
	if err != nil || len(items) != 3 {
		t.Fatal(items, err)
	}
	used := map[string]int64{}
	for _, it := range items {
		key := *it.Alias
		if it.AgentID != nil {
			key += "/" + *it.AgentID
		}
		used[key+"/"+it.Mode] = *it.Used
	}
	if used["fast/hard"] != 100 || used["slow/"+b.agent+"/hard"] != 50 || used["slow/soft"] != 65 {
		t.Fatal("budget consumption", used)
	}
	// The usage is reported per agent and per alias.
	rep, err := b.a.LLMUsage(t.Context(), b.owner, "day")
	if err != nil || len(rep.Lines) != 4 || rep.Totals.Calls != 5 || rep.Totals.PendingTokens != 165 {
		t.Fatal("usage lines", rep, err)
	}
	for _, l := range rep.Lines {
		want := map[string]int64{b.agent + "/fast": 60, b.other + "/fast": 40, b.agent + "/slow": 50, b.other + "/slow": 15}[l.AgentID+"/"+l.Alias]
		if want == 0 || l.PendingTokens != want {
			t.Fatal("usage line", l)
		}
	}
}

// LLM-005: a budget counts the calls of its current UTC day or month. Once
// its period rolls over, the calls of the previous one no longer count: the
// hard cap that refused calls admits them again, and the usage of the period
// starts from zero. The calls are moved back in time, as the clock cannot be.
func TestBudgetPeriodsRollOver(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "day", CreateLLMBudgetInput{Period: "day", LimitTokens: 100, Mode: "hard"})
	b.budget(t, "month", CreateLLMBudgetInput{Period: "month", LimitTokens: 250, Mode: "hard"})
	use := func(key string, n int64) error {
		r, err := b.reserve(b.agent, key, n)
		if err == nil {
			err = b.a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, n, 0)
		}
		return err
	}
	refusedBy := func(err error, period string) {
		t.Helper()
		var r *LLMRefusal
		if !errors.As(err, &r) || r.Reason != "budget_tokens" || r.Period != period {
			t.Fatal("want a refusal by the", period, "budget, got", err)
		}
	}
	// The periods are the database clock's UTC day and month.
	var now time.Time
	if err := b.s.pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC()
	day, month := now.Truncate(24*time.Hour), time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	moveBack := func(key string, to time.Time) {
		t.Helper()
		tag, err := b.s.pool.Exec(t.Context(), `UPDATE llm_usage SET created_at=$2 WHERE request_key=$1`, key, to)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("move back", key, err)
		}
		// Its budgets' windows count it where it now is (P-05).
		recountBudgets(t, b.s, b.owner.TenantID)
	}
	usage := func(period string) LLMUsageTotals {
		t.Helper()
		rep, err := b.a.LLMUsage(t.Context(), b.owner, period)
		if err != nil {
			t.Fatal(err)
		}
		want := day
		if period == "month" {
			want = month
		}
		if !rep.Since.Equal(want) {
			t.Fatal("usage of", period, "since", rep.Since, "want", want)
		}
		return rep.Totals
	}

	if err := use("d1", 100); err != nil {
		t.Fatal(err)
	}
	refusedBy(use("d2", 1), "day")
	// The day rolls over: yesterday's call leaves the day's cap and usage.
	// It stays in the month's, unless today is the first of the month.
	moveBack("d1", day.Add(-time.Microsecond))
	if got := usage("day"); got.Calls != 0 || got.SettledInput != 0 {
		t.Fatal("yesterday's call counted today", got)
	}
	sameMonth := day.After(month)
	if got := usage("month"); sameMonth != (got.SettledInput == 100) {
		t.Fatal("the month's usage", got, sameMonth)
	}
	if err := use("d2", 100); err != nil {
		t.Fatal("the day's cap did not roll over", err)
	}
	if sameMonth {
		// 200 of the month's 250 are spent: the month refuses what the day allows.
		moveBack("d2", day.Add(-time.Microsecond))
		refusedBy(use("d3", 60), "month")
	}
	// The month rolls over: last month's calls leave both caps and usages.
	moveBack("d1", month.Add(-time.Microsecond))
	moveBack("d2", month.Add(-time.Microsecond))
	if got := usage("month"); got.Calls != 0 || got.SettledInput != 0 {
		t.Fatal("last month's calls counted this month", got)
	}
	if err := use("d3", 100); err != nil {
		t.Fatal("the caps did not roll over", err)
	}
	if got := usage("month"); got.Calls != 1 || got.SettledInput != 100 {
		t.Fatal("this month's usage", got)
	}
	if got := usage("day"); got.Calls != 1 || got.SettledInput != 100 {
		t.Fatal("this day's usage", got)
	}
	// A period the code does not know is refused, for budgets and usage.
	if _, err := b.a.CreateLLMBudget(t.Context(), b.owner, "hour", CreateLLMBudgetInput{Period: "hour", LimitTokens: 1, Mode: "hard"}); !errors.Is(err, ErrInput) {
		t.Fatal("an hourly budget", err)
	}
	if _, err := b.a.LLMUsage(t.Context(), b.owner, "hour"); !errors.Is(err, ErrInput) {
		t.Fatal("an hourly usage", err)
	}
}
