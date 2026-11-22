package controlplane

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// The retention of finished model calls: past it, a settled or released
// call goes, with the budget windows that started before it; a call in
// flight or of unknown outcome, one an audit event names, and one a corpus
// build in progress counts, stay. What the current windows count, the
// usage report and each agent's last activity do not change.
func TestModelCallRetentionKeepsWhatIsStillNeeded(t *testing.T) {
	b := newBudgetLab(t)
	tenant := b.owner.TenantID
	b.budget(t, "day", CreateLLMBudgetInput{Period: "day", LimitTokens: 1e9, Mode: "hard"})
	b.budget(t, "month", CreateLLMBudgetInput{Period: "month", LimitCostMicro: 1e12, Mode: "soft"})
	call := func(agent, key string, then func(id string) error) string {
		t.Helper()
		r, err := b.reserve(agent, key, 100)
		if err == nil && then != nil {
			err = then(r.ID)
		}
		if err != nil {
			t.Fatal(key, err)
		}
		return r.ID
	}
	settle := func(id string) error { return b.a.SettleLLM(t.Context(), tenant, id, 40, 0) }
	release := func(id string) error { return b.a.ReleaseLLM(t.Context(), tenant, id) }
	unknown := func(id string) error { return b.a.MarkLLMUnknown(t.Context(), tenant, id) }
	old := map[string]string{
		"settled":  call(b.agent, "old-settled", settle),
		"released": call(b.agent, "old-released", release),
		"reserved": call(b.agent, "old-reserved", nil),
		"unknown":  call(b.agent, "old-unknown", unknown),
		"audited":  call(b.agent, "old-audited", unknown),
		"building": call(b.other, "old-building", settle),
	}
	if _, err := b.a.SettleLLMOutcome(t.Context(), b.owner, old["audited"], "resolve", SettleLLMOutcomeInput{InputTokens: 10}); err != nil {
		t.Fatal(err)
	}
	recent := call(b.agent, "recent", settle)
	// The old calls were made 40 days ago, the corpus build that b.other
	// runs started 41 days ago and is still scanning.
	if _, err := b.s.pool.Exec(t.Context(), `UPDATE llm_usage SET created_at=clock_timestamp()-interval '40 days' WHERE id=ANY($1)`,
		[]string{old["settled"], old["released"], old["reserved"], old["unknown"], old["audited"], old["building"]}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.s.pool.Exec(t.Context(), `INSERT INTO corpora(id,tenant_id,name,source_kind,source_url,source_ref,source_path)
        VALUES('crp_retention',$1,'retention','github','https://example.invalid/r','main','/')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := b.s.pool.Exec(t.Context(), `INSERT INTO corpus_builds(id,tenant_id,corpus_id,state,requested_ref,builder_agent_id,started_at)
        VALUES('cbd_'||repeat('b',32),$1,'crp_retention','SCANNING','main',$2,clock_timestamp()-interval '41 days')`, tenant, b.other); err != nil {
		t.Fatal(err)
	}
	recountBudgets(t, b.s, tenant)
	usage := func() LLMUsageReport {
		t.Helper()
		r, err := b.a.LLMUsage(t.Context(), b.owner, "month")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	budgets := func() []LLMBudget {
		t.Helper()
		items, err := b.a.ListLLMBudgets(t.Context(), b.owner, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	activity := func() []time.Time {
		t.Helper()
		var at []time.Time
		rows, err := b.s.pool.Query(t.Context(), `SELECT at FROM agent_activity WHERE agent_id=ANY($1) ORDER BY agent_id`, []string{b.agent, b.other})
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var v time.Time
			if err = rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			at = append(at, v)
		}
		return at
	}
	var windowsBefore int
	if err := b.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_budget_windows WHERE window_start<clock_timestamp()-interval '35 days'`).Scan(&windowsBefore); err != nil || windowsBefore == 0 {
		t.Fatal("no old window to purge", windowsBefore, err)
	}
	reportBefore, budgetsBefore, activityBefore := usage(), budgets(), activity()
	if _, err := b.s.PurgeModelCalls(t.Context(), nil, MinModelCallRetention-time.Hour, 100); !errors.Is(err, ErrInput) {
		t.Fatal("a retention shorter than a month", err)
	}
	n, err := b.s.PurgeModelCalls(t.Context(), nil, MinModelCallRetention, 100)
	if err != nil || n.Calls != 2 || int(n.Windows) != windowsBefore {
		t.Fatal(n, windowsBefore, err)
	}
	var kept []string
	rows, err := b.s.pool.Query(t.Context(), `SELECT id FROM llm_usage WHERE tenant_id=$1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, id)
	}
	rows.Close()
	for name, id := range old {
		if gone := !slices.Contains(kept, id); gone != (name == "settled" || name == "released") {
			t.Errorf("the old %s call: deleted %v", name, gone)
		}
	}
	if !slices.Contains(kept, recent) {
		t.Error("a recent call was deleted")
	}
	after := usage()
	if after.Totals != reportBefore.Totals {
		t.Error("the month's usage changed", reportBefore.Totals, after.Totals)
	}
	for i, it := range budgets() {
		if *it.Used != *budgetsBefore[i].Used {
			t.Error("a current window changed", it.ID, *budgetsBefore[i].Used, *it.Used)
		}
	}
	if !slices.Equal(activity(), activityBefore) {
		t.Error("the agents' last activity changed")
	}
	// The audit's own retention removed the event: the call goes.
	if _, err = b.s.pool.Exec(t.Context(), `ALTER TABLE llm_audit DISABLE TRIGGER USER; DELETE FROM llm_audit WHERE usage_id IS NOT NULL; ALTER TABLE llm_audit ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if n, err = b.s.PurgeModelCalls(t.Context(), nil, MinModelCallRetention, 100); err != nil || n.Calls != 1 {
		t.Fatal("the call the audit named", n, err)
	}
}
