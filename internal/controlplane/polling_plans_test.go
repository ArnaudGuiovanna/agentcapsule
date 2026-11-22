package controlplane

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/workqueue"
)

// historyTables keep a row for every operation, request, model call, payload
// or delivery ever made, until the retention removes it: a polling query that
// scans one costs what the history weighs. agent_placements has a row per
// agent of every host.
var historyTables = regexp.MustCompile(`Seq Scan on (platform_operations|owner_instructions|agent_requests|agent_mailboxes|request_closures|llm_usage|transit_payloads|idempotency_keys|inbox_items|mandates|agent_placements)\b`)

// The worker's polling queries read open rows through indexes that hold only
// those, and its retention finds finished rows oldest first, never by
// scanning a table's history (P-04). With sequential scans
// disabled, a plan still scans a table only when no index can serve it.
// Before the open-state indexes and agent_activity, DiscoverWork, the idle
// policy, the eviction order and the transit purge scanned platform_operations,
// agent_requests, request_closures, llm_usage and transit_payloads; the
// seeded measurements are in quint/results/audit/audit-perf-3a.
func TestPollingQueriesUseIndexesOfOpenRows(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	now := time.Now()
	queries := []struct {
		name string
		sql  string
		args []any
	}{
		{"DiscoverWork", workqueue.DiscoverySQL, []any{"local", 64}},
		{"idle policy", idleCandidates, []any{now, "local", "", 16}},
		{"eviction order", evictionOrderQuery, []any{[]string{il.agent}, true}},
		{"resume", `SELECT EXISTS(SELECT 1 FROM agents a WHERE a.id=$1 AND ` + workqueue.ResumeDuePredicate + `)`, []any{il.agent}},
		{"slot", `SELECT EXISTS(SELECT 1 FROM agents a WHERE a.id=$1 AND ` + slotDue + `)`, []any{il.agent}},
		{"transit retention", transitRetentionStart, []any{64, int64(time.Hour / time.Microsecond)}},
		{"transit purge", transitPurgeDue, []any{64}},
		{"finished requests", finishedRequests, []any{now, "local", 64, int64(DefaultFinishedRetention / time.Microsecond)}},
		{"finished lifecycle", finishedLifecycle, []any{now, "local", 64, int64(DefaultFinishedRetention / time.Microsecond)}},
		{"finished invocations", finishedInvocations, []any{now, "local", 64, int64(DefaultFinishedRetention / time.Microsecond)}},
		{"finished model calls", finishedModelCalls, []any{now, int64(DefaultModelCallRetention / time.Microsecond), 64}},
	}
	tx, err := il.s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SET LOCAL enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	for _, q := range queries {
		rows, err := tx.Query(ctx, "EXPLAIN "+q.sql, q.args...)
		if err != nil {
			t.Fatal(q.name, err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err = rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			t.Fatal(q.name, err)
		}
		if scans := historyTables.FindAllString(plan.String(), -1); len(scans) > 0 {
			t.Errorf("%s scans history: %v\n%s", q.name, scans, plan.String())
		}
	}
}
