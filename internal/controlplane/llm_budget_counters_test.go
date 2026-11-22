package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// windowSums is what each budget of tenant counts, by the definition the
// reservations summed before P-05: usedTokensSQL or usedCostSQL over the
// calls of its scope, per UTC day or month a call was created in.
const windowSums = `SELECT b.id, w.start, sum(CASE WHEN b.limit_cost_micro IS NULL
      THEN CASE u.state WHEN 'settled' THEN u.input_tokens+u.output_tokens WHEN 'released' THEN 0 ELSE u.reserved_tokens END
      ELSE CASE u.state WHEN 'settled' THEN coalesce(u.estimated_cost_micro,0) WHEN 'released' THEN 0 ELSE u.reserved_cost_micro END END)
    FROM llm_budgets b JOIN llm_usage u ON u.tenant_id=b.tenant_id AND (b.agent_id IS NULL OR u.agent_id=b.agent_id) AND (b.alias IS NULL OR u.alias=b.alias)
    CROSS JOIN LATERAL (SELECT date_trunc(b.period, u.created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS start) w
   WHERE b.tenant_id=$1 GROUP BY b.id, w.start`

type window struct {
	budget string
	start  time.Time
}

func readWindows(t *testing.T, s *Store, query, tenant string) map[window]int64 {
	t.Helper()
	rows, err := s.pool.Query(t.Context(), query, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[window]int64{}
	for rows.Next() {
		var w window
		var n int64
		if err = rows.Scan(&w.budget, &w.start, &n); err != nil {
			t.Fatal(err)
		}
		out[window{w.budget, w.start.UTC()}] = n
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// recountBudgets rewrites tenant's windows from its calls: what the
// counters would hold had the calls been made at the times a test moved
// them to, as the clock cannot be moved.
func recountBudgets(t *testing.T, s *Store, tenant string) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM llm_budget_windows WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO llm_budget_windows(tenant_id,budget_id,window_start,used)
        SELECT $1,id,start,sum FROM (`+windowSums+`) x(id,start,sum)`, tenant); err != nil {
		t.Fatal(err)
	}
}

// checkWindows compares tenant's counters with the sums, for every window
// from the one its budget was created in.
func checkWindows(t *testing.T, s *Store, tenant string) int {
	t.Helper()
	counted := readWindows(t, s, `SELECT budget_id,window_start,used FROM llm_budget_windows WHERE tenant_id=$1`, tenant)
	summed := readWindows(t, s, windowSums, tenant)
	since := readWindows(t, s, `SELECT id,date_trunc(period, created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',0 FROM llm_budgets WHERE tenant_id=$1`, tenant)
	first := map[string]time.Time{}
	for w := range since {
		first[w.budget] = w.start
	}
	compared := 0
	for _, m := range []map[window]int64{counted, summed} {
		for w := range m {
			if w.start.Before(first[w.budget]) {
				continue
			}
			compared++
			if counted[w] != summed[w] {
				t.Errorf("budget %s, window %s: counted %d, the calls sum %d", w.budget, w.start, counted[w], summed[w])
			}
		}
	}
	return compared
}

// P-05: each budget's window counts exactly what its calls sum, under
// concurrent reservations, settlements, releases, unknown outcomes, an
// organization's resolutions, and budgets created and disabled meanwhile.
// Hard budgets still refuse what would go past them.
func TestBudgetWindowsCountWhatTheCallsSum(t *testing.T) {
	b := newBudgetLab(t)
	tenant := b.owner.TenantID
	b.budget(t, "org-day", CreateLLMBudgetInput{Period: "day", LimitTokens: 60000, Mode: "hard"})
	b.budget(t, "agent-month", CreateLLMBudgetInput{AgentID: b.agent, Period: "month", LimitTokens: 20000, Mode: "soft"})
	b.budget(t, "alias-cost", CreateLLMBudgetInput{Alias: "fast", Period: "day", LimitCostMicro: 90000, Mode: "hard"})
	b.budget(t, "pair-month", CreateLLMBudgetInput{AgentID: b.other, Alias: "fast", Period: "month", LimitTokens: 15000, Mode: "hard"})
	ctx := context.Background()
	var wg sync.WaitGroup
	var refused, calls sync.Map
	errs := make(chan error, 64)
	for g := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(g), 7))
			agent := b.agent
			if g%2 == 1 {
				agent = b.other
			}
			for i := range 25 {
				key := fmt.Sprintf("g%d-%d", g, i)
				res, err := b.a.ReserveLLM(ctx, tenant, agent, "fast", key, int64(1+r.IntN(400)), int64(r.IntN(300)))
				if errors.Is(err, ErrBudgetExceeded) {
					refused.Store(key, true)
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				calls.Store(key, true)
				switch r.IntN(5) {
				case 0, 1:
					err = b.a.SettleLLM(ctx, tenant, res.ID, int64(r.IntN(500)), int64(r.IntN(400)))
				case 2:
					err = b.a.ReleaseLLM(ctx, tenant, res.ID)
				case 3:
					if err = b.a.MarkLLMUnknown(ctx, tenant, res.ID); err == nil && r.IntN(2) == 0 {
						err = b.a.SettleLLM(ctx, tenant, res.ID, int64(r.IntN(200)), int64(r.IntN(200)))
					} else if err == nil {
						_, err = b.a.SettleLLMOutcome(ctx, b.owner, res.ID, "resolve-"+key, SettleLLMOutcomeInput{InputTokens: int64(r.IntN(100))})
					}
				}
				if err != nil {
					errs <- fmt.Errorf("%s: %w", key, err)
					return
				}
			}
		}()
	}
	// Budgets created and disabled while the calls run: a new budget counts
	// its window's calls, those in flight included.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, in := range []CreateLLMBudgetInput{
			{Period: "month", LimitTokens: 1e12, Mode: "soft"},
			{AgentID: b.other, Period: "day", LimitCostMicro: 1e12, Mode: "soft"},
			{Alias: "fast", Period: "month", LimitTokens: 1e12, Mode: "soft"},
		} {
			time.Sleep(30 * time.Millisecond)
			if _, err := b.a.CreateLLMBudget(ctx, b.owner, fmt.Sprintf("late-%d", i), in); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	n := 0
	calls.Range(func(any, any) bool { n++; return true })
	if n < 100 {
		t.Fatal("too few calls to compare:", n)
	}
	if compared := checkWindows(t, b.s, tenant); compared < 7 {
		t.Fatal("too few windows compared:", compared)
	}
	// What each active budget shows is its window's count.
	items, err := b.a.ListLLMBudgets(t.Context(), b.owner, "", 50)
	if err != nil || len(items) != 7 {
		t.Fatal(items, err)
	}
	summed := readWindows(t, b.s, windowSums, tenant)
	for _, it := range items {
		var now time.Time
		if err = b.s.pool.QueryRow(t.Context(), `SELECT date_trunc($1, clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, it.Period).Scan(&now); err != nil {
			t.Fatal(err)
		}
		if it.Used == nil || *it.Used != summed[window{it.ID, now.UTC()}] {
			t.Errorf("budget %s shows %v, its calls sum %d", it.ID, it.Used, summed[window{it.ID, now.UTC()}])
		}
	}
}

// sqlRecorder keeps the statements its connections send.
type sqlRecorder struct {
	mu  sync.Mutex
	sql []string
}

func (r *sqlRecorder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	r.sql = append(r.sql, data.SQL)
	r.mu.Unlock()
	return ctx
}

func (r *sqlRecorder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// P-05: a reservation reads its budgets' windows, never the calls of the
// window: of llm_usage it reads its request key's row and writes its own,
// however many calls the window holds. So do a settlement and a release.
func TestReservationReadsTheWindowsNotTheCalls(t *testing.T) {
	b := newBudgetLab(t)
	b.budget(t, "day", CreateLLMBudgetInput{Period: "day", LimitTokens: 1e9, Mode: "hard"})
	b.budget(t, "month", CreateLLMBudgetInput{AgentID: b.agent, Period: "month", LimitCostMicro: 1e12, Mode: "hard"})
	cfg, err := poolConfig(b.s.pool.Config().ConnString(), Connections{})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &sqlRecorder{}
	cfg.ConnConfig.Tracer = recorder
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a, err := NewAccounts(newStore(pool), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.ReserveLLM(t.Context(), b.owner.TenantID, b.agent, "fast", "traced", 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.SettleLLM(t.Context(), b.owner.TenantID, r.ID, 80, 40); err != nil {
		t.Fatal(err)
	}
	if r, err = a.ReserveLLM(t.Context(), b.owner.TenantID, b.agent, "fast", "released", 100, 50); err == nil {
		err = a.ReleaseLLM(t.Context(), b.owner.TenantID, r.ID)
	}
	if err != nil {
		t.Fatal(err)
	}
	read := regexp.MustCompile(`(?is)\bFROM\s+llm_usage\b`)
	keyed := regexp.MustCompile(`(?is)\bFROM\s+llm_usage\s+WHERE\s+tenant_id=\$1\s+AND\s+(?:agent_id=\$2\s+AND\s+request_key=\$3|id=\$2)\b`)
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.sql) < 10 {
		t.Fatal("too few statements traced:", len(recorder.sql))
	}
	for _, sql := range recorder.sql {
		if read.MatchString(sql) && !keyed.MatchString(sql) {
			t.Errorf("a statement reads the window's calls: %s", sql)
		}
	}
	checkWindows(t, b.s, b.owner.TenantID)
}
