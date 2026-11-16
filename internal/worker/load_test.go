//go:build linux && loadtest

package worker

// The load test (OPS-03): invocations sent over HTTP to the real API at a
// fixed rate, dispatched by the real worker passes, against PostgreSQL. The
// VMs are the mock runtime of the PostgreSQL tests (internal/runtime): one
// SQLite store per agent, written by each delivery, after a set service time.
// scripts/load-test.py starts PostgreSQL, runs this test and states the
// limits observed. It runs only with -tags loadtest.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type loadConfig struct {
	Rates     []float64     `json:"rates_per_second"`
	Step      time.Duration `json:"-"`
	StepText  string        `json:"step"`
	Agents    int           `json:"agents"`
	Workers   int           `json:"workers"`
	Batch     int           `json:"dispatch_batch"`
	Service   time.Duration `json:"-"`
	ServiceMS float64       `json:"service_ms"`
	FailEvery int           `json:"fail_every"`
	Drain     time.Duration `json:"-"`
}

func loadSetting(t *testing.T, name, fallback string) string {
	if v := os.Getenv("AGENTCAPSULE_LOAD_" + name); v != "" {
		return v
	}
	return fallback
}

func loadConfiguration(t *testing.T) loadConfig {
	t.Helper()
	c := loadConfig{}
	var err error
	for _, r := range strings.Split(loadSetting(t, "RATES", "5,10,20,40"), ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(r), 64)
		if err != nil || v <= 0 || v > 2000 {
			t.Fatal("AGENTCAPSULE_LOAD_RATES", r)
		}
		c.Rates = append(c.Rates, v)
	}
	durations := []struct {
		name, fallback string
		out            *time.Duration
	}{{"STEP", "20s", &c.Step}, {"SERVICE", "20ms", &c.Service}, {"DRAIN", "60s", &c.Drain}}
	for _, d := range durations {
		if *d.out, err = time.ParseDuration(loadSetting(t, d.name, d.fallback)); err != nil || *d.out < 0 {
			t.Fatal("AGENTCAPSULE_LOAD_"+d.name, err)
		}
	}
	ints := []struct {
		name, fallback string
		out            *int
		low, high      int
	}{{"AGENTS", "8", &c.Agents, 1, 200}, {"WORKERS", "2", &c.Workers, 1, 16}, {"BATCH", "16", &c.Batch, 1, 256}, {"FAIL_EVERY", "0", &c.FailEvery, 0, 1 << 20}}
	for _, i := range ints {
		if *i.out, err = strconv.Atoi(loadSetting(t, i.name, i.fallback)); err != nil || *i.out < i.low || *i.out > i.high {
			t.Fatal("AGENTCAPSULE_LOAD_"+i.name, err)
		}
	}
	c.StepText, c.ServiceMS = c.Step.String(), float64(c.Service)/float64(time.Millisecond)
	return c
}

// loadRuntime is the mock runtime of the PostgreSQL tests, with a service
// time and, when failEvery is set, one failed delivery in failEvery.
type loadRuntime struct {
	*vmruntime.MockRuntime
	service   time.Duration
	failEvery int64
	calls     atomic.Int64
}

func (r *loadRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	if n := r.calls.Add(1); r.failEvery > 0 && n%r.failEvery == 0 {
		return harnessstore.Receipt{}, errors.New("injected delivery failure")
	}
	return r.Send(ctx, target, e)
}

type loadLab struct {
	store   *controlplane.Store
	db      *pgxpool.Pool
	server  *httptest.Server
	tokens  []string // one owner per agent
	agents  []string
	runtime *loadRuntime
	workers []*Placements
}

func newLoadLab(t *testing.T, c loadConfig) *loadLab {
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		t.Fatal("-tags loadtest needs AGENTCAPSULE_TEST_POSTGRES (scripts/load-test.py)")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("worker_load_%d", time.Now().UnixNano())
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	l := &loadLab{store: s, db: db}
	t.Cleanup(func() {
		if l.server != nil {
			l.server.Close()
		}
		if l.runtime != nil {
			l.runtime.Close()
		}
		s.Close()
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x4c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x4d}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := api.NewForHostWithTransit(s, accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	l.server = httptest.NewServer(server)
	if err = s.ConfigureHostStorage(ctx, "local", int64(c.Agents)*128+64); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	root, err := s.BootstrapService(ctx, "load-admin", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.Agents {
		token := l.owner(t, root, i)
		l.tokens = append(l.tokens, token)
		l.agents = append(l.agents, l.agent(t, token, uint64(1000+i)))
	}
	mock, err := vmruntime.NewMock(ctx, t.TempDir(), l.agents...)
	if err != nil {
		t.Fatal(err)
	}
	mock.SetHandler(func(ctx context.Context, _ string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		select {
		case <-time.After(c.Service):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects(event TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO effects VALUES(?)", e.ID)
		return []byte(`{"text":"done"}`), err
	})
	l.runtime = &loadRuntime{MockRuntime: mock, service: c.Service, failEvery: int64(c.FailEvery)}
	for i := range c.Workers {
		w := &Placements{store: s, hostID: "local", workerID: fmt.Sprintf("load-%d", i), lease: time.Minute, deliveries: l.runtime}
		if err = w.EnableTransit(ctx, transit); err != nil {
			t.Fatal(err)
		}
		l.workers = append(l.workers, w)
	}
	return l
}

func (l *loadLab) post(t *testing.T, path, token, key, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, l.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (l *loadLab) owner(t *testing.T, admin string, i int) string {
	t.Helper()
	code, body := l.post(t, "/v1/users", admin, fmt.Sprintf("owner-%d", i), fmt.Sprintf(`{"display_name":"Load owner %d"}`, i))
	var u controlplane.User
	if code != 201 || json.Unmarshal(body, &u) != nil {
		t.Fatal("user", code, string(body))
	}
	code, body = l.post(t, "/v1/users/"+u.ID+"/tokens", admin, fmt.Sprintf("token-%d", i),
		fmt.Sprintf(`{"expires_at":%q}`, time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339Nano)))
	var token controlplane.TokenResponse
	if code != 201 || json.Unmarshal(body, &token) != nil {
		t.Fatal("token", code, string(body))
	}
	return token.Token
}

// agent creates an agent and stands for its provisioning and boot, as the
// API's messaging tests do: the volume, the first boot and a running VM are
// recorded, not performed.
func (l *loadLab) agent(t *testing.T, token string, inode uint64) string {
	t.Helper()
	ctx, s := t.Context(), l.store
	code, body := l.post(t, "/v1/agents", token, "create", `{"name":"Load","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`)
	var created controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &created) != nil {
		t.Fatal("agent", code, string(body))
	}
	jobs, err := s.PendingProvisioning(ctx, "local", 10)
	if err != nil {
		t.Fatal(err)
	}
	var e controlplane.Enrollment
	for _, j := range jobs {
		if j.AgentID == created.AgentID {
			e = j
		}
	}
	if err = s.RecordProvisionedVolume(ctx, controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: inode}); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimFencePlacement(ctx, e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", inode)
	if err = s.ConfirmFencePlacement(ctx, e.AgentID, e.HostID, "fixture", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentInitialized(ctx, controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: vm}); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(ctx, e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(ctx, e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if p, err = s.ClaimPlacement(ctx, e.AgentID, e.HostID, "fixture", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(ctx, e.AgentID, e.HostID, "fixture", p.Generation, fmt.Sprintf("%016x", inode+1<<20)); err != nil {
		t.Fatal(err)
	}
	// The provisioning job the worker would run is done here.
	if _, err = l.db.Exec(ctx, "DELETE FROM worker_jobs WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	return e.AgentID
}

type stepReport struct {
	Rate           float64            `json:"offered_per_second"`
	Sent           int                `json:"sent"`
	Accepted       int                `json:"accepted"`
	AcceptedPerSec float64            `json:"accepted_per_second"`
	Refusals       map[string]int     `json:"refusals"`
	AdmissionMS    map[string]float64 `json:"admission_latency_ms"`
	// The queue: the oldest invocation not yet delivered (the worker's
	// agentcapsule_worker_invocation_oldest_waiting_seconds), and the delay
	// of the oldest due worker job (agentcapsule_worker_job_oldest_due_seconds).
	MaxQueueAgeS    float64            `json:"max_queue_age_seconds"`
	MaxJobDelayS    float64            `json:"max_job_delay_seconds"`
	EndQueueAgeS    float64            `json:"end_queue_age_seconds"`
	EndBacklog      int64              `json:"end_backlog"`
	Completed       int64              `json:"completed"`
	Failed          int64              `json:"failed"`
	CompletionMS    map[string]float64 `json:"completion_latency_ms"`
	Sustained       bool               `json:"sustained"`
	NotSustainedWhy string             `json:"not_sustained_because,omitempty"`
}

type loadReport struct {
	Config      loadConfig     `json:"config"`
	PostgreSQL  string         `json:"postgresql"`
	Steps       []stepReport   `json:"steps"`
	DeadLetters int64          `json:"dead_letters"`
	Deliveries  map[string]int `json:"instruction_deliveries_by_state"`
	Drained     bool           `json:"drained"`
	Limit       string         `json:"limit"`
}

func percentiles(values []float64) map[string]float64 {
	out := map[string]float64{}
	if len(values) == 0 {
		return out
	}
	slices.Sort(values)
	at := func(q float64) float64 { return values[min(len(values)-1, int(q*float64(len(values))))] }
	out["p50"], out["p95"], out["p99"], out["max"] = at(0.50), at(0.95), at(0.99), values[len(values)-1]
	return out
}

// queueAge is what the worker serves as metrics: the oldest waiting
// invocation's age and the number waiting, and the oldest due job's delay.
func (l *loadLab) queueAge(ctx context.Context) (age float64, waiting int64, jobDelay float64) {
	n, oldest, err := l.store.InvocationBacklog(ctx, "local")
	if err != nil {
		return -1, -1, -1
	}
	stats, err := l.store.WorkQueue(ctx, "local")
	if err != nil {
		return -1, -1, -1
	}
	for _, s := range stats {
		if s.Kind == "delivery" {
			jobDelay = s.OldestDue.Seconds()
		}
	}
	return oldest.Seconds(), int64(n), jobDelay
}

// TestLoad sends invocations at each rate in turn and reports admission
// latency, queue age, completions, dead letters and refusals per step, and
// the limit observed: the highest rate sustained without refusal, server
// error or a queue that kept growing.
func TestLoad(t *testing.T) {
	c := loadConfiguration(t)
	l := newLoadLab(t, c)
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	var running sync.WaitGroup
	for _, w := range l.workers {
		running.Go(func() {
			o := DispatchOptions{Batch: c.Batch, WorkLease: time.Minute, DeliveryLease: 30 * time.Second, RetryBase: 100 * time.Millisecond, RetryMax: 2 * time.Second}
			for ctx.Err() == nil {
				if err := w.DispatchPass(ctx, o, 30*time.Second); err != nil && ctx.Err() == nil {
					t.Log("dispatch pass:", err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(20 * time.Millisecond):
				}
			}
		})
	}
	report := loadReport{Config: c, Deliveries: map[string]int{}}
	if err := l.db.QueryRow(ctx, "SHOW server_version").Scan(&report.PostgreSQL); err != nil {
		t.Fatal(err)
	}
	type sent struct {
		step      int
		operation string
	}
	var mu sync.Mutex
	var operations []sent
	sequence := 0
	for step, rate := range c.Rates {
		r := stepReport{Rate: rate, Refusals: map[string]int{}}
		var latencies []float64
		var inflight sync.WaitGroup
		sampling, endSampling := context.WithCancel(ctx)
		maxAge, maxDelay := 0.0, 0.0
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			for sampling.Err() == nil {
				age, _, delay := l.queueAge(sampling)
				maxAge, maxDelay = max(maxAge, age), max(maxDelay, delay)
				select {
				case <-sampling.Done():
				case <-time.After(250 * time.Millisecond):
				}
			}
		}()
		interval := time.Duration(float64(time.Second) / rate)
		start := time.Now()
		for next := start; time.Since(start) < c.Step; next = next.Add(interval) {
			time.Sleep(time.Until(next))
			i := sequence % len(l.agents)
			sequence++
			key := fmt.Sprintf("load-%d", sequence)
			r.Sent++
			inflight.Go(func() {
				began := time.Now()
				code, body := l.post(t, "/v1/agents/"+l.agents[i]+"/messages", l.tokens[i], key, `{"content":[{"type":"text","text":"load"}]}`)
				elapsed := float64(time.Since(began)) / float64(time.Millisecond)
				mu.Lock()
				defer mu.Unlock()
				latencies = append(latencies, elapsed)
				var accepted struct {
					OperationID string `json:"operation_id"`
				}
				if code == 202 && json.Unmarshal(body, &accepted) == nil && accepted.OperationID != "" {
					r.Accepted++
					operations = append(operations, sent{step, accepted.OperationID})
					return
				}
				var problem struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(body, &problem)
				r.Refusals[fmt.Sprintf("%d %s", code, problem.Code)]++
			})
		}
		inflight.Wait()
		elapsed := time.Since(start).Seconds()
		endSampling()
		<-sampled
		r.AcceptedPerSec = float64(r.Accepted) / elapsed
		r.AdmissionMS = percentiles(latencies)
		r.MaxQueueAgeS, r.MaxJobDelayS = maxAge, maxDelay
		r.EndQueueAgeS, r.EndBacklog, _ = l.queueAge(ctx)
		report.Steps = append(report.Steps, r)
	}
	// Drain: let the workers finish what was accepted.
	deadline := time.Now().Add(c.Drain)
	for time.Now().Before(deadline) {
		if _, backlog, _ := l.queueAge(ctx); backlog == 0 {
			report.Drained = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	stop()
	running.Wait()
	byStep := map[string]int{}
	ids := []string{}
	for _, o := range operations {
		byStep[o.operation] = o.step
		ids = append(ids, o.operation)
	}
	completions := make([][]float64, len(c.Rates))
	rows, err := l.db.Query(t.Context(), `SELECT id,status,extract(epoch FROM coalesce(completed_at,clock_timestamp())-created_at)*1000
        FROM platform_operations WHERE id=ANY($1)`, ids)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		var ms float64
		if err = rows.Scan(&id, &status, &ms); err != nil {
			t.Fatal(err)
		}
		s := &report.Steps[byStep[id]]
		switch status {
		case "SUCCEEDED":
			s.Completed++
			completions[byStep[id]] = append(completions[byStep[id]], ms)
		case "FAILED", "CANCELED":
			s.Failed++
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows, err = l.db.Query(t.Context(), "SELECT delivery_state,count(*) FROM agent_mailboxes WHERE kind='instruction' GROUP BY delivery_state")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var state string
		var n int
		if err = rows.Scan(&state, &n); err != nil {
			t.Fatal(err)
		}
		report.Deliveries[state] = n
		if state == "DEAD" {
			report.DeadLetters = int64(n)
		}
	}
	rows.Close()
	for i := range report.Steps {
		s := &report.Steps[i]
		s.CompletionMS = percentiles(completions[i])
		var why []string
		for code, n := range s.Refusals {
			why = append(why, fmt.Sprintf("%d refused (%s)", n, code))
		}
		slices.Sort(why)
		// A queue whose oldest invocation ends the step older than five
		// seconds, or with more than two seconds of arrivals waiting, kept
		// growing.
		if s.EndQueueAgeS > 5 || float64(s.EndBacklog) > 2*s.Rate {
			why = append(why, fmt.Sprintf("the queue kept growing (oldest invocation %.1f s, %d waiting at the end of the step)", s.EndQueueAgeS, s.EndBacklog))
		}
		s.Sustained, s.NotSustainedWhy = len(why) == 0, strings.Join(why, "; ")
	}
	report.Limit = "no rate sustained"
	for _, s := range report.Steps {
		if !s.Sustained {
			report.Limit += fmt.Sprintf("; first rate not sustained: %g/s: %s", s.Rate, s.NotSustainedWhy)
			break
		}
		report.Limit = fmt.Sprintf("sustained %g/s (admission p99 %.0f ms, oldest waiting invocation %.1f s)", s.Rate, s.AdmissionMS["p99"], s.MaxQueueAgeS)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("AGENTCAPSULE_LOAD_REPORT"); path != "" {
		if err = os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(out))
	if !report.Drained {
		t.Error("the accepted work did not drain within", c.Drain)
	}
	if c.FailEvery == 0 && report.DeadLetters != 0 {
		t.Error("dead letters without injected failures:", report.DeadLetters)
	}
}
